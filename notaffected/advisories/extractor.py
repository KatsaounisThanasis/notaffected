"""Extracts deterministic CheckSpecs from built-in database, OSV payloads, and
optional schema-validated LLM extraction.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from notaffected.advisories.builtin_specs import BUILTIN_SPECS
from notaffected.advisories.fetcher import (
    fetch_mitre_cve_as_osv,
    fetch_osv_advisory,
    fetch_reference_snippets,
    fetch_ubuntu_osv_advisory,
)
from notaffected.local_model import generate_json
from notaffected.model import (
    PROBE_TYPES,
    CheckSpec,
    PatchInfo,
    Precondition,
    VexJustification,
)

KNOWN_KERNEL_MODULES = (
    "ksmbd",
    "nf_tables",
    "bluetooth",
    "rds",
    "tipc",
    "sctp",
    "overlay",
    "usb_storage",
    "mptcp_diag",
)

KERNEL_ALIAS_TO_MODULE: dict[str, str] = {
    "nftables": "nf_tables",
}

KERNEL_PATH_TO_MODULE: dict[str, str] = {
    "fs/smb/server/": "ksmbd",
    "net/netfilter/": "nf_tables",
    "net/bluetooth/": "bluetooth",
    "drivers/bluetooth/": "bluetooth",
    "fs/overlayfs/": "overlay",
    "net/rds/": "rds",
    "net/tipc/": "tipc",
    "net/sctp/": "sctp",
    "net/can/": "can",
    "drivers/usb/storage/": "usb_storage",
}

PROBE_PARAM_SCHEMA: dict[str, tuple[str, ...]] = {
    "kernel_version_vulnerable": ("fixed_version",),
    "package_installed_vulnerable": ("package",),
    "kernel_module_loaded": ("module",),
    "sysctl_equals": ("key", "value"),
    "network_listener": ("proto",),
    "firewall_allows_port": ("proto",),
    "systemd_service_active": ("service",),
    "process_running": ("process",),
    "config_contains": ("path", "pattern"),
    "windows_build_vulnerable": ("kb",),
    "windows_registry_equals": ("path", "name", "value"),
    "windows_service_active": ("service",),
}

PROBE_OPTIONAL_PARAMS: dict[str, tuple[str, ...]] = {
    "kernel_version_vulnerable": ("min_version", "track_fixes", "mainline_from"),
    "package_installed_vulnerable": ("fixed_version", "release_fixes"),
    "kernel_module_loaded": (),
    "sysctl_equals": (),
    "network_listener": ("port", "process", "scope"),
    "firewall_allows_port": ("port",),
    "systemd_service_active": (),
    "process_running": (),
    "config_contains": ("negate",),
    "windows_build_vulnerable": ("fixed_build",),
    "windows_registry_equals": ("negate",),
    "windows_service_active": (),
}

# Justification used for every LLM-proposed precondition; the LLM never chooses it.
PROBE_DEFAULT_JUSTIFICATION: dict[str, VexJustification] = {
    "kernel_version_vulnerable": VexJustification.VULNERABLE_CODE_NOT_PRESENT,
    "package_installed_vulnerable": VexJustification.VULNERABLE_CODE_NOT_PRESENT,
    "kernel_module_loaded": VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
    "sysctl_equals": VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
    "network_listener": VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
    "firewall_allows_port": VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
    "systemd_service_active": VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
    "process_running": VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
    "config_contains": VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
    "windows_build_vulnerable": VexJustification.VULNERABLE_CODE_NOT_PRESENT,
    "windows_registry_equals": VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
    "windows_service_active": VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
}

WINDOWS_ALLOWED_PROBES: frozenset[str] = frozenset(
    {
        "windows_build_vulnerable",
        "windows_registry_equals",
        "windows_service_active",
        "process_running",
    }
)
LINUX_ALLOWED_PROBES: frozenset[str] = PROBE_TYPES - {
    "windows_build_vulnerable",
    "windows_registry_equals",
    "windows_service_active",
}


def validate_precondition_params(pre: Precondition) -> bool:
    """Verify that `pre.params` contains all required keys with non-empty values."""
    if pre.probe not in PROBE_TYPES:
        return False
    if pre.probe == "windows_build_vulnerable":
        kb = str(pre.params.get("kb") or "").strip()
        fb = str(pre.params.get("fixed_build") or "").strip()
        return bool(kb or fb)
    required_keys = PROBE_PARAM_SCHEMA.get(pre.probe, ())
    for req_key in required_keys:
        val = pre.params.get(req_key)
        if val is None or str(val).strip() == "":
            return False
    return True


def resolve_check_spec(
    cve_id: str,
    use_llm: bool = False,
    cache_dir: Path | None = None,
    package_hint: str | None = None,
    fixed_version_hint: str | None = None,
    offline: bool = False,
    package_class: str | None = None,
) -> CheckSpec:
    """Resolve a CheckSpec for `cve_id`: built-in golden spec first, then OSV + Ubuntu OSV + heuristics/LLM.

    `package_class="lang"` (a scanner finding in a pip/npm/jar/... package) yields a spec with no
    host probes: dpkg/rpm/apk cannot see language packages, so "not installed" would be a false proof.
    """
    norm_id = cve_id.strip().upper()
    if package_class == "lang":
        return CheckSpec(
            cve_id=norm_id,
            summary=(
                f"Language-ecosystem package{f' {package_hint!r}' if package_hint else ''}; "
                "host package probes do not apply"
            ),
            preconditions=[],
            confidence="low",
            source="fallback",
            os_source="heuristic",
        )
    if norm_id in BUILTIN_SPECS:
        return BUILTIN_SPECS[norm_id]

    osv_data = None if offline else fetch_osv_advisory(norm_id, cache_dir=cache_dir)
    ubuntu_osv = None if offline else fetch_ubuntu_osv_advisory(norm_id, cache_dir=cache_dir)
    if osv_data and ubuntu_osv:
        merged = dict(osv_data)
        merged["affected"] = list(osv_data.get("affected") or []) + list(
            ubuntu_osv.get("affected") or []
        )
        for field_key in ("summary", "details", "references", "database_specific"):
            if not merged.get(field_key) and ubuntu_osv.get(field_key):
                merged[field_key] = ubuntu_osv[field_key]
        osv_data = merged
    elif ubuntu_osv and not osv_data:
        osv_data = ubuntu_osv

    if not osv_data and not offline:
        osv_data = fetch_mitre_cve_as_osv(norm_id, cache_dir=cache_dir)
    elif osv_data and not offline:
        summ_low = f"{osv_data.get('summary') or ''} {osv_data.get('details') or ''}".lower()
        if "windows " in summ_low or "netlogon" in summ_low or "active directory" in summ_low:
            mitre_extra = fetch_mitre_cve_as_osv(norm_id, cache_dir=cache_dir)
            if isinstance(mitre_extra, dict):
                db_s = dict(osv_data.get("database_specific") or {})
                m_aff = (mitre_extra.get("database_specific") or {}).get("mitre_affected")
                if m_aff:
                    db_s["mitre_affected"] = m_aff
                    osv_data = dict(osv_data)
                    osv_data["database_specific"] = db_s
                if not osv_data.get("summary") and mitre_extra.get("summary"):
                    osv_data["summary"] = mitre_extra["summary"]

    if osv_data:
        return extract_from_osv_payload(
            norm_id,
            osv_data,
            use_llm=use_llm,
            package_hint=package_hint,
            fixed_version_hint=fixed_version_hint,
        )

    # Fallback when offline and not in built-ins
    preconditions: list[Precondition] = []
    if package_hint:
        preconditions.append(
            Precondition(
                probe="package_installed_vulnerable",
                params={
                    "package": package_hint,
                    "fixed_version": fixed_version_hint or "",
                },
                description=(
                    f"Package '{package_hint}' installed"
                    + (f" (< {fixed_version_hint})" if fixed_version_hint else "")
                ),
                justification_if_not_met=(
                    VexJustification.VULNERABLE_CODE_NOT_PRESENT
                    if fixed_version_hint
                    else VexJustification.COMPONENT_NOT_PRESENT
                ),
                origin="scanner",
            )
        )
    return CheckSpec(
        cve_id=norm_id,
        summary=f"Advisory details unavailable offline for {norm_id}",
        severity="UNKNOWN",
        preconditions=preconditions,
        mitigation=[],
        patch=PatchInfo(
            status="released" if fixed_version_hint else "unknown",
            fixed_version=fixed_version_hint,
        ),
        confidence="low",
        source="fallback",
        os_source="heuristic",
    )


def extract_from_osv_payload(
    cve_id: str,
    osv_data: dict[str, Any],
    use_llm: bool = False,
    package_hint: str | None = None,
    fixed_version_hint: str | None = None,
) -> CheckSpec:
    """Turn an OSV JSON payload into a CheckSpec using deterministic rules + optional LLM."""
    summary = str(osv_data.get("summary") or osv_data.get("details") or f"Advisory {cve_id}").strip()
    if len(summary) > 160:
        summary = summary[:157] + "..."
    details = str(osv_data.get("details") or "")
    full_text = f"{summary}\n{details}"

    pkg_name, fixed_ver, ecosystem = _extract_package_and_fix(
        osv_data, package_hint, fixed_version_hint
    )
    distro_eco = _is_distro_ecosystem(ecosystem)
    if ecosystem and not distro_eco:
        # A language-ecosystem advisory (PyPI, npm, Go, Maven, ...): dpkg/rpm/apk cannot see those
        # packages and the ecosystem's fix version is not a distro version.
        if not package_hint:
            return CheckSpec(
                cve_id=cve_id,
                summary=f"{summary} [{ecosystem} package; host package probes do not apply]",
                severity=_extract_severity(osv_data),
                preconditions=[],
                patch=PatchInfo(
                    status="released" if fixed_ver else "unknown", fixed_version=fixed_ver, pocket=ecosystem
                ),
                confidence="low",
                source="fallback",
                os_source="heuristic",
            )
        if not fixed_version_hint:
            fixed_ver = None

    preconditions: list[Precondition] = []
    mitigation: list[str] = []

    text_lower = full_text.lower()
    db_spec = osv_data.get("database_specific") or {}
    mitre_aff = (
        db_spec.get("mitre_affected")
        if isinstance(db_spec, dict) and isinstance(db_spec.get("mitre_affected"), list)
        else []
    )
    has_msrc_ref = any(
        "msrc.microsoft.com" in str(r.get("url") or "").lower()
        for r in (osv_data.get("references") or [])
        if isinstance(r, dict)
    )
    mitre_products = [str(a.get("product") or "").lower() for a in mitre_aff if isinstance(a, dict)]
    has_mitre_windows = bool(mitre_products) and all("windows" in prod for prod in mitre_products)
    has_windows_phrase = text_lower.startswith("windows ") or any(
        phrase in text_lower
        for phrase in (
            "windows server",
            "microsoft windows",
            "windows shell",
            "windows tcp/ip",
            "windows remote desktop",
            "windows hyper-v",
            "windows kerberos",
            "windows ntlm",
            "windows common log",
            "windows kernel",
            "windows wi-fi",
            "windows imaging",
            "windows mshtml",
            "windows dns",
            "windows dhcp",
            "microsoft message queuing",
            "active directory",
            "windows 10",
            "windows 11",
            "hklm\\",
            "hklm:\\",
            "print spooler",
        )
    )
    is_windows = (
        (has_mitre_windows and (not pkg_name or text_lower.startswith("windows ")))
        or (not pkg_name and has_windows_phrase)
        or (not pkg_name and has_msrc_ref and "windows" in text_lower)
    )
    os_family = "windows" if is_windows else "linux"
    has_kb_ref = bool(re.search(r"\bKB\d{6,8}\b", full_text, re.IGNORECASE))
    kernel_by_pkg = pkg_name in ("linux", "linux-image", "kernel")
    if is_windows:
        # Structured only with MSRC + KB evidence or an all-Windows MITRE product list.
        os_source = "structured" if (has_mitre_windows or (has_msrc_ref and has_kb_ref)) else "heuristic"
    else:
        os_source = "structured" if (distro_eco or kernel_by_pkg) else "heuristic"
    # Provenance of the version/package precondition built below.
    if package_hint:
        pkg_origin = "scanner"
    elif distro_eco and pkg_name:
        pkg_origin = "osv"
    else:
        pkg_origin = "heuristic"

    if is_windows:
        kb_match = re.search(r"\b(KB\d{6,8})\b", full_text, re.IGNORECASE)
        kb_id = kb_match.group(1).upper() if kb_match else ""
        fixed_build = ""
        branch_builds: list[str] = []
        for a in mitre_aff:
            if not isinstance(a, dict):
                continue
            prod = str(a.get("product") or "").lower()
            for v in a.get("versions") or []:
                if not isinstance(v, dict):
                    continue
                lt = str(v.get("lessThan") or v.get("lessThanOrEqual") or "").strip()
                m_build = re.match(r"^(?:10\.0\.|6\.\d\.)?(\d{4,5}\.\d+)$", lt)
                if m_build:
                    cand_build = m_build.group(1)
                    if cand_build not in branch_builds:
                        branch_builds.append(cand_build)
                    if "2022" in prod and cand_build.startswith("20348."):
                        fixed_build = cand_build
                    elif not fixed_build and cand_build.startswith("20348."):
                        fixed_build = cand_build
        if not fixed_build and branch_builds:
            fixed_build = branch_builds[0]

        if kb_id or fixed_build:
            win_params: dict[str, Any] = {}
            # A KB regexed from prose can be unrelated: it is only used when MITRE gives no build.
            if kb_id and not fixed_build:
                win_params["kb"] = kb_id
            if fixed_build:
                win_params["fixed_build"] = (
                    ",".join(branch_builds) if len(branch_builds) > 1 else fixed_build
                )
            fixed_ver = fixed_ver or (
                f"{kb_id} ({fixed_build})" if kb_id and fixed_build else (kb_id or fixed_build)
            )
            ecosystem = ecosystem or "msrc-security-update"
            desc_parts = []
            if fixed_build:
                desc_parts.append(f"OS build < {fixed_build}")
            if "kb" in win_params:
                desc_parts.append(f"update {kb_id} is not installed")
            preconditions.append(
                Precondition(
                    probe="windows_build_vulnerable",
                    params=win_params,
                    description="Windows " + " and ".join(desc_parts),
                    justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_PRESENT,
                    origin="osv" if fixed_build else "heuristic",
                )
            )

        for phrase, svc_name, svc_label in _WIN_SERVICE_PHRASES:
            if phrase in text_lower:
                preconditions.append(
                    Precondition(
                        probe="windows_service_active",
                        params={"service": svc_name},
                        description=f"{svc_label} service ('{svc_name}') is Running",
                        justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
                        origin="heuristic",
                    )
                )
                mitigation.append(
                    f"Stop-Service -Name {svc_name} -Force; Set-Service -Name {svc_name} -StartupType Disabled"
                )
                break

    is_kernel = not is_windows and (kernel_by_pkg or (not pkg_name and "linux kernel" in text_lower))
    if is_kernel:
        kernel_params: dict[str, Any] = {"fixed_version": fixed_ver or ""}
        track_fixes = _extract_kernel_track_fixes(osv_data)
        if track_fixes:
            kernel_params["track_fixes"] = track_fixes
        preconditions.append(
            Precondition(
                probe="kernel_version_vulnerable",
                params=kernel_params,
                description=f"Running kernel is older than fixed version '{fixed_ver or 'unfixed'}'",
                justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_PRESENT,
                origin=pkg_origin,
            )
        )
    elif pkg_name and not is_windows:
        pkg_params: dict[str, Any] = {
            "package": pkg_name,
            "fixed_version": fixed_ver or "",
        }
        if not fixed_version_hint:
            rel_fixes = _extract_release_fixes(osv_data, pkg_name)
            if rel_fixes:
                pkg_params["release_fixes"] = rel_fixes
        preconditions.append(
            Precondition(
                probe="package_installed_vulnerable",
                params=pkg_params,
                description=(
                    f"Package '{pkg_name}' is installed"
                    + (f" and < {fixed_ver}" if fixed_ver else "")
                ),
                justification_if_not_met=(
                    VexJustification.VULNERABLE_CODE_NOT_PRESENT
                    if fixed_ver
                    else VexJustification.COMPONENT_NOT_PRESENT
                ),
                origin=pkg_origin,
            )
        )

    # Keyword heuristics (non-authoritative): kernel modules only for kernel advisories, listeners for any.
    if not is_windows:
        detected_module: str | None = None
        if is_kernel:
            for mod in KNOWN_KERNEL_MODULES:
                if re.search(rf"\b{re.escape(mod)}\b", text_lower):
                    detected_module = mod
                    break
        if is_kernel and not detected_module:
            for alias, canonical_mod in KERNEL_ALIAS_TO_MODULE.items():
                if re.search(rf"\b{re.escape(alias)}\b", text_lower):
                    detected_module = canonical_mod
                    break
        if is_kernel and not detected_module:
            for path_prefix, mapped_mod in KERNEL_PATH_TO_MODULE.items():
                if path_prefix in text_lower:
                    detected_module = mapped_mod
                    break
        if detected_module:
            preconditions.append(
                Precondition(
                    probe="kernel_module_loaded",
                    params={"module": detected_module},
                    description=f"Kernel module '{detected_module}' is loaded",
                    justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
                    origin="heuristic",
                )
            )
            mitigation.append(f"sudo modprobe -r {detected_module}")

        port_match = re.search(r"\b(tcp|udp)\s+port\s+(\d{1,5})\b", text_lower)
        if port_match:
            proto = port_match.group(1).lower()
            port_num = int(port_match.group(2))
            preconditions.append(
                Precondition(
                    probe="network_listener",
                    params={"proto": proto, "port": port_num, "scope": "non_loopback"},
                    description=f"{proto.upper()} port {port_num} is listening on a non-loopback address",
                    justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
                    origin="heuristic",
                )
            )
            mitigation.append(f"sudo ufw deny {port_num}/{proto}")

    source = "osv"
    if use_llm:
        enriched_text = full_text
        if len(details) < 300:
            ref_snippets = fetch_reference_snippets(osv_data)
            if ref_snippets:
                enriched_text = f"{full_text}\n\n{ref_snippets}"
        llm_pres, llm_mitigations = _extract_via_llm(
            cve_id,
            enriched_text,
            os_family=os_family,
            is_kernel=is_kernel,
        )
        existing_probes = {_precondition_dedup_key(p) for p in preconditions}
        for lp in llm_pres:
            key = _precondition_dedup_key(lp)
            if key not in existing_probes:
                preconditions.append(lp)
                existing_probes.add(key)
        for m in llm_mitigations:
            if m not in mitigation:
                mitigation.append(m)
        if llm_pres:
            source = "osv+llm"

    # High confidence requires at least one narrowing runtime precondition beyond bare version check,
    # and on Windows also requires a build/KB baseline precondition so a service check alone never
    # falsely marks a patched Windows Server as AFFECTED.
    has_runtime_precondition = any(
        p.probe
        in (
            "kernel_module_loaded",
            "sysctl_equals",
            "network_listener",
            "firewall_allows_port",
            "systemd_service_active",
            "process_running",
            "config_contains",
            "windows_registry_equals",
            "windows_service_active",
        )
        for p in preconditions
    )
    has_win_baseline = (
        os_family != "windows"
        or any(p.probe == "windows_build_vulnerable" for p in preconditions)
    )
    confidence = "high" if (has_runtime_precondition and has_win_baseline) else "low"

    advisory_url = None
    for ref in osv_data.get("references") or []:
        if isinstance(ref, dict) and ref.get("url"):
            advisory_url = str(ref["url"])
            break

    return CheckSpec(
        cve_id=cve_id,
        summary=summary,
        severity=_extract_severity(osv_data),
        preconditions=preconditions,
        mitigation=mitigation,
        patch=PatchInfo(
            status="released" if fixed_ver else "unfixed",
            fixed_version=fixed_ver,
            pocket=ecosystem,
            advisory_url=advisory_url,
        ),
        confidence=confidence,
        source=source,
        os_family=os_family,
        os_source=os_source,
    )


def _precondition_dedup_key(pre: Precondition) -> tuple[str, str]:
    params = dict(pre.params)
    if pre.probe == "kernel_module_loaded" and "module" in params:
        params["module"] = str(params["module"]).replace("-", "_")
    return (pre.probe, json.dumps(params, sort_keys=True))


def _score_osv_affected_entry(
    eco: str, name: str, text_lower: str = "", has_fixed: bool = False
) -> int:
    if not eco and not name:
        return -500
    eco_low = eco.lower()
    name_low = name.lower()
    score = 10
    if "ubuntu:24.04" in eco_low:
        score = 100
    elif "ubuntu:22.04" in eco_low:
        score = 90
    elif "ubuntu:20.04" in eco_low:
        score = 80
    elif "ubuntu" in eco_low:
        score = 65
    elif "debian" in eco_low:
        score = 55

    if has_fixed:
        score += 20
    if name_low and text_lower and name_low in text_lower:
        score += 25
    if "pro:" in eco_low or "fips" in eco_low or name_low.endswith("-fips"):
        score -= 45
    if name_low.startswith("linux-") and name_low not in ("linux-image", "linux-base"):
        score -= 35
    return score


_GIT_HASH_RE = re.compile(r"^[0-9a-f]{20,64}$", re.IGNORECASE)


def _extract_package_and_fix(
    osv_data: dict[str, Any],
    package_hint: str | None,
    fixed_version_hint: str | None,
) -> tuple[str | None, str | None, str | None]:
    pkg_name = package_hint
    fixed_ver = fixed_version_hint
    ecosystem = None
    best_score = -100
    text_lower = (
        f"{osv_data.get('summary') or ''} {osv_data.get('details') or ''}".lower()
    )

    for aff in osv_data.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package") or {}
        eco = str(pkg.get("ecosystem") or "")
        name = str(pkg.get("name") or "")
        cand_fixed = None
        for rng in aff.get("ranges") or []:
            if not isinstance(rng, dict) or str(rng.get("type") or "").upper() == "GIT":
                continue
            for ev in rng.get("events") or []:
                if isinstance(ev, dict) and ev.get("fixed"):
                    f_str = str(ev["fixed"]).strip()
                    if f_str and not _GIT_HASH_RE.fullmatch(f_str):
                        cand_fixed = f_str
                        break
            if cand_fixed:
                break

        score = _score_osv_affected_entry(eco, name, text_lower, bool(cand_fixed))
        if score > best_score:
            best_score = score
            if not package_hint:
                pkg_name = name or None
            ecosystem = eco or None
            if not fixed_version_hint:
                fixed_ver = cand_fixed
    return pkg_name, fixed_ver, ecosystem


_NON_KERNEL_LINUX_PACKAGES = ("linux-firmware", "linux-libc-dev", "linux-meta", "linux-signed", "linux-restricted")


def _extract_kernel_track_fixes(osv_data: dict[str, Any]) -> dict[str, str]:
    """Per-track kernel fixes from Ubuntu OSV data, keyed 'ubuntu:<release>:<line>:<flavour>'.

    Each Ubuntu kernel source package is one flavour/line: 'linux' = generic, 'linux-hwe-6.5' =
    generic on line 6.5, 'linux-azure' = azure, 'linux-lowlatency-hwe-6.5' = lowlatency on 6.5.
    The line comes from the '-X.Y' suffix, else from the fixed version. "" = listed, no fix.
    A key that gets two different fixed ABIs is dropped (it would be a guess).
    """
    tracks: dict[str, str] = {}
    conflicted: set[str] = set()
    for aff in osv_data.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package") or {}
        eco = str(pkg.get("ecosystem") or "").lower()
        name = str(pkg.get("name") or "").strip().lower()
        m_rel = re.fullmatch(r"ubuntu:(\d{2}\.\d{2})(?::lts)?", eco)
        if not m_rel or not (name == "linux" or name.startswith("linux-")):
            continue
        if name.startswith(_NON_KERNEL_LINUX_PACKAGES):
            continue
        fixed = ""
        for rng in aff.get("ranges") or []:
            if not isinstance(rng, dict) or str(rng.get("type") or "").upper() == "GIT":
                continue
            for ev in rng.get("events") or []:
                if isinstance(ev, dict) and ev.get("fixed"):
                    fixed = str(ev["fixed"]).strip()
                    break
            if fixed:
                break
        rest = name[len("linux"):].lstrip("-")
        m_line = re.search(r"(?:^|-)(\d+\.\d+)$", rest)
        if m_line:
            line = m_line.group(1)
            rest = rest[: m_line.start()]
        else:
            m_fixed_line = re.match(r"^(\d+\.\d+)\.", fixed)
            if not m_fixed_line:
                continue
            line = m_fixed_line.group(1)
        parts = [t for t in rest.split("-") if t and t != "hwe"]
        flavour = "-".join(parts) or "generic"
        key = f"ubuntu:{m_rel.group(1)}:{line}:{flavour}"
        if key in tracks and _kernel_abi(tracks[key]) != _kernel_abi(fixed):
            conflicted.add(key)
        tracks.setdefault(key, fixed)
    for key in conflicted:
        tracks.pop(key, None)
    return tracks


def _kernel_abi(version: str) -> str:
    m = re.match(r"^(\d+\.\d+\.\d+-\d+)", version.strip())
    return m.group(1) if m else version.strip()


# OSV ecosystems whose packages are OS packages that dpkg/rpm/apk (or the kernel probe) can see.
_DISTRO_ECOSYSTEMS = frozenset(
    {
        "ubuntu", "debian", "alpine", "rocky linux", "almalinux", "red hat", "suse", "opensuse",
        "mageia", "photon os", "wolfi", "chainguard", "azure linux", "mariner", "openeuler", "minimos",
        "echo", "linux",
    }
)


def _is_distro_ecosystem(ecosystem: str | None) -> bool:
    return bool(ecosystem) and str(ecosystem).split(":", 1)[0].strip().lower() in _DISTRO_ECOSYSTEMS


def _extract_release_fixes(osv_data: dict[str, Any], pkg_name: str) -> dict[str, str]:
    """Collect per-distro-release fixed versions (e.g. 'ubuntu:22.04' -> '3.0.2-0ubuntu1.16')
    so a multi-release Ubuntu/Debian/Alpine fleet compares against each host's own release track.
    """
    target = pkg_name.strip().lower()
    rel_fixes: dict[str, str] = {}
    for aff in osv_data.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package") or {}
        eco = str(pkg.get("ecosystem") or "")
        name = str(pkg.get("name") or "").strip().lower()
        eco_low = eco.lower()
        if name != target or "pro:" in eco_low or "fips" in eco_low:
            continue
        rel_key = ""
        m_ubu = re.search(r"ubuntu:(\d{2}\.\d{2})", eco_low)
        m_deb = re.search(r"debian:(\d+)", eco_low)
        m_alp = re.search(r"alpine:v?(\d+\.\d+)", eco_low)
        if m_ubu:
            rel_key = f"ubuntu:{m_ubu.group(1)}"
        elif m_deb:
            rel_key = f"debian:{m_deb.group(1)}"
        elif m_alp:
            rel_key = f"alpine:{m_alp.group(1)}"
        if not rel_key:
            continue
        # Every listed release is recorded; "" = listed as affected with no fix yet.
        rel_fixes.setdefault(rel_key, "")
        for rng in aff.get("ranges") or []:
            if not isinstance(rng, dict) or str(rng.get("type") or "").upper() == "GIT":
                continue
            for ev in rng.get("events") or []:
                if isinstance(ev, dict) and ev.get("fixed"):
                    f_str = str(ev["fixed"]).strip()
                    if f_str and not _GIT_HASH_RE.fullmatch(f_str):
                        if not rel_fixes[rel_key]:
                            rel_fixes[rel_key] = f_str
                        break
    return rel_fixes


def _extract_severity(osv_data: dict[str, Any]) -> str:
    db_spec = osv_data.get("database_specific") or {}
    if isinstance(db_spec, dict) and db_spec.get("severity"):
        return str(db_spec["severity"]).upper()
    return "HIGH"


_NON_DAEMON_PACKAGES: frozenset[str] = frozenset(
    {
        "curl",
        "openssl",
        "glibc",
        "libc6",
        "runc",
        "xz",
        "xz-utils",
        "util-linux",
        "sudo",
        "bash",
        "python",
        "python3",
        "git",
        "zlib",
        "libxml2",
        "busybox",
    }
)

# Advisory phrase -> Windows service name. Drives the deterministic service heuristic and
# grounds LLM-proposed windows_service_active checks (a service counts as named in the advisory
# when its name or one of its phrases appears).
_WIN_SERVICE_PHRASES: tuple[tuple[str, str, str], ...] = (
    ("spooler", "Spooler", "Print Spooler"),
    ("remote desktop licensing", "TermServLicensing", "Remote Desktop Licensing"),
    ("message queuing", "MSMQ", "Message Queuing (MSMQ)"),
    ("msmq", "MSMQ", "Message Queuing (MSMQ)"),
    ("dns server", "DNS", "Windows DNS Server"),
    ("dhcp server", "DHCPServer", "Windows DHCP Server"),
    ("windows search", "WSearch", "Windows Search"),
    ("wi-fi", "WlanSvc", "WLAN AutoConfig"),
    ("wlan", "WlanSvc", "WLAN AutoConfig"),
    ("http protocol stack", "W3SVC", "IIS World Wide Web Publishing"),
    ("windows kerberos", "Kdc", "Kerberos Key Distribution Center"),
)


def _mentions(term: str, text_lower: str) -> bool:
    """True when `term` appears in the advisory as a whole token (not inside a longer word)."""
    term = term.strip().lower()
    if not term:
        return False
    return bool(re.search(rf"(?<![a-z0-9_.-]){re.escape(term)}(?![a-z0-9_-])", text_lower))


def _mentions_port(port: object, text_lower: str) -> bool:
    port_s = str(port or "").strip()
    if not port_s.isdigit():
        return False
    return bool(
        re.search(rf"\bport\s+{port_s}\b|\b{port_s}/(?:tcp|udp)\b|:{port_s}\b", text_lower)
    )


def _is_grounded_llm_precondition(
    cand: Precondition,
    advisory_text_lower: str,
    is_kernel: bool,
) -> bool:
    """Accept an LLM precondition only when every name, port, key or path it uses is written in
    the advisory itself (rejects e.g. apache2.service for an nginx advisory, or kernel_module_loaded('curl')).
    """
    p = cand.probe
    params = cand.params
    if p == "kernel_module_loaded":
        mod = str(params.get("module") or "").strip().lower().replace("-", "_")
        return is_kernel and mod in KNOWN_KERNEL_MODULES

    if p == "process_running":
        proc = str(params.get("process") or "").strip().lower()
        base = proc[:-4] if proc.endswith(".exe") else proc
        if not base or base in _NON_DAEMON_PACKAGES:
            return False
        return _mentions(base, advisory_text_lower)

    if p == "systemd_service_active":
        svc = str(params.get("service") or "").strip().lower()
        base = svc[:-8] if svc.endswith(".service") else svc
        if not base or base in _NON_DAEMON_PACKAGES:
            return False
        return _mentions(base, advisory_text_lower)

    if p == "windows_service_active":
        svc = str(params.get("service") or "").strip()
        if not svc:
            return False
        return _mentions(svc, advisory_text_lower) or any(
            name.lower() == svc.lower() and phrase in advisory_text_lower for phrase, name, _ in _WIN_SERVICE_PHRASES
        )

    if p == "network_listener":
        port, proc = params.get("port"), str(params.get("process") or "")
        if not port and not proc:
            return False
        if port and not _mentions_port(port, advisory_text_lower):
            return False
        return not proc or _mentions(proc, advisory_text_lower)

    if p == "firewall_allows_port":
        return _mentions_port(params.get("port"), advisory_text_lower)

    if p == "config_contains":
        return _mentions(str(params.get("path") or ""), advisory_text_lower)

    if p == "sysctl_equals":
        return _mentions(str(params.get("key") or ""), advisory_text_lower)

    if p == "windows_registry_equals":
        return _mentions(str(params.get("name") or ""), advisory_text_lower)

    if p == "package_installed_vulnerable":
        return _mentions(str(params.get("package") or ""), advisory_text_lower)

    return False


_SAFE_LLM_MITIGATION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^sudo\s+systemctl\s+(?:disable\s+--now|stop)\s+[a-zA-Z0-9_.@-]+$"),
    re.compile(r"^sudo\s+modprobe\s+-r\s+[a-zA-Z0-9_-]+$"),
    re.compile(r"^sudo\s+ufw\s+deny\s+\d{1,5}/(?:tcp|udp)$"),
    re.compile(r"^sudo\s+sysctl\s+-w\s+[a-zA-Z0-9_.-]+=[a-zA-Z0-9_.-]+$"),
    re.compile(r"^Stop-Service\s+-Name\s+[a-zA-Z0-9_.-]+\s+-Force$", re.IGNORECASE),
    re.compile(
        r"^Stop-Service\s+-Name\s+[a-zA-Z0-9_.-]+\s+-Force;\s*Set-Service\s+-Name\s+[a-zA-Z0-9_.-]+\s+-StartupType\s+Disabled$",
        re.IGNORECASE,
    ),
)


def _is_safe_llm_mitigation(cmd: str, is_kernel: bool) -> bool:
    """Strictly allowlist safe single-command mitigations from LLM output (blocks rm -rf, redirects, etc.)."""
    cleaned = cmd.strip()
    if not cleaned or any(tok in cleaned for tok in ("\n", "\r", "`", "$(", ">", "<", "|", "&&")):
        return False
    if not any(pat.fullmatch(cleaned) for pat in _SAFE_LLM_MITIGATION_PATTERNS):
        return False
    low = cleaned.lower()
    if low.startswith("sudo modprobe -r "):
        mod = low.removeprefix("sudo modprobe -r ").strip().replace("-", "_")
        return is_kernel and mod in KNOWN_KERNEL_MODULES
    if any(f"{nd}.service" in low for nd in _NON_DAEMON_PACKAGES):
        return False
    return True


def _extract_via_llm(
    cve_id: str,
    advisory_text: str,
    os_family: str = "linux",
    is_kernel: bool = False,
) -> tuple[list[Precondition], list[str]]:
    """Ask the local/configured LLM to map advisory prose into closed PROBE_TYPES.
    Drops any unrecognized probe type, cross-OS probe, ungrounded name/port/path,
    missing required parameter, or unsafe mitigation command. The LLM never sets the OS
    family or the VEX justification, and its preconditions are tagged origin="llm".
    """
    allowed_set = WINDOWS_ALLOWED_PROBES if os_family == "windows" else LINUX_ALLOWED_PROBES
    if not is_kernel:
        allowed_set = allowed_set - {"kernel_module_loaded", "kernel_version_vulnerable"}
    schema_lines = "\n".join(
        f"  - {probe}: required={list(req_keys)}, optional={list(PROBE_OPTIONAL_PARAMS.get(probe, ()))}"
        for probe, req_keys in sorted(PROBE_PARAM_SCHEMA.items())
        if probe in allowed_set
    )
    os_label = "Windows Server" if os_family == "windows" else "Linux"
    if os_family == "windows":
        example_json = (
            '{"preconditions": [{"probe": "windows_service_active", '
            '"params": {"service": "<ServiceName>"}, "description": "Windows service is running"}], '
            '"mitigation": ["Stop-Service -Name <ServiceName> -Force"]}'
        )
    else:
        example_json = (
            '{"preconditions": [{"probe": "systemd_service_active", '
            '"params": {"service": "<unit>.service"}, "description": "Systemd service is active"}], '
            '"mitigation": ["sudo systemctl disable --now <unit>.service"]}'
        )
    prompt = (
        f"Extract at most 2 deterministic {os_label} runtime preconditions for {cve_id}.\n"
        "If the advisory is for a CLI tool or library (e.g. curl, openssl, glibc, runc, xz-utils) "
        "with no always-running daemon or kernel module, return {\"preconditions\": [], \"mitigation\": []}.\n"
        "For Microsoft Message Queuing (MSMQ), use ONLY windows_service_active with service='MSMQ'.\n"
        f"Allowed probes:\n{schema_lines}\n"
        "Use only names, ports and paths that appear in the advisory text.\n"
        f"Return compact JSON (short descriptions <10 words):\n{example_json}\n\n"
        f"Advisory:\n{advisory_text[:1000]}"
    )
    resp = generate_json(prompt, timeout=90)
    if not resp:
        return [], []

    adv_lower = advisory_text.lower()

    valid_preconditions: list[Precondition] = []
    for raw_p in resp.get("preconditions") or []:
        if not isinstance(raw_p, dict):
            continue
        probe_name = str(raw_p.get("probe") or "")
        if probe_name not in allowed_set:
            continue
        normalized_p = dict(raw_p)
        normalized_p["justification_if_not_met"] = PROBE_DEFAULT_JUSTIFICATION[probe_name].value
        normalized_p["origin"] = "llm"
        if not normalized_p.get("description"):
            normalized_p["description"] = f"Check {probe_name}"
        try:
            cand = Precondition.from_dict(normalized_p)
        except (ValueError, KeyError, TypeError):
            continue
        if not validate_precondition_params(cand):
            continue
        if not _is_grounded_llm_precondition(cand, adv_lower, is_kernel=is_kernel):
            continue
        valid_preconditions.append(cand)

    mitigations: list[str] = []
    for m in resp.get("mitigation") or []:
        if not isinstance(m, str) or not m.strip():
            continue
        if _is_safe_llm_mitigation(m, is_kernel=is_kernel):
            mitigations.append(m.strip())
    return valid_preconditions, mitigations
