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
    "net/mptcp/": "mptcp_diag",
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
    "kernel_version_vulnerable": ("min_version",),
    "package_installed_vulnerable": ("fixed_version",),
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
) -> CheckSpec:
    """Resolve a CheckSpec for `cve_id`: built-in golden spec first, then OSV + Ubuntu OSV + heuristics/LLM."""
    norm_id = cve_id.strip().upper()
    if norm_id in BUILTIN_SPECS:
        return BUILTIN_SPECS[norm_id]

    osv_data = fetch_osv_advisory(norm_id, cache_dir=cache_dir)
    ubuntu_osv = fetch_ubuntu_osv_advisory(norm_id, cache_dir=cache_dir)
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

    if not osv_data:
        osv_data = fetch_mitre_cve_as_osv(norm_id, cache_dir=cache_dir)

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
    has_mitre_windows = any(
        "windows" in str(a.get("product") or "").lower()
        for a in mitre_aff
        if isinstance(a, dict)
    )
    is_windows = not pkg_name and (
        has_mitre_windows
        or has_msrc_ref
        or text_lower.startswith("windows ")
        or any(
            phrase in text_lower
            for phrase in (
                "windows server",
                "microsoft windows",
                "windows shell",
                "windows tcp/ip",
                "windows remote desktop",
                "windows hyper-v",
                "microsoft message queuing",
                "active directory",
                "windows 10",
                "windows 11",
                "hklm\\",
                "hklm:\\",
                "print spooler",
            )
        )
    )
    os_family = "windows" if is_windows else "linux"

    if is_windows:
        kb_match = re.search(r"\b(KB\d{6,8})\b", full_text, re.IGNORECASE)
        kb_id = kb_match.group(1).upper() if kb_match else ""
        fixed_build = ""
        for a in mitre_aff:
            if not isinstance(a, dict):
                continue
            prod = str(a.get("product") or "").lower()
            for v in a.get("versions") or []:
                if not isinstance(v, dict):
                    continue
                lt = str(v.get("lessThan") or "").strip()
                m_build = re.match(r"^(?:10\.0\.)?(\d{5}\.\d+)$", lt)
                if m_build:
                    cand_build = m_build.group(1)
                    if "2022" in prod and cand_build.startswith("20348."):
                        fixed_build = cand_build
                        break
                    if not fixed_build:
                        fixed_build = cand_build
            if fixed_build.startswith("20348."):
                break

        if kb_id or fixed_build:
            win_params: dict[str, Any] = {}
            if kb_id:
                win_params["kb"] = kb_id
            if fixed_build:
                win_params["fixed_build"] = fixed_build
            fixed_ver = fixed_ver or (
                f"{kb_id} ({fixed_build})" if kb_id and fixed_build else (kb_id or fixed_build)
            )
            ecosystem = ecosystem or "msrc-security-update"
            desc_parts = []
            if fixed_build:
                desc_parts.append(f"OS build < {fixed_build}")
            if kb_id:
                desc_parts.append(f"update {kb_id} is not installed")
            preconditions.append(
                Precondition(
                    probe="windows_build_vulnerable",
                    params=win_params,
                    description="Windows " + " and ".join(desc_parts),
                    justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_PRESENT,
                )
            )

        win_service_map = (
            ("spooler", "Spooler", "Print Spooler"),
            ("remote desktop licensing", "TermServLicensing", "Remote Desktop Licensing"),
            ("message queuing", "MSMQ", "Message Queuing (MSMQ)"),
            ("msmq", "MSMQ", "Message Queuing (MSMQ)"),
            ("dns server", "DNS", "Windows DNS Server"),
            ("dhcp server", "DHCPServer", "Windows DHCP Server"),
            ("windows search", "WSearch", "Windows Search"),
        )
        for phrase, svc_name, svc_label in win_service_map:
            if phrase in text_lower:
                preconditions.append(
                    Precondition(
                        probe="windows_service_active",
                        params={"service": svc_name},
                        description=f"{svc_label} service ('{svc_name}') is Running",
                        justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
                    )
                )
                mitigation.append(
                    f"Stop-Service -Name {svc_name} -Force; Set-Service -Name {svc_name} -StartupType Disabled"
                )
                break

    is_kernel = (
        not is_windows
        and (pkg_name in ("linux", "linux-image", "kernel") or "linux kernel" in text_lower)
    )
    if is_kernel:
        preconditions.append(
            Precondition(
                probe="kernel_version_vulnerable",
                params={"fixed_version": fixed_ver or ""},
                description=f"Running kernel is older than fixed version '{fixed_ver or 'unfixed'}'",
                justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_PRESENT,
            )
        )
    elif pkg_name and not is_windows:
        preconditions.append(
            Precondition(
                probe="package_installed_vulnerable",
                params={"package": pkg_name, "fixed_version": fixed_ver or ""},
                description=(
                    f"Package '{pkg_name}' is installed"
                    + (f" and < {fixed_ver}" if fixed_ver else "")
                ),
                justification_if_not_met=(
                    VexJustification.VULNERABLE_CODE_NOT_PRESENT
                    if fixed_ver
                    else VexJustification.COMPONENT_NOT_PRESENT
                ),
            )
        )

    # Deterministic heuristic extraction for Linux kernel modules and listeners
    if not is_windows:
        detected_module: str | None = None
        for mod in KNOWN_KERNEL_MODULES:
            if re.search(rf"\b{re.escape(mod)}\b", text_lower):
                detected_module = mod
                break
        if not detected_module:
            for alias, canonical_mod in KERNEL_ALIAS_TO_MODULE.items():
                if re.search(rf"\b{re.escape(alias)}\b", text_lower):
                    detected_module = canonical_mod
                    break
        if not detected_module:
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
        llm_pres, llm_mitigations, llm_os = _extract_via_llm(
            cve_id, enriched_text, os_family=os_family
        )
        if llm_os in ("linux", "windows") and not is_kernel and not pkg_name:
            os_family = llm_os
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

    # High confidence requires at least one narrowing runtime precondition beyond bare version check
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
    confidence = "high" if has_runtime_precondition else "low"

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
    )


def _precondition_dedup_key(pre: Precondition) -> tuple[str, str]:
    params = dict(pre.params)
    if pre.probe == "kernel_module_loaded" and "module" in params:
        params["module"] = str(params["module"]).replace("-", "_")
    return (pre.probe, json.dumps(params, sort_keys=True))


def _score_osv_affected_entry(eco: str, name: str, text_lower: str = "") -> int:
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

    if name_low and text_lower and name_low in text_lower:
        score += 25
    if "pro:" in eco_low or "fips" in eco_low or name_low.endswith("-fips"):
        score -= 45
    if name_low.startswith("linux-") and name_low not in ("linux-image", "linux-base"):
        score -= 35
    return score


def _extract_package_and_fix(
    osv_data: dict[str, Any],
    package_hint: str | None,
    fixed_version_hint: str | None,
) -> tuple[str | None, str | None, str | None]:
    pkg_name = package_hint
    fixed_ver = fixed_version_hint
    ecosystem = None
    best_score = -999
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
            for ev in rng.get("events") or []:
                if isinstance(ev, dict) and ev.get("fixed"):
                    cand_fixed = str(ev["fixed"])
                    break
            if cand_fixed:
                break

        score = _score_osv_affected_entry(eco, name, text_lower)
        if cand_fixed:
            score += 5
        if score > best_score:
            best_score = score
            if not package_hint and name:
                pkg_name = name
            ecosystem = eco or ecosystem
            if not fixed_version_hint and cand_fixed:
                fixed_ver = cand_fixed
    return pkg_name, fixed_ver, ecosystem


def _extract_severity(osv_data: dict[str, Any]) -> str:
    db_spec = osv_data.get("database_specific") or {}
    if isinstance(db_spec, dict) and db_spec.get("severity"):
        return str(db_spec["severity"]).upper()
    return "HIGH"


def _extract_via_llm(
    cve_id: str,
    advisory_text: str,
    os_family: str = "linux",
) -> tuple[list[Precondition], list[str], str]:
    """Ask the local/configured LLM to map advisory prose into closed PROBE_TYPES.
    Drops any unrecognized probe type, cross-OS probe, missing required parameter, or malformed entry.
    """
    allowed_set = WINDOWS_ALLOWED_PROBES if os_family == "windows" else LINUX_ALLOWED_PROBES
    schema_lines = "\n".join(
        f"  - {probe}: required={list(req_keys)}, optional={list(PROBE_OPTIONAL_PARAMS.get(probe, ()))}"
        for probe, req_keys in sorted(PROBE_PARAM_SCHEMA.items())
        if probe in allowed_set
    )
    os_label = "Windows Server" if os_family == "windows" else "Linux"
    if os_family == "windows":
        example_json = (
            '{"os_family": "windows", "preconditions": [{"probe": "windows_service_active", '
            '"params": {"service": "<ServiceName>"}, "description": "Windows service is running", '
            '"justification_if_not_met": "component_not_present"}], '
            '"mitigation": ["Stop-Service -Name <ServiceName> -Force"]}'
        )
    else:
        example_json = (
            '{"os_family": "linux", "preconditions": [{"probe": "systemd_service_active", '
            '"params": {"service": "<unit>.service"}, "description": "Systemd service is active", '
            '"justification_if_not_met": "vulnerable_code_not_in_execute_path"}], '
            '"mitigation": ["sudo systemctl disable --now <unit>.service"]}'
        )
    prompt = (
        f"Extract at most 2 deterministic {os_label} runtime preconditions for {cve_id}.\n"
        "For Microsoft Message Queuing (MSMQ), use service='MSMQ'.\n"
        f"Allowed probes:\n{schema_lines}\n"
        "Allowed justification_if_not_met: component_not_present, vulnerable_code_not_present, "
        "vulnerable_code_not_in_execute_path, inline_mitigations_already_exist.\n"
        f"Return compact JSON (short descriptions <10 words):\n{example_json}\n\n"
        f"Advisory:\n{advisory_text[:1000]}"
    )
    resp = generate_json(prompt, timeout=90)
    if not resp:
        return [], [], os_family

    detected_os = str(resp.get("os_family") or os_family).strip().lower()
    if detected_os not in ("linux", "windows"):
        detected_os = os_family
    effective_allowed = WINDOWS_ALLOWED_PROBES if detected_os == "windows" else LINUX_ALLOWED_PROBES
    valid_justifications = {j.value for j in VexJustification}

    valid_preconditions: list[Precondition] = []
    for raw_p in resp.get("preconditions") or []:
        if not isinstance(raw_p, dict):
            continue
        probe_name = str(raw_p.get("probe") or "")
        if probe_name not in effective_allowed:
            continue
        normalized_p = dict(raw_p)
        just_val = str(normalized_p.get("justification_if_not_met") or "").strip()
        if just_val not in valid_justifications:
            normalized_p["justification_if_not_met"] = (
                VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH.value
            )
        if not normalized_p.get("description"):
            normalized_p["description"] = f"Check {probe_name}"
        try:
            cand = Precondition.from_dict(normalized_p)
        except (ValueError, KeyError, TypeError):
            continue
        if not validate_precondition_params(cand):
            continue
        valid_preconditions.append(cand)

    mitigations = [
        str(m) for m in (resp.get("mitigation") or []) if isinstance(m, str) and m.strip()
    ]
    return valid_preconditions, mitigations, detected_os
