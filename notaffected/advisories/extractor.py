"""Extracts deterministic CheckSpecs from built-in database, OSV payloads, and
optional schema-validated LLM extraction.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from notaffected.advisories.builtin_specs import BUILTIN_SPECS
from notaffected.advisories.fetcher import fetch_osv_advisory
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
    "nftables",
    "bluetooth",
    "rds",
    "tipc",
    "sctp",
    "can",
    "overlay",
    "usb_storage",
    "mptcp_diag",
)


def resolve_check_spec(
    cve_id: str,
    use_llm: bool = False,
    cache_dir: Path | None = None,
    package_hint: str | None = None,
    fixed_version_hint: str | None = None,
) -> CheckSpec:
    """Resolve a CheckSpec for `cve_id`: built-in golden spec first, then OSV + heuristics/LLM."""
    norm_id = cve_id.strip().upper()
    if norm_id in BUILTIN_SPECS:
        return BUILTIN_SPECS[norm_id]

    osv_data = fetch_osv_advisory(norm_id, cache_dir=cache_dir)
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

    is_kernel = pkg_name in ("linux", "linux-image", "kernel") or "linux kernel" in full_text.lower()
    if is_kernel:
        preconditions.append(
            Precondition(
                probe="kernel_version_vulnerable",
                params={"fixed_version": fixed_ver or ""},
                description=f"Running kernel is older than fixed version '{fixed_ver or 'unfixed'}'",
                justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_PRESENT,
            )
        )
    elif pkg_name:
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

    # Deterministic heuristic extraction for kernel modules and ports
    text_lower = full_text.lower()
    for mod in KNOWN_KERNEL_MODULES:
        if re.search(rf"\b{re.escape(mod)}\b", text_lower):
            preconditions.append(
                Precondition(
                    probe="kernel_module_loaded",
                    params={"module": mod},
                    description=f"Kernel module '{mod}' is loaded",
                    justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
                )
            )
            mitigation.append(f"sudo modprobe -r {mod}")
            break

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
        llm_pres, llm_mitigations = _extract_via_llm(cve_id, full_text)
        existing_probes = {(p.probe, json.dumps(p.params, sort_keys=True)) for p in preconditions}
        for lp in llm_pres:
            key = (lp.probe, json.dumps(lp.params, sort_keys=True))
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
    )


def _extract_package_and_fix(
    osv_data: dict[str, Any],
    package_hint: str | None,
    fixed_version_hint: str | None,
) -> tuple[str | None, str | None, str | None]:
    pkg_name = package_hint
    fixed_ver = fixed_version_hint
    ecosystem = None

    for aff in osv_data.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package") or {}
        eco = str(pkg.get("ecosystem") or "")
        name = str(pkg.get("name") or "")
        is_preferred_distro = "ubuntu" in eco.lower() or "debian" in eco.lower()
        if not pkg_name and name:
            pkg_name = name
            ecosystem = eco
        if is_preferred_distro:
            pkg_name = name or pkg_name
            ecosystem = eco
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if isinstance(ev, dict) and ev.get("fixed"):
                    if not fixed_ver or (is_preferred_distro and not fixed_version_hint):
                        fixed_ver = str(ev["fixed"])
    return pkg_name, fixed_ver, ecosystem


def _extract_severity(osv_data: dict[str, Any]) -> str:
    db_spec = osv_data.get("database_specific") or {}
    if isinstance(db_spec, dict) and db_spec.get("severity"):
        return str(db_spec["severity"]).upper()
    return "HIGH"


def _extract_via_llm(
    cve_id: str,
    advisory_text: str,
) -> tuple[list[Precondition], list[str]]:
    """Ask the local/configured LLM to map advisory prose into closed PROBE_TYPES.
    Drops any unrecognized probe type or malformed entry.
    """
    prompt = (
        f"Extract deterministic Linux runtime preconditions for {cve_id} from the advisory below.\n"
        f"Allowed probe types ONLY: {sorted(PROBE_TYPES)}.\n"
        "Return strict JSON: {\"preconditions\": [{\"probe\": \"...\", \"params\": {...}, "
        "\"description\": \"...\", \"justification_if_not_met\": \"...\"}], \"mitigation\": [\"...\"]}.\n\n"
        f"Advisory:\n{advisory_text[:3000]}"
    )
    resp = generate_json(prompt)
    if not resp:
        return [], []

    valid_preconditions: list[Precondition] = []
    for raw_p in resp.get("preconditions") or []:
        if not isinstance(raw_p, dict):
            continue
        probe_name = str(raw_p.get("probe") or "")
        if probe_name not in PROBE_TYPES:
            continue
        try:
            valid_preconditions.append(Precondition.from_dict(raw_p))
        except (ValueError, KeyError, TypeError):
            continue

    mitigations = [
        str(m) for m in (resp.get("mitigation") or []) if isinstance(m, str) and m.strip()
    ]
    return valid_preconditions, mitigations
