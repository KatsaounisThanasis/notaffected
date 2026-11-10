"""AI-assisted and deterministic post-verdict remediation & operational risk advisor.

Takes the deterministic probe evidence from AFFECTED and UNDER_INVESTIGATION hosts
and synthesizes a prioritized, service-aware remediation plan.
"""

from __future__ import annotations

from notaffected.local_model import detect_provider, generate
from notaffected.model import CheckSpec, HostVerdict, VerdictStatus


def build_remediation_briefing(
    specs: list[CheckSpec],
    verdicts: list[HostVerdict],
) -> str:
    """Generate a host-aware remediation & operational impact briefing."""
    actionable = [
        v
        for v in verdicts
        if v.status in (VerdictStatus.AFFECTED, VerdictStatus.UNDER_INVESTIGATION)
    ]
    if not actionable:
        return "All evaluated hosts are deterministically NOT AFFECTED. No remediation actions required."

    spec_map = {s.cve_id: s for s in specs}
    findings_lines: list[str] = []
    for v in actionable:
        spec = spec_map.get(v.cve_id)
        patch_str = v.patch.status if v.patch else "unknown"
        short_reason = v.reason[:180]
        short_mit = "; ".join(v.mitigation[:2]) or "None"
        findings_lines.append(
            f"- {v.host} ({v.os_family}) | {v.cve_id} ({spec.severity if spec else 'HIGH'}) "
            f"| {v.status.value} | Patch: {patch_str}\n"
            f"  Proof: {short_reason}\n"
            f"  Mitigations: {short_mit}"
        )

    prompt = (
        "Output ONLY 3 single-line bullets (one per finding below, no intro text, no code blocks): "
        "[Host/CVE] Risk | Safest mitigation avoiding active service disruption | Patch readiness.\n\n"
        + "\n".join(findings_lines)
    )

    llm_reply = generate(prompt, timeout=90, json_format=False, max_tokens=240).strip()
    if llm_reply:
        provider = detect_provider()
        return f"[Provider: {provider}]\n{llm_reply}"

    # Deterministic host-aware operational triage when no LLM is reachable
    out_lines: list[str] = [
        "Structured Operational Triage (deterministic fallback — start local `ollama serve` or set NOTAFFECTED_LLM_PROVIDER):"
    ]
    for idx, v in enumerate(actionable, start=1):
        patch_status = v.patch.status if v.patch else "unknown"
        fixed_ver = (v.patch.fixed_version if v.patch else None) or "pending"
        caution_notes: list[str] = []
        search_text = f"{v.reason} {' '.join(v.mitigation)}".lower()
        if "nginx" in search_text or ":443" in search_text or ":80" in search_text:
            caution_notes.append(
                "Active web listener detected on host; prefer targeted sysctl/config mitigation over blanket incoming firewall deny."
            )
        if "sshd" in search_text or ":22" in search_text:
            caution_notes.append(
                "Active OpenSSH listener detected; reload sshd rather than blocking TCP/22 to avoid losing remote access."
            )
        if v.os_family == "windows" and "spooler" in search_text:
            caution_notes.append(
                "If this Windows Server is not a dedicated print server, disabling 'Spooler' is safe and takes effect immediately without reboot."
            )
        if v.os_family == "windows" and "disabledcomponents" in search_text:
            caution_notes.append(
                "Setting Tcpip6 DisabledComponents=0xff requires a reboot; verify Active Directory / dual-stack dependencies before disabling IPv6 on a Domain Controller."
            )

        out_lines.append(
            f"{idx}. {v.host} [{v.os_family.upper()}] — {v.cve_id} ({v.status.value.upper()})"
        )
        out_lines.append(f"   • Patch Readiness: {patch_status} (fix: {fixed_ver})")
        if caution_notes:
            for note in caution_notes:
                out_lines.append(f"   • Operational Safety Note: {note}")
        if v.mitigation:
            out_lines.append(f"   • Recommended First Action: {v.mitigation[0]}")

    return "\n".join(out_lines)
