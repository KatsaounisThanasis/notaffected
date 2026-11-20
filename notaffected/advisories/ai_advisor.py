"""AI-assisted and deterministic post-verdict remediation & operational risk advisor.

Takes the deterministic probe evidence from AFFECTED and UNDER_INVESTIGATION hosts
and synthesizes a prioritized, service-aware remediation plan.
"""

from __future__ import annotations

from notaffected.local_model import detect_provider, generate, get_ai_status
from notaffected.model import CheckSpec, HostVerdict, VerdictStatus


def build_remediation_briefing(
    specs: list[CheckSpec],
    verdicts: list[HostVerdict],
    use_llm: bool = True,
) -> str:
    """Generate a host-aware remediation & operational impact briefing."""
    affected = [v for v in verdicts if v.status == VerdictStatus.AFFECTED]
    under_inv = [v for v in verdicts if v.status == VerdictStatus.UNDER_INVESTIGATION]
    actionable = affected + under_inv
    if not actionable:
        return "All evaluated hosts are deterministically NOT AFFECTED. No remediation actions required."

    # Prioritize confirmed AFFECTED findings and keep prompt compact for fast local CPU models
    provider = detect_provider()
    max_items = 3 if provider == "ollama" else 8
    max_toks = 180 if provider == "ollama" else 512
    llm_items = actionable[:max_items]
    spec_map = {s.cve_id: s for s in specs}
    findings_lines: list[str] = []
    for v in llm_items:
        spec = spec_map.get(v.cve_id)
        patch_str = v.patch.status if v.patch else "unknown"
        short_reason = v.reason[:120]
        short_mit = (v.mitigation[0] if v.mitigation else "None")[:100]
        findings_lines.append(
            f"- {v.host} ({v.os_family}) {v.cve_id} [{spec.severity if spec else 'HIGH'}] "
            f"Patch={patch_str} | Mit={short_mit} | Proof={short_reason}"
        )

    prompt = (
        f"Write {len(findings_lines)} short bullets (max 18 words each, no intro): "
        "[Host CVE] Risk & safest action.\n"
        + "\n".join(findings_lines)
    )

    if use_llm:
        llm_reply = generate(prompt, timeout=90, json_format=False, max_tokens=max_toks).strip()
        if llm_reply:
            st = get_ai_status()
            model_name = st.get("model") or "default"
            extra_note = (
                f"\n(Showing AI triage for top {len(llm_items)} of {len(actionable)} actionable findings)"
                if len(actionable) > len(llm_items)
                else ""
            )
            return f"[AI Provider: {provider} | Model: {model_name} | Local-Only: {st.get('local_only')}]\n{llm_reply}{extra_note}"

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
            first_action = v.mitigation[0]
            if (
                ("nginx" in search_text or ":443" in search_text or ":80" in search_text)
                and "ufw default deny" in first_action.lower()
                and len(v.mitigation) > 1
            ):
                first_action = v.mitigation[1]
            out_lines.append(f"   • Recommended First Action: {first_action}")

    return "\n".join(out_lines)
