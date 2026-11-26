"""Self-contained interactive HTML report generator for notaffected.

Zero external CDNs, fonts, or network calls. Styled to match the Obsidian Dark
+ warm coral (`#f08a59`) Web Dashboard with a 1-click Light/Dark theme toggle.
All untrusted host/probe data is strictly escaped via `html.escape`.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path

from notaffected.model import CheckSpec, HostVerdict, VerdictStatus


def build_html_report(
    specs: list[CheckSpec],
    verdicts: list[HostVerdict],
) -> str:
    """Build a standalone, interactive HTML audit report."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    total_count = len(verdicts)
    affected_count = sum(1 for v in verdicts if v.status == VerdictStatus.AFFECTED)
    under_inv_count = sum(
        1 for v in verdicts if v.status == VerdictStatus.UNDER_INVESTIGATION
    )
    not_affected_count = sum(1 for v in verdicts if v.status == VerdictStatus.NOT_AFFECTED)
    noise_cut_pct = round((not_affected_count / total_count) * 100) if total_count else 0

    pct_aff = (affected_count / total_count * 100.0) if total_count else 0.0
    pct_unk = (under_inv_count / total_count * 100.0) if total_count else 0.0
    pct_safe = (not_affected_count / total_count * 100.0) if total_count else 0.0

    unique_hosts = len({v.host for v in verdicts})
    spec_by_cve = {s.cve_id.upper(): s for s in specs}

    spec_cards_html: list[str] = []
    for s in specs:
        pre_items = "".join(
            f"<li><code>{html.escape(p.probe)}</code> "
            f"<code class='param-code'>{html.escape(str(p.params))}</code> "
            f"<span class='sep'>/</span> {html.escape(p.description)} "
            f"<span class='muted'>(if false &rarr; {html.escape(p.justification_if_not_met.value)})</span></li>"
            for p in s.preconditions
        ) or "<li class='muted'>No runtime preconditions extracted (resolves to under_investigation)</li>"
        mit_items = "".join(
            f"<li><code>$ {html.escape(m)}</code></li>" for m in s.mitigation
        )
        mit_block = (
            f"<div class='spec-sub'><div class='sub-label'>Temporary Mitigations</div>"
            f"<ul class='cmd-list'>{mit_items}</ul></div>"
            if mit_items
            else ""
        )
        patch_parts = [html.escape(s.patch.status)]
        if s.patch.fixed_version:
            patch_parts.append(f"fixed in <code>{html.escape(s.patch.fixed_version)}</code>")
        if s.patch.pocket:
            patch_parts.append(f"({html.escape(s.patch.pocket)})")
        patch_str = " &middot; ".join(patch_parts)

        sev_low = s.severity.strip().lower()
        sev_cls = (
            "sev-crit"
            if sev_low == "critical"
            else "sev-high"
            if sev_low == "high"
            else "sev-med"
            if sev_low == "medium"
            else "sev-low"
        )
        os_label = "Windows" if s.os_family == "windows" else "Linux"

        spec_cards_html.append(
            f"""
            <details class="spec-card">
              <summary class="spec-summary">
                <div class="spec-title-row">
                  <span class="cve-id">{html.escape(s.cve_id)}</span>
                  <span class="badge {sev_cls}">{html.escape(s.severity)}</span>
                  <span class="os-pill">{os_label}</span>
                  <span class="meta-pill">source: {html.escape(s.source)}</span>
                  <span class="meta-pill">confidence: {html.escape(s.confidence)}</span>
                </div>
                <div class="spec-desc">{html.escape(s.summary)}</div>
              </summary>
              <div class="spec-body">
                <div class="spec-sub">
                  <div class="sub-label">Required Preconditions ({len(s.preconditions)})</div>
                  <ol class="pre-list">{pre_items}</ol>
                </div>
                {mit_block}
                <div class="patch-line"><strong>Patch Status:</strong> {patch_str}</div>
              </div>
            </details>
            """
        )

    rows_html: list[str] = []
    for v in verdicts:
        st_val = v.status.value
        badge_cls, row_cls, st_label = {
            "affected": ("badge-affected", "row-affected", "AFFECTED"),
            "under_investigation": ("badge-unknown", "row-unknown", "UNDER INVESTIGATION"),
            "not_affected": ("badge-safe", "row-safe", "NOT AFFECTED"),
        }.get(st_val, ("badge-unknown", "row-unknown", st_val.upper()))

        spec_ref = spec_by_cve.get(v.cve_id.upper())
        sev_badge = ""
        if spec_ref and spec_ref.severity:
            s_low = spec_ref.severity.strip().lower()
            s_cls = (
                "sev-crit"
                if s_low == "critical"
                else "sev-high"
                if s_low == "high"
                else "sev-med"
                if s_low == "medium"
                else "sev-low"
            )
            sev_badge = f"<div class='cell-sub'><span class='badge {s_cls}'>{html.escape(spec_ref.severity)}</span></div>"

        os_label = "Windows" if v.os_family == "windows" else "Linux"

        just_html = (
            f"<code class='vex-token'>{html.escape(v.justification.value)}</code>"
            if v.justification
            else "<span class='muted'>&mdash;</span>"
        )
        patch_html = ""
        if v.patch and (v.patch.status or v.patch.fixed_version):
            p_bits = [html.escape(v.patch.status)]
            if v.patch.fixed_version:
                p_bits.append(f"<code>{html.escape(v.patch.fixed_version)}</code>")
            patch_html = f"<div class='cell-sub muted'>Patch: {' &middot; '.join(p_bits)}</div>"

        mit_inline = ""
        if v.status == VerdictStatus.AFFECTED and v.mitigation:
            cmds = "".join(
                f"<div class='mit-cmd'><code>$ {html.escape(m)}</code></div>"
                for m in v.mitigation
            )
            mit_inline = (
                f"<div class='row-mit'><div class='sub-label'>Recommended Mitigation</div>{cmds}</div>"
            )

        probes_inline = ""
        if v.probe_results:
            p_lines = []
            for idx, pr in enumerate(v.probe_results, 1):
                p_st = pr.status.value
                p_st_cls = (
                    "p-met"
                    if p_st == "MET"
                    else "p-not-met"
                    if p_st == "NOT_MET"
                    else "p-unk"
                )
                p_name = html.escape(pr.precondition.probe)
                p_cmd = html.escape(pr.command or "n/a")
                p_ev = html.escape(pr.evidence)
                p_lines.append(
                    f"<li><span class='probe-tag {p_st_cls}'>#{idx} {html.escape(p_st)}</span> "
                    f"<code>{p_name}</code> <span class='muted'>cmd:</span> <code>{p_cmd}</code>"
                    f"<div class='probe-ev'>{p_ev}</div></li>"
                )
            probes_inline = (
                f"<details class='probe-trail'>"
                f"<summary>Inspect Probe Commands &amp; Audit Trail ({len(v.probe_results)})</summary>"
                f"<ul class='probe-list'>{''.join(p_lines)}</ul>"
                f"</details>"
            )

        rows_html.append(
            f"""
            <tr class="{row_cls}" data-status="{html.escape(st_val)}">
              <td class="verdict-cell">
                <span class="badge {badge_cls}">{html.escape(st_label)}</span>
              </td>
              <td class="cve-cell">
                <code class="cve-code">{html.escape(v.cve_id)}</code>
                {sev_badge}
              </td>
              <td class="host-cell">
                <div class="host-name">{html.escape(v.host)}</div>
                <div class="cell-sub"><span class="os-pill">{os_label}</span></div>
              </td>
              <td class="vex-cell">
                {just_html}
                {patch_html}
              </td>
              <td class="proof-cell">
                <div class="proof-text">{html.escape(v.reason)}</div>
                {mit_inline}
                {probes_inline}
              </td>
            </tr>
            """
        )

    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='8' fill='%2309090b' stroke='%2332323a' stroke-width='1.5'/%3E%3Cpath d='M10 9H7v14h3M22 9h3v14h-3' stroke='%23e4e4e7' stroke-width='2.2' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3Cpath d='M11.5 16.5l3.2 3.2 6-6.8' stroke='%2322c55e' stroke-width='2.6' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
  <title>notaffected - Exploitability &amp; OpenVEX Audit Report</title>
  <style>
    :root, [data-theme="dark"] {{
      --bg: #09090b;
      --surface: #111114;
      --surface-raised: #18181b;
      --surface-hover: #202024;
      --border: rgba(255, 255, 255, 0.08);
      --border-strong: rgba(255, 255, 255, 0.14);
      --text: #f4f4f5;
      --text-2: #a1a1aa;
      --text-3: #71717a;
      --accent: #f08a59;
      --accent-soft: rgba(240, 138, 89, 0.14);
      --red: #f87171;
      --red-soft: rgba(248, 113, 113, 0.14);
      --red-border: rgba(248, 113, 113, 0.36);
      --amber: #fbbf24;
      --amber-soft: rgba(251, 191, 36, 0.14);
      --amber-border: rgba(251, 191, 36, 0.36);
      --green: #34d399;
      --green-soft: rgba(52, 211, 153, 0.14);
      --green-border: rgba(52, 211, 153, 0.36);
      --code-bg: #0c0c0f;
      --shadow: 0 1px 2px rgba(0, 0, 0, 0.35);
    }}
    [data-theme="light"] {{
      --bg: #f8fafc;
      --surface: #ffffff;
      --surface-raised: #f1f5f9;
      --surface-hover: #e2e8f0;
      --border: rgba(15, 23, 42, 0.10);
      --border-strong: rgba(15, 23, 42, 0.18);
      --text: #0f172a;
      --text-2: #475569;
      --text-3: #64748b;
      --accent: #d96b38;
      --accent-soft: rgba(217, 107, 56, 0.12);
      --red: #dc2626;
      --red-soft: rgba(220, 38, 38, 0.10);
      --red-border: rgba(220, 38, 38, 0.30);
      --amber: #b45309;
      --amber-soft: rgba(217, 119, 6, 0.12);
      --amber-border: rgba(217, 119, 6, 0.32);
      --green: #059669;
      --green-soft: rgba(5, 150, 105, 0.10);
      --green-border: rgba(5, 150, 105, 0.30);
      --code-bg: #f1f5f9;
      --shadow: 0 1px 3px rgba(15, 23, 42, 0.08);
    }}
    * {{ box-sizing: border-box; }}
    html, body {{
      margin: 0;
      padding: 0;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
      font-size: 14px;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }}
    .topbar {{
      position: sticky;
      top: 0;
      z-index: 20;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      padding: 0.85rem 1.75rem;
      background: var(--surface);
      border-bottom: 1px solid var(--border);
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 0.7rem;
    }}
    .brand-mark {{
      width: 28px;
      height: 28px;
      border-radius: 7px;
      background: var(--accent-soft);
      border: 1px solid var(--accent);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      color: var(--accent);
      font-weight: 800;
      font-size: 13px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    }}
    .brand h1 {{
      margin: 0;
      font-size: 1.05rem;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: var(--text);
    }}
    .brand-sub {{
      font-size: 0.78rem;
      color: var(--text-3);
    }}
    .topbar-right {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
      flex-wrap: wrap;
    }}
    .meta-chip {{
      font-size: 0.76rem;
      color: var(--text-2);
      background: var(--surface-raised);
      border: 1px solid var(--border);
      padding: 0.25rem 0.6rem;
      border-radius: 999px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    }}
    .theme-btn {{
      background: var(--surface-raised);
      color: var(--text);
      border: 1px solid var(--border-strong);
      border-radius: 6px;
      padding: 0.35rem 0.75rem;
      font-size: 0.78rem;
      font-weight: 600;
      cursor: pointer;
    }}
    .theme-btn:hover {{
      background: var(--surface-hover);
      border-color: var(--accent);
    }}
    .container {{
      width: 100%;
      max-width: 1480px;
      margin: 0 auto;
      padding: 1.5rem 1.75rem 3rem;
    }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 0.85rem;
      margin-bottom: 1rem;
    }}
    @media (max-width: 980px) {{
      .kpi-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    }}
    .kpi-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.95rem 1.05rem;
      cursor: pointer;
      text-align: left;
      color: inherit;
      font: inherit;
      box-shadow: var(--shadow);
      transition: border-color 0.15s ease, background 0.15s ease;
    }}
    .kpi-card:hover {{
      border-color: var(--border-strong);
      background: var(--surface-raised);
    }}
    .kpi-card.kpi-highlight {{
      border-color: rgba(240, 138, 89, 0.35);
      background: linear-gradient(135deg, var(--surface) 0%, var(--accent-soft) 100%);
    }}
    .kpi-label {{
      font-size: 0.74rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-3);
      font-weight: 600;
    }}
    .kpi-num {{
      font-size: 1.85rem;
      font-weight: 700;
      letter-spacing: -0.03em;
      margin-top: 0.2rem;
      font-variant-numeric: tabular-nums;
    }}
    .kpi-sub {{
      font-size: 0.74rem;
      color: var(--text-2);
      margin-top: 0.15rem;
    }}
    .num-accent {{ color: var(--accent); }}
    .num-red {{ color: var(--red); }}
    .num-amber {{ color: var(--amber); }}
    .num-green {{ color: var(--green); }}
    .split-panel {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.85rem 1.05rem;
      margin-bottom: 1.5rem;
    }}
    .split-head {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.5rem;
      font-size: 0.78rem;
      color: var(--text-2);
    }}
    .split-bar {{
      display: flex;
      height: 8px;
      width: 100%;
      border-radius: 999px;
      overflow: hidden;
      background: var(--surface-raised);
    }}
    .seg-aff {{ background: var(--red); }}
    .seg-unk {{ background: var(--amber); }}
    .seg-safe {{ background: var(--green); }}
    .split-legend {{
      display: flex;
      gap: 1.1rem;
      margin-top: 0.5rem;
      font-size: 0.75rem;
      color: var(--text-2);
      flex-wrap: wrap;
    }}
    .dot {{
      display: inline-block;
      width: 8px;
      height: 8px;
      border-radius: 50%;
      margin-right: 0.35rem;
    }}
    .section-head {{
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      margin: 1.5rem 0 0.75rem;
    }}
    .section-head h2 {{
      margin: 0;
      font-size: 0.95rem;
      font-weight: 700;
      letter-spacing: -0.01em;
    }}
    .toolbar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.75rem;
      flex-wrap: wrap;
      margin-bottom: 0.85rem;
    }}
    .pill-group {{
      display: inline-flex;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 3px;
      gap: 3px;
    }}
    .filter-pill {{
      background: transparent;
      color: var(--text-2);
      border: none;
      border-radius: 6px;
      padding: 0.35rem 0.7rem;
      font-size: 0.78rem;
      font-weight: 600;
      cursor: pointer;
    }}
    .filter-pill:hover {{ color: var(--text); }}
    .filter-pill[aria-pressed="true"] {{
      background: var(--surface-raised);
      color: var(--text);
      box-shadow: inset 0 0 0 1px var(--border-strong);
    }}
    input[type="search"] {{
      flex: 1;
      min-width: 240px;
      max-width: 440px;
      background: var(--surface);
      border: 1px solid var(--border-strong);
      color: var(--text);
      padding: 0.45rem 0.75rem;
      border-radius: 8px;
      font-size: 0.84rem;
    }}
    input[type="search"]:focus {{
      outline: 2px solid var(--accent);
      outline-offset: 1px;
    }}
    .table-wrap {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow-x: auto;
      box-shadow: var(--shadow);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
      min-width: 780px;
    }}
    th, td {{
      text-align: left;
      padding: 0.75rem 0.9rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
      overflow-wrap: anywhere;
      word-break: break-word;
    }}
    th {{
      background: var(--surface-raised);
      color: var(--text-3);
      font-size: 0.72rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    tbody tr:last-child td {{ border-bottom: none; }}
    tbody tr:hover {{ background: var(--surface-hover); }}
    tbody tr.row-affected td:first-child {{ border-left: 3px solid var(--red); }}
    tbody tr.row-unknown td:first-child {{ border-left: 3px solid var(--amber); }}
    tbody tr.row-safe td:first-child {{ border-left: 3px solid var(--green); }}
    th:nth-child(1), td:nth-child(1) {{ width: 12%; }}
    th:nth-child(2), td:nth-child(2) {{ width: 12%; }}
    th:nth-child(3), td:nth-child(3) {{ width: 13%; }}
    th:nth-child(4), td:nth-child(4) {{ width: 22%; }}
    th:nth-child(5), td:nth-child(5) {{ width: 41%; }}
    .host-name {{ font-weight: 600; color: var(--text); }}
    .cve-code {{ font-weight: 600; color: var(--accent); background: transparent; padding: 0; }}
    .cell-sub {{ margin-top: 0.3rem; font-size: 0.76rem; }}
    .badge {{
      display: inline-block;
      padding: 0.16rem 0.5rem;
      border-radius: 5px;
      font-size: 0.7rem;
      font-weight: 700;
      letter-spacing: 0.03em;
      white-space: nowrap;
    }}
    .badge-affected {{ background: var(--red-soft); color: var(--red); border: 1px solid var(--red-border); }}
    .badge-unknown {{ background: var(--amber-soft); color: var(--amber); border: 1px solid var(--amber-border); }}
    .badge-safe {{ background: var(--green-soft); color: var(--green); border: 1px solid var(--green-border); }}
    .sev-crit {{ background: var(--red-soft); color: var(--red); border: 1px solid var(--red-border); }}
    .sev-high {{ background: var(--accent-soft); color: var(--accent); border: 1px solid rgba(240, 138, 89, 0.35); }}
    .sev-med {{ background: var(--amber-soft); color: var(--amber); border: 1px solid var(--amber-border); }}
    .sev-low {{ background: var(--surface-raised); color: var(--text-2); border: 1px solid var(--border-strong); }}
    .os-pill, .meta-pill {{
      display: inline-block;
      font-size: 0.7rem;
      padding: 0.1rem 0.45rem;
      border-radius: 4px;
      background: var(--surface-raised);
      border: 1px solid var(--border);
      color: var(--text-2);
    }}
    .vex-token {{
      font-size: 0.78rem;
      color: var(--text);
      background: var(--code-bg);
      border: 1px solid var(--border);
      padding: 0.12rem 0.38rem;
      border-radius: 4px;
    }}
    .proof-text {{ color: var(--text); }}
    .row-mit {{
      margin-top: 0.55rem;
      padding: 0.55rem 0.65rem;
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-left: 2px solid var(--accent);
      border-radius: 6px;
    }}
    .sub-label {{
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-3);
      font-weight: 700;
      margin-bottom: 0.3rem;
    }}
    .mit-cmd {{ margin-top: 0.2rem; }}
    .probe-trail {{
      margin-top: 0.5rem;
      font-size: 0.8rem;
    }}
    .probe-trail summary {{
      cursor: pointer;
      color: var(--accent);
      font-weight: 600;
      user-select: none;
    }}
    .probe-list {{
      margin: 0.45rem 0 0;
      padding-left: 1.1rem;
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
    }}
    .probe-tag {{
      display: inline-block;
      font-size: 0.68rem;
      font-weight: 700;
      padding: 0.06rem 0.35rem;
      border-radius: 4px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    }}
    .p-met {{ background: var(--red-soft); color: var(--red); }}
    .p-not-met {{ background: var(--green-soft); color: var(--green); }}
    .p-unk {{ background: var(--amber-soft); color: var(--amber); }}
    .probe-ev {{ color: var(--text-2); margin-top: 0.15rem; }}
    .specs-grid {{
      display: flex;
      flex-direction: column;
      gap: 0.6rem;
    }}
    .spec-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.8rem 1rem;
    }}
    .spec-summary {{
      cursor: pointer;
      list-style: none;
    }}
    .spec-summary::-webkit-details-marker {{ display: none; }}
    .spec-title-row {{
      display: flex;
      align-items: center;
      gap: 0.5rem;
      flex-wrap: wrap;
    }}
    .cve-id {{
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-weight: 700;
      color: var(--accent);
      font-size: 0.92rem;
    }}
    .spec-desc {{
      color: var(--text-2);
      font-size: 0.84rem;
      margin-top: 0.3rem;
    }}
    .spec-body {{
      margin-top: 0.75rem;
      padding-top: 0.75rem;
      border-top: 1px solid var(--border);
    }}
    .spec-sub {{ margin-bottom: 0.65rem; }}
    .pre-list, .cmd-list {{
      margin: 0.25rem 0 0;
      padding-left: 1.25rem;
      display: flex;
      flex-direction: column;
      gap: 0.3rem;
      font-size: 0.83rem;
    }}
    .patch-line {{ font-size: 0.82rem; color: var(--text-2); }}
    .muted {{ color: var(--text-2); }}
    .sep {{ color: var(--text-3); margin: 0 0.2rem; }}
    code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.84em;
      background: var(--code-bg);
      padding: 0.1rem 0.32rem;
      border-radius: 4px;
      overflow-wrap: anywhere;
      word-break: break-word;
      white-space: pre-wrap;
    }}
    .param-code {{ color: var(--text-2); }}
    @media print {{
      .topbar {{ position: static; }}
      .theme-btn, .toolbar {{ display: none; }}
      body {{ background: #fff; color: #000; }}
    }}
  </style>
</head>
<body>
  <header class="topbar">
    <div class="brand">
      <span class="brand-mark" aria-hidden="true"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M7.5 6H5v12h2.5M16.5 6H19v12h-2.5" stroke="currentColor" stroke-width="2.1"/><path d="M8.8 12.4 11.2 14.8 15.6 9.6" stroke="#22c55e" stroke-width="2.3"/></svg></span>
      <div>
        <h1>notaffected</h1>
        <div class="brand-sub">Deterministic Exploitability &amp; OpenVEX v0.2.0 Audit Report</div>
      </div>
    </div>
    <div class="topbar-right">
      <span class="meta-chip">{unique_hosts} host(s) &middot; {len(specs)} CVE(s)</span>
      <span class="meta-chip">Generated {now_iso}</span>
      <button type="button" id="themeToggle" class="theme-btn" onclick="toggleTheme()">Light Mode</button>
    </div>
  </header>

  <main class="container">
    <section class="kpi-grid" aria-label="Audit Summary">
      <button type="button" class="kpi-card kpi-highlight" onclick="filterRows('not_affected')">
        <div class="kpi-label">False-Positive Noise Cut</div>
        <div class="kpi-num num-accent">{noise_cut_pct}%</div>
        <div class="kpi-sub">{not_affected_count} of {total_count} checks proven safe</div>
      </button>
      <button type="button" class="kpi-card" onclick="filterRows('all')">
        <div class="kpi-label">Total Host Checks</div>
        <div class="kpi-num">{total_count}</div>
        <div class="kpi-sub">Across {unique_hosts} target(s)</div>
      </button>
      <button type="button" class="kpi-card" onclick="filterRows('affected')">
        <div class="kpi-label">Affected</div>
        <div class="kpi-num num-red">{affected_count}</div>
        <div class="kpi-sub">Action required</div>
      </button>
      <button type="button" class="kpi-card" onclick="filterRows('under_investigation')">
        <div class="kpi-label">Under Investigation</div>
        <div class="kpi-num num-amber">{under_inv_count}</div>
        <div class="kpi-sub">Fail-closed unknown</div>
      </button>
      <button type="button" class="kpi-card" onclick="filterRows('not_affected')">
        <div class="kpi-label">Not Affected</div>
        <div class="kpi-num num-green">{not_affected_count}</div>
        <div class="kpi-sub">Deterministic VEX proof</div>
      </button>
    </section>

    <section class="split-panel" aria-label="Verdict Split">
      <div class="split-head">
        <strong>Verdict Split</strong>
        <span id="visibleCounter">Showing {total_count} of {total_count} checks</span>
      </div>
      <div class="split-bar" role="img" aria-label="Affected {affected_count}, Under Investigation {under_inv_count}, Not Affected {not_affected_count}">
        <div class="seg-aff" style="width:{pct_aff:.2f}%"></div>
        <div class="seg-unk" style="width:{pct_unk:.2f}%"></div>
        <div class="seg-safe" style="width:{pct_safe:.2f}%"></div>
      </div>
      <div class="split-legend">
        <span><span class="dot" style="background:var(--red)"></span>Affected ({affected_count})</span>
        <span><span class="dot" style="background:var(--amber)"></span>Under Investigation ({under_inv_count})</span>
        <span><span class="dot" style="background:var(--green)"></span>Not Affected ({not_affected_count})</span>
      </div>
    </section>

    <div class="section-head">
      <h2>Host Verdicts &amp; Deterministic Proofs</h2>
    </div>
    <div class="toolbar">
      <div class="pill-group" role="group" aria-label="Filter verdicts by status">
        <button type="button" class="filter-pill" data-filter="all" aria-pressed="true" onclick="filterRows('all')">All ({total_count})</button>
        <button type="button" class="filter-pill" data-filter="affected" aria-pressed="false" onclick="filterRows('affected')">Affected ({affected_count})</button>
        <button type="button" class="filter-pill" data-filter="under_investigation" aria-pressed="false" onclick="filterRows('under_investigation')">Under Investigation ({under_inv_count})</button>
        <button type="button" class="filter-pill" data-filter="not_affected" aria-pressed="false" onclick="filterRows('not_affected')">Not Affected ({not_affected_count})</button>
      </div>
      <input type="search" id="searchInput" aria-label="Search verdicts" placeholder="Filter by host, CVE, justification, or proof..." oninput="applySearch()">
    </div>
    <div class="table-wrap">
      <table id="verdictTable">
        <thead>
          <tr>
            <th>Verdict</th>
            <th>CVE ID</th>
            <th>Host</th>
            <th>VEX Justification / Patch</th>
            <th>Deterministic Proof &amp; Mitigations</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows_html)}
        </tbody>
      </table>
    </div>

    <div class="section-head">
      <h2>Evaluated CVE Specifications ({len(specs)})</h2>
      <span class="muted">Click any specification to inspect preconditions and patch metadata</span>
    </div>
    <section class="specs-grid">
      {''.join(spec_cards_html)}
    </section>
  </main>

  <script>
    let currentStatus = 'all';
    const totalRows = {total_count};
    function toggleTheme() {{
      const root = document.documentElement;
      const next = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      root.setAttribute('data-theme', next);
      const btn = document.getElementById('themeToggle');
      if (btn) btn.textContent = next === 'light' ? 'Dark Mode' : 'Light Mode';
    }}
    function filterRows(status) {{
      currentStatus = status;
      document.querySelectorAll('.filter-pill').forEach(btn => {{
        btn.setAttribute('aria-pressed', btn.getAttribute('data-filter') === status ? 'true' : 'false');
      }});
      applySearch();
    }}
    function applySearch() {{
      const q = (document.getElementById('searchInput').value || '').toLowerCase();
      const rows = document.querySelectorAll('#verdictTable tbody tr');
      let shown = 0;
      rows.forEach(r => {{
        const st = r.getAttribute('data-status');
        const matchesStatus = (currentStatus === 'all' || st === currentStatus);
        const matchesText = (r.textContent || '').toLowerCase().includes(q);
        const visible = matchesStatus && matchesText;
        r.style.display = visible ? '' : 'none';
        if (visible) shown += 1;
      }});
      const counter = document.getElementById('visibleCounter');
      if (counter) counter.textContent = 'Showing ' + shown + ' of ' + totalRows + ' checks';
    }}
  </script>
</body>
</html>
"""


def write_html_report(
    specs: list[CheckSpec],
    verdicts: list[HostVerdict],
    path: Path,
) -> str:
    """Write standalone HTML report to `path` and return the HTML string."""
    doc = build_html_report(specs, verdicts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc, encoding="utf-8")
    return doc
