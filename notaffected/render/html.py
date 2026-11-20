"""Self-contained interactive HTML report generator for notaffected.

Zero external CDNs, fonts, or network calls. All untrusted host/probe data is
strictly escaped via `html.escape`.
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
    affected_count = sum(1 for v in verdicts if v.status == VerdictStatus.AFFECTED)
    under_inv_count = sum(
        1 for v in verdicts if v.status == VerdictStatus.UNDER_INVESTIGATION
    )
    not_affected_count = sum(1 for v in verdicts if v.status == VerdictStatus.NOT_AFFECTED)

    spec_cards_html: list[str] = []
    for s in specs:
        pre_items = "".join(
            f"<li><code>{html.escape(p.probe)}</code> {html.escape(str(p.params))} &mdash; "
            f"{html.escape(p.description)} <span class='muted'>(if false &rarr; "
            f"{html.escape(p.justification_if_not_met.value)})</span></li>"
            for p in s.preconditions
        )
        mit_items = "".join(
            f"<li><code>$ {html.escape(m)}</code></li>" for m in s.mitigation
        )
        mit_block = (
            f"<div class='mit-box'><strong>Temporary Mitigations:</strong><ul>{mit_items}</ul></div>"
            if mit_items
            else ""
        )
        patch_str = html.escape(s.patch.status)
        if s.patch.fixed_version:
            patch_str += f" &mdash; fixed in <code>{html.escape(s.patch.fixed_version)}</code>"
        if s.patch.pocket:
            patch_str += f" ({html.escape(s.patch.pocket)})"

        spec_cards_html.append(
            f"""
            <div class="spec-card">
              <div class="spec-header">
                <span class="cve-id">{html.escape(s.cve_id)}</span>
                <span class="badge sev">{html.escape(s.severity)}</span>
                <span class="muted">source: {html.escape(s.source)} | confidence: {html.escape(s.confidence)}</span>
              </div>
              <p class="summary">{html.escape(s.summary)}</p>
              <div class="pre-box">
                <strong>Required Preconditions:</strong>
                <ol>{pre_items}</ol>
              </div>
              {mit_block}
              <p class="patch-line"><strong>Patch Status:</strong> {patch_str}</p>
            </div>
            """
        )

    rows_html: list[str] = []
    for v in verdicts:
        st_val = v.status.value
        badge_cls = {
            "affected": "badge-affected",
            "under_investigation": "badge-unknown",
            "not_affected": "badge-safe",
        }.get(st_val, "badge-unknown")
        just_str = html.escape(v.justification.value) if v.justification else "&mdash;"
        mit_inline = ""
        if v.status == VerdictStatus.AFFECTED and v.mitigation:
            cmds = "<br>".join(f"<code>$ {html.escape(m)}</code>" for m in v.mitigation)
            mit_inline = f"<div class='row-mit'><strong>Mitigation:</strong><br>{cmds}</div>"

        probes_inline = ""
        if v.probe_results:
            p_lines = []
            for idx, pr in enumerate(v.probe_results, 1):
                p_st = html.escape(pr.status.value)
                p_name = html.escape(pr.precondition.probe)
                p_cmd = html.escape(pr.command or "n/a")
                p_ev = html.escape(pr.evidence)
                p_lines.append(
                    f"<li><strong>#{idx} [{p_st}]</strong> <code>{p_name}</code> "
                    f"&mdash; cmd: <code>{p_cmd}</code><br><span class='muted'>{p_ev}</span></li>"
                )
            probes_inline = (
                f"<details style='margin-top:0.4rem;font-size:0.82rem;'>"
                f"<summary style='cursor:pointer;color:var(--cyan);'>"
                f"Inspect Probe Commands &amp; Audit Trail ({len(v.probe_results)})</summary>"
                f"<ul style='margin:0.35rem 0 0;padding-left:1.2rem;'>{''.join(p_lines)}</ul>"
                f"</details>"
            )

        rows_html.append(
            f"""
            <tr data-status="{html.escape(st_val)}">
              <td class="host-col">{html.escape(v.host)}</td>
              <td><code>{html.escape(v.cve_id)}</code></td>
              <td><span class="badge {badge_cls}">{html.escape(st_val.upper())}</span></td>
              <td><code>{just_str}</code></td>
              <td>{html.escape(v.reason)}{mit_inline}{probes_inline}</td>
            </tr>
            """
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>notaffected — Exploitability &amp; VEX Audit Report</title>
  <style>
    :root {{
      --bg: #0f172a;
      --panel: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --muted: #94a3b8;
      --red: #ef4444;
      --amber: #f59e0b;
      --green: #10b981;
      --cyan: #38bdf8;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      padding: 2rem;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }}
    .container {{ width: 100%; max-width: 100%; margin: 0; }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      border-bottom: 1px solid var(--border);
      padding-bottom: 1rem;
      margin-bottom: 1.5rem;
    }}
    h1 {{ margin: 0; font-size: 1.6rem; color: var(--cyan); }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1rem;
      margin-bottom: 1.5rem;
    }}
    .stat-card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      cursor: pointer;
    }}
    .stat-card .num {{ font-size: 1.8rem; font-weight: 700; }}
    .num.red {{ color: var(--red); }}
    .num.amber {{ color: var(--amber); }}
    .num.green {{ color: var(--green); }}
    .spec-card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
      margin-bottom: 1rem;
    }}
    .spec-header {{ display: flex; gap: 0.75rem; align-items: center; margin-bottom: 0.5rem; }}
    .cve-id {{ font-weight: 700; font-size: 1.15rem; color: var(--cyan); }}
    .muted {{ color: var(--muted); font-size: 0.88rem; }}
    .badge {{
      display: inline-block;
      padding: 0.15rem 0.55rem;
      border-radius: 4px;
      font-size: 0.78rem;
      font-weight: 700;
    }}
    .badge.sev {{ background: #334155; color: var(--text); }}
    .badge-affected {{ background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid var(--red); }}
    .badge-unknown {{ background: rgba(245, 158, 11, 0.2); color: #fcd34d; border: 1px solid var(--amber); }}
    .badge-safe {{ background: rgba(16, 185, 129, 0.2); color: #6ee7b7; border: 1px solid var(--green); }}
    .controls {{ display: flex; gap: 0.75rem; margin: 1.5rem 0 1rem; }}
    input[type="search"] {{
      flex: 1;
      background: var(--panel);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 0.5rem 0.75rem;
      border-radius: 6px;
    }}
    table {{
      width: 100%;
      table-layout: fixed;
      border-collapse: collapse;
      background: var(--panel);
      border-radius: 8px;
      overflow: hidden;
    }}
    th, td {{
      text-align: left;
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
      overflow-wrap: anywhere;
      word-break: break-word;
    }}
    th {{ background: #0f172a; color: var(--muted); font-size: 0.85rem; text-transform: uppercase; }}
    .host-col {{ font-weight: 600; }}
    .row-mit {{ margin-top: 0.5rem; padding: 0.5rem; background: #0f172a; border-radius: 4px; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.88em; overflow-wrap: anywhere; word-break: break-word; white-space: pre-wrap; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>notaffected &mdash; Exploitability &amp; VEX Audit Report</h1>
      <span class="muted">Generated: {now_iso}</span>
    </header>

    <div class="stats">
      <div class="stat-card" onclick="filterRows('all')">
        <div class="muted">Total Host Checks</div>
        <div class="num">{len(verdicts)}</div>
      </div>
      <div class="stat-card" onclick="filterRows('affected')">
        <div class="muted">Affected (Action Required)</div>
        <div class="num red">{affected_count}</div>
      </div>
      <div class="stat-card" onclick="filterRows('under_investigation')">
        <div class="muted">Under Investigation</div>
        <div class="num amber">{under_inv_count}</div>
      </div>
      <div class="stat-card" onclick="filterRows('not_affected')">
        <div class="muted">Not Affected (Proven)</div>
        <div class="num green">{not_affected_count}</div>
      </div>
    </div>

    <h2>Evaluated CVE Specifications</h2>
    {''.join(spec_cards_html)}

    <h2>Host Verdicts &amp; Deterministic Proofs</h2>
    <div class="controls">
      <input type="search" id="searchInput" placeholder="Filter by hostname, CVE, justification, or proof..." oninput="applySearch()">
    </div>
    <table id="verdictTable">
      <thead>
        <tr>
          <th>Host</th>
          <th>CVE</th>
          <th>Status</th>
          <th>OpenVEX Justification</th>
          <th>Deterministic Proof &amp; Mitigation</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows_html)}
      </tbody>
    </table>
  </div>
  <script>
    let currentStatus = 'all';
    function filterRows(status) {{
      currentStatus = status;
      applySearch();
    }}
    function applySearch() {{
      const q = (document.getElementById('searchInput').value || '').toLowerCase();
      const rows = document.querySelectorAll('#verdictTable tbody tr');
      rows.forEach(r => {{
        const st = r.getAttribute('data-status');
        const matchesStatus = (currentStatus === 'all' || st === currentStatus);
        const matchesText = (r.textContent || '').toLowerCase().includes(q);
        r.style.display = (matchesStatus && matchesText) ? '' : 'none';
      }});
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
