"""Local Web Dashboard (`notaffected ui`) for interactive vulnerability reachability
proofs, live CVE scanning, and OpenVEX v0.2.0 / HTML export.

Binds strictly to 127.0.0.1 by default with zero external framework dependencies.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from notaffected import __version__
from notaffected.advisories.ai_advisor import build_remediation_briefing
from notaffected.advisories.builtin_specs import BUILTIN_SPECS
from notaffected.advisories.extractor import resolve_check_spec
from notaffected.advisories.fetcher import fetch_advisories_concurrent
from notaffected.advisories.live_feed import collect_scan_specs
from notaffected.engine.evaluator import evaluate_fleet
from notaffected.importers.scanners import parse_scanner_json
from notaffected.inventory import (
    discover_docker_containers,
    load_demo_fleet,
    load_runners,
)
from notaffected.model import CheckSpec, VerdictStatus
from notaffected.probes.runner import DockerRunner, HostRunner, LocalRunner
from notaffected.render.html import build_html_report
from notaffected.render.vex import build_openvex

MAX_REQUEST_BODY_BYTES = 1_048_576
MAX_CUSTOM_CVES = 50
_CVE_TOKEN_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_ALLOWED_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


def _build_runners_for_mode(
    target_mode: str,
    custom_container: str | None = None,
) -> list[HostRunner]:
    mode = (target_mode or "docker_discovered").strip().lower()
    if mode == "demo_fleet":
        return load_demo_fleet()
    if mode == "local":
        return [LocalRunner()]
    if mode == "lab_inventory":
        inv_path = Path("lab/inventory.yaml")
        if inv_path.is_file():
            return load_runners(inventory_path=inv_path)
    if mode == "custom_inventory":
        inv_path = Path("inventory.yaml")
        if inv_path.is_file():
            return load_runners(inventory_path=inv_path)
    if mode == "docker_discovered":
        containers = discover_docker_containers()
        if containers:
            return [
                DockerRunner(
                    container=c["docker"],
                    host_name=c["name"],
                    os_family=c.get("os", "linux"),
                )
                for c in containers
            ]
        inv_path = Path("lab/inventory.yaml")
        if inv_path.is_file():
            return load_runners(inventory_path=inv_path)
    if custom_container:
        return [DockerRunner(container=custom_container.strip())]
    return load_demo_fleet()


def evaluate_dashboard_request(payload: dict[str, Any]) -> dict[str, Any]:
    """Execute a dashboard scan or targeted CVE check and return JSON-serializable results."""
    target_mode = str(payload.get("target_mode") or "docker_discovered")
    scan_mode = str(payload.get("scan_mode") or "live_scan")
    offline = bool(payload.get("offline", False))
    use_llm = bool(payload.get("use_llm", False))

    runners = _build_runners_for_mode(target_mode)

    feed_meta: dict[str, Any] = {
        "builtin_count": len(BUILTIN_SPECS),
        "osv_live_cves": [],
        "cisa_kev_cves": [],
        "total_cves": 0,
        "offline": offline,
    }

    if scan_mode == "custom_cves":
        raw_cves = payload.get("cves") or []
        if isinstance(raw_cves, str):
            tokens = [
                tok.strip().upper()
                for tok in raw_cves.replace(",", " ").split()
                if tok.strip()
            ]
        elif isinstance(raw_cves, list):
            tokens = [str(c).strip().upper() for c in raw_cves if str(c).strip()]
        else:
            tokens = []
        cve_list = [t for t in dict.fromkeys(tokens) if _CVE_TOKEN_RE.match(t)][
            :MAX_CUSTOM_CVES
        ]
        if not cve_list:
            cve_list = list(BUILTIN_SPECS.keys())
        non_builtin = [c for c in cve_list if not offline and c not in BUILTIN_SPECS]
        if len(non_builtin) > 1:
            fetch_advisories_concurrent(non_builtin)
        specs: list[CheckSpec] = [
            resolve_check_spec(cid, use_llm=use_llm) for cid in cve_list
        ]
        feed_meta["total_cves"] = len(specs)
    elif scan_mode == "scanner_json":
        raw_report = payload.get("scanner_report")
        sample_path = Path("examples/trivy-scan.json")
        try:
            if isinstance(raw_report, (dict, str)) and raw_report:
                findings = parse_scanner_json(raw_report)
            elif sample_path.is_file():
                findings = parse_scanner_json(sample_path)
            else:
                findings = []
        except Exception:
            findings = []
        non_builtin = [
            f.cve_id
            for f in findings[:MAX_CUSTOM_CVES]
            if not offline and f.cve_id.strip().upper() not in BUILTIN_SPECS
        ]
        if len(non_builtin) > 1:
            fetch_advisories_concurrent(non_builtin)
        specs = []
        seen_cves: set[str] = set()
        for f in findings:
            if f.cve_id in seen_cves or len(specs) >= MAX_CUSTOM_CVES:
                continue
            seen_cves.add(f.cve_id)
            specs.append(
                resolve_check_spec(
                    f.cve_id,
                    use_llm=use_llm,
                    package_hint=f.package_name,
                    fixed_version_hint=f.fixed_version,
                )
            )
        if not specs:
            specs = list(BUILTIN_SPECS.values())
        feed_meta["total_cves"] = len(specs)
    else:
        specs, feed_meta = collect_scan_specs(
            runners,
            offline=offline,
            use_llm=use_llm,
        )

    verdicts = evaluate_fleet(specs, runners)
    briefing = build_remediation_briefing(specs, verdicts, use_llm=use_llm)
    openvex_doc = build_openvex(verdicts)
    html_doc = build_html_report(specs, verdicts)

    affected_count = sum(1 for v in verdicts if v.status == VerdictStatus.AFFECTED)
    not_affected_count = sum(1 for v in verdicts if v.status == VerdictStatus.NOT_AFFECTED)
    under_inv_count = sum(
        1 for v in verdicts if v.status == VerdictStatus.UNDER_INVESTIGATION
    )
    total_count = len(verdicts)
    noise_pct = (
        round((not_affected_count / total_count) * 100, 1) if total_count > 0 else 0.0
    )

    return {
        "summary": {
            "total": total_count,
            "affected": affected_count,
            "not_affected": not_affected_count,
            "under_investigation": under_inv_count,
            "noise_reduction_pct": noise_pct,
            "hosts_evaluated": len(runners),
            "cves_evaluated": len(specs),
        },
        "feed_meta": feed_meta,
        "specs": [s.to_dict() for s in specs],
        "verdicts": [v.to_dict() for v in verdicts],
        "briefing": briefing,
        "openvex": openvex_doc,
        "html_report": html_doc,
    }


def get_targets_metadata() -> dict[str, Any]:
    """Return discovered Docker containers, inventory availability, and built-in CVEs."""
    containers = discover_docker_containers()
    return {
        "version": __version__,
        "docker_containers": containers,
        "has_lab_inventory": Path("lab/inventory.yaml").is_file(),
        "has_custom_inventory": Path("inventory.yaml").is_file(),
        "builtin_cves": [
            {
                "cve_id": s.cve_id,
                "summary": s.summary,
                "severity": s.severity,
                "os_family": s.os_family,
                "precondition_count": len(s.preconditions),
            }
            for s in BUILTIN_SPECS.values()
        ],
    }


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>notaffected — Vulnerability Reachability &amp; OpenVEX Dashboard</title>
  <style>
    :root {
      --bg: #0b0f19;
      --panel: #111827;
      --panel-alt: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --danger: #ef4444;
      --danger-bg: rgba(239, 68, 68, 0.14);
      --ok: #22c55e;
      --ok-bg: rgba(34, 197, 94, 0.14);
      --warn: #eab308;
      --warn-bg: rgba(234, 179, 8, 0.14);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }
    header {
      border-bottom: 1px solid var(--border);
      background: var(--panel);
      padding: 1rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .brand h1 {
      margin: 0;
      font-size: 1.35rem;
      letter-spacing: -0.02em;
    }
    .pill {
      font-size: 0.75rem;
      padding: 0.2rem 0.6rem;
      border-radius: 999px;
      background: var(--panel-alt);
      border: 1px solid var(--border);
      color: var(--accent);
      font-weight: 600;
    }
    main {
      max-width: 1360px;
      margin: 0 auto;
      padding: 1.5rem 2rem 3rem;
    }
    .controls-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 1rem;
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.25rem;
      margin-bottom: 1.5rem;
    }
    .field label {
      display: block;
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--muted);
      margin-bottom: 0.4rem;
      font-weight: 600;
    }
    select, input[type="text"] {
      width: 100%;
      padding: 0.6rem 0.75rem;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--bg);
      color: var(--text);
      font-size: 0.92rem;
    }
    .btn-row {
      display: flex;
      align-items: flex-end;
      gap: 0.6rem;
      flex-wrap: wrap;
    }
    button {
      cursor: pointer;
      padding: 0.62rem 1.1rem;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--panel-alt);
      color: var(--text);
      font-weight: 600;
      font-size: 0.9rem;
      transition: filter 0.15s;
    }
    button:hover { filter: brightness(1.15); }
    button.primary {
      background: #0284c7;
      border-color: #38bdf8;
      color: #fff;
    }
    button:disabled {
      opacity: 0.55;
      cursor: wait;
    }
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }
    .kpi-card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1rem 1.2rem;
    }
    .kpi-card .label {
      font-size: 0.8rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .kpi-card .val {
      font-size: 1.9rem;
      font-weight: 700;
      margin-top: 0.2rem;
    }
    .val.danger { color: var(--danger); }
    .val.ok { color: var(--ok); }
    .val.warn { color: var(--warn); }
    .val.accent { color: var(--accent); }
    .section-card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.25rem;
      margin-bottom: 1.5rem;
    }
    .section-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      flex-wrap: wrap;
      margin-bottom: 1rem;
    }
    .section-header h2 {
      margin: 0;
      font-size: 1.1rem;
    }
    .filter-bar {
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
      align-items: center;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.9rem;
    }
    th, td {
      text-align: left;
      padding: 0.75rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    th {
      color: var(--muted);
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .badge {
      display: inline-block;
      padding: 0.18rem 0.55rem;
      border-radius: 6px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
    }
    .badge.affected { background: var(--danger-bg); color: var(--danger); border: 1px solid var(--danger); }
    .badge.not_affected { background: var(--ok-bg); color: var(--ok); border: 1px solid var(--ok); }
    .badge.under_investigation { background: var(--warn-bg); color: var(--warn); border: 1px solid var(--warn); }
    .badge.os { background: var(--panel-alt); color: var(--accent); border: 1px solid var(--border); }
    pre.briefing {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      white-space: pre-wrap;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.85rem;
      margin: 0;
    }
    .mit-row {
      display: flex;
      align-items: center;
      gap: 0.45rem;
      margin-top: 0.35rem;
      flex-wrap: wrap;
    }
    .mit-cmd {
      flex: 1;
      display: block;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.35rem 0.6rem;
      font-family: ui-monospace, SFMono-Regular, monospace;
      font-size: 0.8rem;
      color: #bae6fd;
    }
    button.mini {
      padding: 0.25rem 0.55rem;
      font-size: 0.75rem;
      border-radius: 6px;
    }
    .feed-banner {
      font-size: 0.84rem;
      color: var(--muted);
      margin-bottom: 1rem;
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <h1>notaffected</h1>
      <span class="pill" id="verPill">Reachability &amp; OpenVEX Engine</span>
      <span class="pill" id="dockerCountPill">Docker Targets: ...</span>
    </div>
    <div class="btn-row">
      <button id="btnExportVex" disabled>Download OpenVEX (.vex.json)</button>
      <button id="btnExportJson" disabled>Download Audit JSON</button>
      <button id="btnExportHtml" disabled>Download Standalone HTML</button>
    </div>
  </header>

  <main>
    <div class="controls-grid">
      <div class="field">
        <label for="targetMode">1. Target Fleet</label>
        <select id="targetMode">
          <option value="docker_discovered">Running Docker Lab Containers (Auto-Discover)</option>
          <option value="lab_inventory">Lab Inventory (lab/inventory.yaml)</option>
          <option value="custom_inventory">Custom Inventory (inventory.yaml)</option>
          <option value="demo_fleet">Simulated Demo Fleet (3 Linux + 2 Windows Server)</option>
          <option value="local">Local Machine (localhost)</option>
        </select>
      </div>

      <div class="field">
        <label for="scanMode">2. Evaluation Mode</label>
        <select id="scanMode">
          <option value="live_scan">Auto-Scan (Built-in + Live OSV Packages + CISA KEV Feed)</option>
          <option value="custom_cves">Specific CVE ID(s)</option>
          <option value="scanner_json">Filter Trivy / Grype JSON Report</option>
        </select>
      </div>

      <div class="field" id="customCveField" style="display:none;">
        <label for="cveInput">CVE IDs (comma or space separated)</label>
        <input type="text" id="cveInput" placeholder="e.g. CVE-2024-6387, CVE-2024-38063, CVE-2021-34527" value="CVE-2024-6387, CVE-2024-38063, CVE-2021-34527" />
      </div>

      <div class="field" id="scannerJsonField" style="display:none;">
        <label for="scannerFileInput">Trivy / Grype JSON File (leave empty for examples/trivy-scan.json)</label>
        <input type="file" id="scannerFileInput" accept=".json,application/json" style="color:var(--muted); font-size:0.85rem;" />
      </div>

      <div class="btn-row">
        <button class="primary" id="btnRun">Run Reachability Proof</button>
        <label style="font-size:0.84rem; color:var(--muted); display:flex; align-items:center; gap:0.35rem;">
          <input type="checkbox" id="chkOffline" /> Offline Only (Skip Live Feeds)
        </label>
      </div>
    </div>

    <div class="feed-banner" id="feedBanner">Ready. Click "Run Reachability Proof" to evaluate targets.</div>

    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="label">Total Host-CVE Proofs</div>
        <div class="val" id="kpiTotal">0</div>
      </div>
      <div class="kpi-card">
        <div class="label">Affected (Action Required)</div>
        <div class="val danger" id="kpiAffected">0</div>
      </div>
      <div class="kpi-card">
        <div class="label">Not Affected (VEX Proven)</div>
        <div class="val ok" id="kpiNotAffected">0</div>
      </div>
      <div class="kpi-card">
        <div class="label">False-Positive Noise Cut</div>
        <div class="val accent" id="kpiNoise">0%</div>
      </div>
    </div>

    <div class="section-card">
      <div class="section-header">
        <h2>Host Reachability Verdicts &amp; Deterministic Proofs</h2>
        <div class="filter-bar">
          <select id="filterStatus" style="width:auto;">
            <option value="all">All Verdicts</option>
            <option value="affected">Affected Only</option>
            <option value="not_affected">Not Affected Only</option>
            <option value="under_investigation">Under Investigation</option>
          </select>
          <select id="filterOs" style="width:auto;">
            <option value="all">All OS Families</option>
            <option value="linux">Linux</option>
            <option value="windows">Windows Server</option>
          </select>
          <input type="text" id="filterSearch" placeholder="Filter host, CVE, proof..." style="width:220px;" />
        </div>
      </div>

      <table>
        <thead>
          <tr>
            <th>Host</th>
            <th>OS</th>
            <th>CVE ID</th>
            <th>Verdict</th>
            <th>VEX Justification / Patch Status</th>
            <th>Deterministic System Proof &amp; Temporary Mitigations</th>
          </tr>
        </thead>
        <tbody id="verdictsBody">
          <tr><td colspan="6" style="color:var(--muted);">Loading initial evaluation...</td></tr>
        </tbody>
      </table>
    </div>

    <div class="section-card">
      <div class="section-header">
        <h2>Operational Risk &amp; Remediation Safety Briefing</h2>
      </div>
      <pre class="briefing" id="briefingBox">Run an evaluation to view host-aware remediation guidance.</pre>
    </div>
  </main>

  <script>
    let latestResult = null;

    function esc(s) {
      const div = document.createElement("div");
      div.textContent = s == null ? "" : String(s);
      return div.innerHTML;
    }

    function downloadBlob(filename, content, mimeType) {
      const blob = new Blob([content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    }

    document.getElementById("scanMode").addEventListener("change", (e) => {
      document.getElementById("customCveField").style.display =
        e.target.value === "custom_cves" ? "block" : "none";
      document.getElementById("scannerJsonField").style.display =
        e.target.value === "scanner_json" ? "block" : "none";
    });

    async function loadMeta() {
      try {
        const res = await fetch("/api/targets");
        const data = await res.json();
        document.getElementById("verPill").textContent = "v" + (data.version || "0.5.0");
        const count = (data.docker_containers || []).length;
        document.getElementById("dockerCountPill").textContent =
          count > 0
            ? "Discovered Docker Containers: " + count
            : "Docker Containers: 0 (Demo Fleet ready)";
        if (count === 0 && !data.has_lab_inventory) {
          document.getElementById("targetMode").value = "demo_fleet";
        }
      } catch (err) {
        console.error(err);
      }
    }

    function renderVerdictRows() {
      const tbody = document.getElementById("verdictsBody");
      if (!latestResult || !latestResult.verdicts) {
        tbody.innerHTML = '<tr><td colspan="6">No verdicts available.</td></tr>';
        return;
      }
      const stFilter = document.getElementById("filterStatus").value;
      const osFilter = document.getElementById("filterOs").value;
      const q = (document.getElementById("filterSearch").value || "").toLowerCase();

      const filtered = latestResult.verdicts.filter((v) => {
        if (stFilter !== "all" && v.status !== stFilter) return false;
        if (osFilter !== "all" && v.os_family !== osFilter) return false;
        if (q) {
          const blob = `${v.host} ${v.cve_id} ${v.reason} ${v.justification || ""}`.toLowerCase();
          if (!blob.includes(q)) return false;
        }
        return true;
      });

      if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="color:var(--muted);">No matching verdicts for current filter.</td></tr>';
        return;
      }

      tbody.innerHTML = filtered.map((v) => {
        const justOrPatch = v.status === "not_affected"
          ? `<code>${esc(v.justification || "not_affected")}</code>`
          : `Patch: <strong>${esc(v.patch ? v.patch.status : "unknown")}</strong>` +
            (v.patch && v.patch.fixed_version ? ` (<code>${esc(v.patch.fixed_version)}</code>)` : "");
        const mitigationsHtml = (v.status === "affected" && v.mitigation && v.mitigation.length > 0)
          ? v.mitigation.map((m) => `
              <div class="mit-row">
                <code class="mit-cmd">$ ${esc(m)}</code>
                <button type="button" class="mini" data-copy-cmd="${esc(m)}">Copy</button>
                <button type="button" class="mini" data-reverify="1">Re-Verify</button>
              </div>
            `).join("")
          : "";
        return `
          <tr>
            <td><strong>${esc(v.host)}</strong></td>
            <td><span class="badge os">${esc(v.os_family)}</span></td>
            <td><code>${esc(v.cve_id)}</code></td>
            <td><span class="badge ${esc(v.status)}">${esc(v.status)}</span></td>
            <td>${justOrPatch}</td>
            <td>
              <div>${esc(v.reason)}</div>
              ${mitigationsHtml}
            </td>
          </tr>
        `;
      }).join("");
    }

    async function runEvaluation() {
      const btn = document.getElementById("btnRun");
      btn.disabled = true;
      btn.textContent = "Probing targets...";
      document.getElementById("feedBanner").textContent = "Executing read-only system probes and live CVE checks...";

      const body = {
        target_mode: document.getElementById("targetMode").value,
        scan_mode: document.getElementById("scanMode").value,
        cves: document.getElementById("cveInput").value,
        offline: document.getElementById("chkOffline").checked,
      };
      if (body.scan_mode === "scanner_json") {
        const fileEl = document.getElementById("scannerFileInput");
        if (fileEl && fileEl.files && fileEl.files.length > 0) {
          body.scanner_report = await fileEl.files[0].text();
        }
      }

      try {
        const res = await fetch("/api/evaluate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        latestResult = await res.json();
        const s = latestResult.summary || {};
        document.getElementById("kpiTotal").textContent = s.total || 0;
        document.getElementById("kpiAffected").textContent = s.affected || 0;
        document.getElementById("kpiNotAffected").textContent = s.not_affected || 0;
        document.getElementById("kpiNoise").textContent = (s.noise_reduction_pct || 0) + "%";
        document.getElementById("briefingBox").textContent = latestResult.briefing || "";

        const fm = latestResult.feed_meta || {};
        const osvCount = (fm.osv_live_cves || []).length;
        const kevCount = (fm.cisa_kev_cves || []).length;
        document.getElementById("feedBanner").textContent =
          `Evaluated ${s.hosts_evaluated || 0} host(s) across ${s.cves_evaluated || 0} CVE(s) ` +
          `[Built-in rules: ${fm.builtin_count || 0} | Live OSV package CVEs: ${osvCount} | Live CISA KEV CVEs: ${kevCount}]`;

        document.getElementById("btnExportVex").disabled = false;
        document.getElementById("btnExportJson").disabled = false;
        document.getElementById("btnExportHtml").disabled = false;
        renderVerdictRows();
      } catch (err) {
        document.getElementById("feedBanner").textContent = "Error during evaluation: " + err;
      } finally {
        btn.disabled = false;
        btn.textContent = "Run Reachability Proof";
      }
    }

    document.getElementById("btnRun").addEventListener("click", runEvaluation);
    document.getElementById("filterStatus").addEventListener("change", renderVerdictRows);
    document.getElementById("filterOs").addEventListener("change", renderVerdictRows);
    document.getElementById("filterSearch").addEventListener("input", renderVerdictRows);

    document.getElementById("verdictsBody").addEventListener("click", async (e) => {
      const btn = e.target.closest("button");
      if (!btn) return;
      const copyCmd = btn.getAttribute("data-copy-cmd");
      if (copyCmd) {
        try {
          await navigator.clipboard.writeText(copyCmd);
          const orig = btn.textContent;
          btn.textContent = "Copied!";
          setTimeout(() => { btn.textContent = orig; }, 1200);
        } catch (err) {
          console.error(err);
        }
        return;
      }
      if (btn.getAttribute("data-reverify")) {
        runEvaluation();
      }
    });

    document.getElementById("btnExportVex").addEventListener("click", () => {
      if (!latestResult) return;
      downloadBlob("notaffected.vex.json", JSON.stringify(latestResult.openvex, null, 2), "application/json");
    });
    document.getElementById("btnExportJson").addEventListener("click", () => {
      if (!latestResult) return;
      downloadBlob("notaffected-audit.json", JSON.stringify({
        specs: latestResult.specs,
        verdicts: latestResult.verdicts,
        summary: latestResult.summary
      }, null, 2), "application/json");
    });
    document.getElementById("btnExportHtml").addEventListener("click", () => {
      if (!latestResult) return;
      downloadBlob("notaffected-report.html", latestResult.html_report || "", "text/html");
    });

    loadMeta().then(() => runEvaluation());
  </script>
</body>
</html>
"""


class DashboardRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the local notaffected Web UI."""

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _send_json(self, status: int, data: dict[str, Any]) -> None:
        raw = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, status: int, html_text: str) -> None:
        raw = html_text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _is_allowed_host(self) -> bool:
        raw_host = (self.headers.get("Host") or "").strip().lower()
        if not raw_host:
            return False
        host_only = raw_host.split(":")[0] if not raw_host.startswith("[") else raw_host.split("]")[0] + "]"
        srv_addr = str(self.server.server_address[0]).lower()
        return host_only in _ALLOWED_LOCAL_HOSTS or host_only == srv_addr

    def _is_allowed_post_origin(self) -> bool:
        ctype = (self.headers.get("Content-Type") or "").strip().lower()
        if not ctype.startswith("application/json"):
            return False
        origin = (self.headers.get("Origin") or "").strip()
        if origin:
            parsed_origin = urllib.parse.urlparse(origin)
            origin_host = (parsed_origin.hostname or "").lower()
            srv_addr = str(self.server.server_address[0]).lower()
            if origin_host not in _ALLOWED_LOCAL_HOSTS and origin_host != srv_addr:
                return False
        return True

    def do_GET(self) -> None:  # noqa: N802
        if not self._is_allowed_host():
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "Forbidden Host header"})
            return
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            self._send_html(HTTPStatus.OK, DASHBOARD_HTML)
            return
        if parsed.path == "/api/targets":
            self._send_json(HTTPStatus.OK, get_targets_metadata())
            return
        if parsed.path == "/api/spec":
            qs = urllib.parse.parse_qs(parsed.query)
            cve = (qs.get("cve") or [""])[0].strip()
            if not cve:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Missing cve query parameter"})
                return
            spec = resolve_check_spec(cve, use_llm=False)
            self._send_json(HTTPStatus.OK, spec.to_dict())
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._is_allowed_host() or not self._is_allowed_post_origin():
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "Forbidden cross-origin or non-JSON request"},
            )
            return
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/api/evaluate":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
            return
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_REQUEST_BODY_BYTES:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "Invalid or oversized request body"},
            )
            return
        try:
            raw_body = self.rfile.read(length)
            payload = json.loads(raw_body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("Expected JSON object")
        except Exception as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"Invalid JSON: {exc}"})
            return

        result = evaluate_dashboard_request(payload)
        self._send_json(HTTPStatus.OK, result)


def run_web_server(host: str = "127.0.0.1", port: int = 8484) -> None:
    """Start the local notaffected Web UI server."""
    server = ThreadingHTTPServer((host, port), DashboardRequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
