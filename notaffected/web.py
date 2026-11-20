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
from notaffected.probes.runner import (
    CommandResult,
    DockerRunner,
    HostRunner,
    LocalRunner,
    MockRunner,
    SSHRunner,
)
from notaffected.render.html import build_html_report
from notaffected.render.vex import build_openvex

MAX_REQUEST_BODY_BYTES = 1_048_576
MAX_CUSTOM_CVES = 50
_CVE_TOKEN_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$")
_ALLOWED_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})
_DEMO_MITIGATED: set[tuple[str, str]] = set()
_EXEC_MITIGATION_PREFIXES = (
    "sudo ",
    "echo ",
    "set-itemproperty ",
    "stop-service ",
    "set-service ",
)


def _is_executable_mitigation(cmd: str) -> bool:
    low = cmd.strip().lower()
    return low.startswith(_EXEC_MITIGATION_PREFIXES)


def _apply_demo_overrides(runners: list[HostRunner]) -> list[HostRunner]:
    for r in runners:
        if not isinstance(r, MockRunner):
            continue
        if (r.host_name, "CVE-2024-6387") in _DEMO_MITIGATED:
            r.responses[("cat", "/etc/ssh/sshd_config")] = CommandResult(
                0, "PermitRootLogin no\nLoginGraceTime 0\n", ""
            )
        if (r.host_name, "CVE-2026-98432") in _DEMO_MITIGATED:
            r.responses[("ufw", "status", "verbose")] = CommandResult(
                0,
                "Status: active\nDefault: deny (incoming), allow (outgoing)\n",
                "",
            )
        if (r.host_name, "CVE-2024-38063") in _DEMO_MITIGATED:
            ps_reg_ipv6 = (
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters' "
                "-Name 'DisabledComponents' -ErrorAction Stop).'DisabledComponents'",
            )
            r.responses[ps_reg_ipv6] = CommandResult(0, "255\n", "")
        if (r.host_name, "CVE-2021-34527") in _DEMO_MITIGATED:
            ps_svc_spooler = (
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-Service -Name 'Spooler' -ErrorAction Stop).Status",
            )
            r.responses[ps_svc_spooler] = CommandResult(0, "Stopped\n", "")
    return runners


def _build_runners_for_mode(
    target_mode: str,
    custom_container: str | None = None,
    custom_target_type: str | None = None,
    custom_target_value: str | None = None,
) -> list[HostRunner]:
    mode = (target_mode or "docker_discovered").strip().lower()
    if mode == "demo_fleet":
        return _apply_demo_overrides(load_demo_fleet())
    if mode == "local":
        return [LocalRunner()]
    if mode == "custom_target":
        val = (custom_target_value or "").strip()
        ttype = (custom_target_type or "docker_linux").strip().lower()
        if val and _SAFE_TARGET_RE.match(val):
            os_fam = "windows" if "windows" in ttype else "linux"
            if ttype.startswith("ssh"):
                return [SSHRunner(target=val, host_name=val, os_family=os_fam)]
            return [DockerRunner(container=val, host_name=val, os_family=os_fam)]
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
    return _apply_demo_overrides(load_demo_fleet())


def reset_lab_and_demo() -> dict[str, Any]:
    """Reset in-memory demo fleet mitigations and restore lab containers to initial vulnerable state."""
    _DEMO_MITIGATED.clear()
    reset_targets: list[str] = ["demo_fleet"]

    containers = {c["docker"] for c in discover_docker_containers()}
    if "lab-ssh-vuln" in containers:
        r_ssh = DockerRunner(container="lab-ssh-vuln", host_name="lab-ssh-vuln", os_family="linux")
        res = r_ssh.run(
            [
                "sh",
                "-c",
                "printf 'Port 22\\nPermitRootLogin no\\nLoginGraceTime 120\\n' > /etc/ssh/sshd_config "
                "&& echo '1:9.6p1-3ubuntu13' > /etc/ssh/openssh_version",
            ]
        )
        if res.returncode == 0 and not res.transport_error:
            reset_targets.append("lab-ssh-vuln")
    if "lab-win-dc01" in containers:
        r_win = DockerRunner(container="lab-win-dc01", host_name="lab-win-dc01", os_family="windows")
        res = r_win.run(
            ["sh", "-c", "echo '0' > /etc/win-sim/DisabledComponents && echo 'Running' > /etc/win-sim/Spooler"]
        )
        if res.returncode == 0 and not res.transport_error:
            reset_targets.append("lab-win-dc01")

    return {"ok": True, "reset_targets": reset_targets}


def apply_host_mitigation(payload: dict[str, Any]) -> dict[str, Any]:
    """Execute an allowlisted CheckSpec mitigation command on the specified host runner."""
    target_mode = str(payload.get("target_mode") or "docker_discovered")
    custom_target_type = str(payload.get("custom_target_type") or "")
    custom_target_value = str(payload.get("custom_target_value") or "")
    host = str(payload.get("host") or "").strip()
    cve_id = str(payload.get("cve_id") or "").strip().upper()
    try:
        mit_idx = int(payload.get("mitigation_index", 0))
    except (ValueError, TypeError):
        mit_idx = -1

    if not host or not _CVE_TOKEN_RE.match(cve_id) or mit_idx < 0:
        return {"ok": False, "error": "Invalid host, CVE ID, or mitigation index"}

    spec = resolve_check_spec(cve_id, use_llm=False)
    if mit_idx >= len(spec.mitigation):
        return {"ok": False, "error": f"Mitigation index {mit_idx} out of range for {cve_id}"}

    cmd_text = spec.mitigation[mit_idx]
    if not _is_executable_mitigation(cmd_text):
        return {
            "ok": False,
            "error": "Selected mitigation is an advisory instruction, not a direct command.",
        }

    runners = _build_runners_for_mode(
        target_mode,
        custom_target_type=custom_target_type,
        custom_target_value=custom_target_value,
    )
    runner = next((r for r in runners if r.host_name == host), None)
    if runner is None:
        return {"ok": False, "error": f"Target host {host!r} not found in {target_mode!r}"}

    if isinstance(runner, MockRunner):
        _DEMO_MITIGATED.add((host, cve_id))
        return {
            "ok": True,
            "host": host,
            "cve_id": cve_id,
            "command": cmd_text,
            "output": f"Applied mitigation on simulated host {host}.",
        }

    os_family = getattr(runner, "os_family", "linux")
    if os_family == "windows":
        res = runner.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd_text]
        )
    else:
        exec_cmd = cmd_text
        if isinstance(runner, DockerRunner):
            if "LoginGraceTime 0" in exec_cmd and "/etc/ssh/sshd_config" in exec_cmd:
                exec_cmd = "echo 'LoginGraceTime 0' >> /etc/ssh/sshd_config"
            else:
                exec_cmd = re.sub(r"\bsudo\s+", "", exec_cmd)
        res = runner.run(["sh", "-c", exec_cmd])

    if hasattr(runner, "_cache") and isinstance(runner._cache, dict):
        runner._cache.clear()

    ok = res.returncode == 0 and not res.transport_error
    output_text = (res.stdout or res.stderr or "").strip()
    return {
        "ok": ok,
        "host": host,
        "cve_id": cve_id,
        "command": cmd_text,
        "output": output_text or ("Command succeeded." if ok else f"Exit code {res.returncode}"),
        "error": None if ok else (output_text or f"Command failed with exit code {res.returncode}"),
    }


def evaluate_dashboard_request(payload: dict[str, Any]) -> dict[str, Any]:
    """Execute a dashboard scan or targeted CVE check and return JSON-serializable results."""
    target_mode = str(payload.get("target_mode") or "docker_discovered")
    custom_target_type = str(payload.get("custom_target_type") or "")
    custom_target_value = str(payload.get("custom_target_value") or "")
    scan_mode = str(payload.get("scan_mode") or "live_scan")
    offline = bool(payload.get("offline", False))
    use_llm = bool(payload.get("use_llm", False))

    feed_meta: dict[str, Any] = {
        "builtin_count": len(BUILTIN_SPECS),
        "osv_live_cves": [],
        "cisa_kev_cves": [],
        "total_cves": 0,
        "offline": offline,
    }

    mode_low = target_mode.strip().lower()
    if mode_low == "custom_inventory" and not Path("inventory.yaml").is_file():
        runners: list[HostRunner] = []
        feed_meta["error"] = (
            "inventory.yaml not found in working directory "
            "(run 'notaffected init --discover-docker' or select another target fleet)."
        )
    elif mode_low == "custom_target" and not (
        custom_target_value.strip() and _SAFE_TARGET_RE.match(custom_target_value.strip())
    ):
        runners = []
        feed_meta["error"] = (
            f"Invalid or empty custom target address: {custom_target_value!r}"
        )
    else:
        runners = _build_runners_for_mode(
            target_mode,
            custom_target_type=custom_target_type,
            custom_target_value=custom_target_value,
        )

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
            resolve_check_spec(cid, use_llm=use_llm, offline=offline)
            for cid in cve_list
        ]
        feed_meta["total_cves"] = len(specs)
    elif scan_mode == "scanner_json":
        raw_report = payload.get("scanner_report")
        sample_path = Path("examples/trivy-scan.json")
        explicit_report = isinstance(raw_report, (dict, str)) and bool(raw_report)
        try:
            if explicit_report:
                findings = parse_scanner_json(raw_report)
            elif sample_path.is_file():
                findings = parse_scanner_json(sample_path)
            else:
                findings = []
        except Exception as exc:
            findings = []
            feed_meta["error"] = f"Invalid scanner JSON report: {exc}"
        non_builtin = [
            f.cve_id
            for f in findings[:MAX_CUSTOM_CVES]
            if not offline and f.cve_id.strip().upper() not in BUILTIN_SPECS
        ]
        if len(non_builtin) > 1:
            fetch_advisories_concurrent(non_builtin)
        grouped_findings: dict[str, Any] = {}
        for f in findings:
            existing = grouped_findings.get(f.cve_id)
            if existing is None:
                grouped_findings[f.cve_id] = f
            else:
                pkg_cand = (f.package_name or "").lower()
                if pkg_cand.endswith("-server") or pkg_cand.endswith("d"):
                    grouped_findings[f.cve_id] = f
        specs = []
        for cid, f in list(grouped_findings.items())[:MAX_CUSTOM_CVES]:
            specs.append(
                resolve_check_spec(
                    cid,
                    use_llm=use_llm,
                    package_hint=f.package_name,
                    fixed_version_hint=f.fixed_version,
                    offline=offline,
                )
            )
        if not specs and not explicit_report:
            specs = list(BUILTIN_SPECS.values())
        feed_meta["total_cves"] = len(specs)
    else:
        target_error = feed_meta.get("error")
        if target_error and not runners:
            specs = []
        else:
            specs, feed_meta = collect_scan_specs(
                runners,
                offline=offline,
                use_llm=use_llm,
            )
            if target_error:
                feed_meta["error"] = target_error

    verdicts = evaluate_fleet(specs, runners)
    if not verdicts:
        briefing = feed_meta.get("error") or "No hosts or CVEs were evaluated."
    else:
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
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='6' fill='%230284c7'/><path d='M9 17l5 5 9-11' stroke='white' stroke-width='3' fill='none' stroke-linecap='round' stroke-linejoin='round'/></svg>" />
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
      width: 100%;
      max-width: 100%;
      margin: 0;
      padding: 1.25rem 1.75rem 3rem;
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
      overflow-x: auto;
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
      table-layout: fixed;
      border-collapse: collapse;
      font-size: 0.9rem;
    }
    th, td {
      text-align: left;
      padding: 0.75rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    th:nth-child(1), td:nth-child(1) { width: 12%; }
    th:nth-child(2), td:nth-child(2) { width: 8%; }
    th:nth-child(3), td:nth-child(3) { width: 11%; white-space: nowrap; }
    th:nth-child(4), td:nth-child(4) { width: 12%; }
    th:nth-child(5), td:nth-child(5) { width: 17%; }
    th:nth-child(6), td:nth-child(6) { width: 40%; }
    th {
      color: var(--muted);
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    code {
      overflow-wrap: anywhere;
      word-break: break-word;
      white-space: pre-wrap;
    }
    .badge {
      display: inline-block;
      padding: 0.18rem 0.55rem;
      border-radius: 6px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      white-space: nowrap;
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
      overflow-wrap: anywhere;
      word-break: break-word;
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
      max-width: 100%;
    }
    .mit-cmd {
      flex: 1 1 260px;
      min-width: 0;
      max-width: 100%;
      display: block;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.35rem 0.6rem;
      font-family: ui-monospace, SFMono-Regular, monospace;
      font-size: 0.8rem;
      color: #bae6fd;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
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
          <option value="custom_target">Custom Target (Single Docker Container / SSH Host)</option>
        </select>
      </div>

      <div class="field" id="customTargetField" style="display:none;">
        <label for="customTargetValue">Custom Target Type &amp; Address</label>
        <div style="display:flex; gap:0.5rem;">
          <select id="customTargetType" style="width:48%;">
            <option value="docker_linux">Docker (Linux)</option>
            <option value="docker_windows">Docker (Win-Sim)</option>
            <option value="ssh_linux">SSH (Linux)</option>
            <option value="ssh_windows">SSH (Windows)</option>
          </select>
          <input type="text" id="customTargetValue" placeholder="e.g. lab-ssh-vuln or ubuntu@10.0.0.15" value="lab-ssh-vuln" style="width:52%;" />
        </div>
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
        <button id="btnResetLab" title="Restore Demo Fleet and Docker Lab containers to initial vulnerable state">Reset Lab / Demo</button>
        <label style="font-size:0.84rem; color:var(--muted); display:flex; align-items:center; gap:0.35rem;">
          <input type="checkbox" id="chkOffline" /> Offline Only (Skip Live Feeds)
        </label>
        <label style="font-size:0.84rem; color:var(--muted); display:flex; align-items:center; gap:0.35rem;">
          <input type="checkbox" id="chkUseLlm" /> Use Local LLM (Ollama / AI Advisor)
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
        <div class="label">Under Investigation</div>
        <div class="val" id="kpiUnderInv" style="color:var(--warn);">0</div>
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
    let activeTargetConfig = {
      target_mode: "docker_discovered",
      custom_target_type: "docker_linux",
      custom_target_value: "lab-ssh-vuln",
    };

    function esc(s) {
      return String(s == null ? "" : s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
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

    document.getElementById("targetMode").addEventListener("change", (e) => {
      document.getElementById("customTargetField").style.display =
        e.target.value === "custom_target" ? "block" : "none";
    });

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
        const customInvOpt = document.querySelector('#targetMode option[value="custom_inventory"]');
        if (customInvOpt && !data.has_custom_inventory) {
          customInvOpt.textContent = "Custom Inventory (inventory.yaml — not found)";
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
      const specById = {};
      for (const sp of (latestResult.specs || [])) {
        if (sp && sp.cve_id) specById[sp.cve_id] = sp;
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
        const spec = specById[v.cve_id] || null;
        const justOrPatch = v.status === "not_affected"
          ? `<code>${esc(v.justification || "not_affected")}</code>`
          : `Patch: <strong>${esc(v.patch ? v.patch.status : "unknown")}</strong>` +
            (v.patch && v.patch.fixed_version ? ` (<code>${esc(v.patch.fixed_version)}</code>)` : "");
        const mitigationsHtml = (v.status === "affected" && v.mitigation && v.mitigation.length > 0)
          ? v.mitigation.map((m, idx) => {
              const low = String(m || "").trim().toLowerCase();
              const canRun = (
                low.startsWith("sudo ") ||
                low.startsWith("echo ") ||
                low.startsWith("set-itemproperty ") ||
                low.startsWith("stop-service ") ||
                low.startsWith("set-service ")
              );
              const runBtn = canRun
                ? `<button type="button" class="mini primary" data-apply-host="${esc(v.host)}" data-apply-cve="${esc(v.cve_id)}" data-apply-idx="${idx}" data-apply-cmd="${esc(m)}">Run Mitigation</button>`
                : "";
              return `
                <div class="mit-row">
                  <code class="mit-cmd">$ ${esc(m)}</code>
                  ${runBtn}
                  <button type="button" class="mini" data-copy-cmd="${esc(m)}">Copy</button>
                </div>
              `;
            }).join("")
          : "";

        const probes = v.probe_results || [];
        let probeListHtml = "";
        if (probes.length > 0) {
          probeListHtml = probes.map((pr, idx) => {
            const pSt = String(pr.status || "UNKNOWN");
            const pColor = pSt === "NOT_MET" ? "var(--ok)" : (pSt === "MET" ? "var(--danger)" : "var(--warn)");
            const pName = pr.precondition ? pr.precondition.probe : "probe";
            const pDesc = pr.precondition ? pr.precondition.description : "";
            return `
              <div style="margin-top:0.45rem; padding:0.45rem 0.65rem; background:var(--bg); border:1px solid var(--border); border-radius:6px; font-size:0.81rem;">
                <div>
                  <strong style="color:${pColor};">#${idx + 1} [${esc(pSt)}]</strong>
                  <code>${esc(pName)}</code> &mdash; <span style="color:var(--muted);">${esc(pDesc)}</span>
                </div>
                <div style="margin-top:0.2rem;">Command: <code>${esc(pr.command || "n/a")}</code></div>
                <div style="margin-top:0.15rem; color:var(--muted);">Output: ${esc(pr.evidence || "")}</div>
              </div>
            `;
          }).join("");
        } else if (spec && spec.preconditions && spec.preconditions.length > 0) {
          probeListHtml = spec.preconditions.map((pre, idx) => `
            <div style="margin-top:0.35rem; font-size:0.8rem; color:var(--muted);">
              #${idx + 1} <code>${esc(pre.probe)}</code>: ${esc(pre.description)} (skipped due to OS mismatch)
            </div>
          `).join("");
        } else {
          probeListHtml = `<div style="margin-top:0.35rem; font-size:0.8rem; color:var(--muted);">No deterministic preconditions available for this advisory.</div>`;
        }

        const specMeta = spec
          ? `Rule source: ${esc(spec.source)} | Confidence: ${esc(spec.confidence)} | Severity: ${esc(spec.severity)}`
          : "";
        const inspectDrawer = `
          <details style="margin-top:0.45rem;">
            <summary style="cursor:pointer; font-size:0.8rem; color:var(--accent); user-select:none;">
              Inspect Probes &amp; Commands (${probes.length} executed${specMeta ? " — " + specMeta : ""})
            </summary>
            <div style="margin-top:0.35rem;">
              ${spec ? `<div style="font-size:0.81rem; color:var(--text); margin-bottom:0.3rem;"><strong>Advisory:</strong> ${esc(spec.summary)}</div>` : ""}
              ${probeListHtml}
            </div>
          </details>
        `;

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
              ${inspectDrawer}
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
        custom_target_type: document.getElementById("customTargetType").value,
        custom_target_value: document.getElementById("customTargetValue").value,
        scan_mode: document.getElementById("scanMode").value,
        cves: document.getElementById("cveInput").value,
        offline: document.getElementById("chkOffline").checked,
        use_llm: document.getElementById("chkUseLlm").checked,
      };
      activeTargetConfig = {
        target_mode: body.target_mode,
        custom_target_type: body.custom_target_type,
        custom_target_value: body.custom_target_value,
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
        document.getElementById("kpiUnderInv").textContent = s.under_investigation || 0;
        document.getElementById("kpiNoise").textContent = (s.noise_reduction_pct || 0) + "%";
        document.getElementById("briefingBox").textContent = latestResult.briefing || "";

        const fm = latestResult.feed_meta || {};
        const bannerEl = document.getElementById("feedBanner");
        if (fm.error) {
          bannerEl.style.color = "var(--danger)";
          bannerEl.textContent = "Notice: " + fm.error;
        } else {
          bannerEl.style.color = "var(--muted)";
          const osvCount = (fm.osv_live_cves || []).length;
          const kevCount = (fm.cisa_kev_cves || []).length;
          bannerEl.textContent =
            `Evaluated ${s.hosts_evaluated || 0} host(s) across ${s.cves_evaluated || 0} CVE(s) ` +
            `[Built-in rules: ${fm.builtin_count || 0} | Live OSV package CVEs: ${osvCount} | Live CISA KEV CVEs: ${kevCount}]`;
        }

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
    document.getElementById("btnResetLab").addEventListener("click", async () => {
      const btn = document.getElementById("btnResetLab");
      btn.disabled = true;
      btn.textContent = "Resetting...";
      try {
        await fetch("/api/reset", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
        });
        document.getElementById("feedBanner").textContent =
          "Restored Demo Fleet and Docker Lab containers to initial vulnerable state. Re-evaluating...";
        await runEvaluation();
      } catch (err) {
        window.alert("Error resetting lab: " + err);
      } finally {
        btn.disabled = false;
        btn.textContent = "Reset Lab / Demo";
      }
    });
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
      const applyHost = btn.getAttribute("data-apply-host");
      if (applyHost) {
        const applyCve = btn.getAttribute("data-apply-cve");
        const applyIdx = Number(btn.getAttribute("data-apply-idx") || "0");
        const applyCmd = btn.getAttribute("data-apply-cmd") || "";
        const okConfirm = window.confirm(
          `Execute mitigation on host '${applyHost}' for ${applyCve}?\n\n$ ${applyCmd}`
        );
        if (!okConfirm) return;
        btn.disabled = true;
        btn.textContent = "Running...";
        try {
          const res = await fetch("/api/mitigate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              target_mode: activeTargetConfig.target_mode,
              custom_target_type: activeTargetConfig.custom_target_type,
              custom_target_value: activeTargetConfig.custom_target_value,
              host: applyHost,
              cve_id: applyCve,
              mitigation_index: applyIdx,
            }),
          });
          const data = await res.json();
          if (data.ok) {
            document.getElementById("feedBanner").textContent =
              `Mitigation executed on ${applyHost} (${applyCve}). Re-verifying host reachability...`;
            await runEvaluation();
          } else {
            window.alert("Mitigation failed: " + (data.error || "Unknown error"));
            btn.disabled = false;
            btn.textContent = "Run Mitigation";
          }
        } catch (err) {
          window.alert("Error executing mitigation: " + err);
          btn.disabled = false;
          btn.textContent = "Run Mitigation";
        }
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
            cve = (qs.get("cve") or [""])[0].strip().upper()
            if not cve or not _CVE_TOKEN_RE.match(cve):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid or missing cve query parameter"})
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
        if parsed.path not in ("/api/evaluate", "/api/mitigate", "/api/reset"):
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

        if parsed.path == "/api/reset":
            self._send_json(HTTPStatus.OK, reset_lab_and_demo())
            return

        if parsed.path == "/api/mitigate":
            mit_res = apply_host_mitigation(payload)
            status = HTTPStatus.OK if mit_res.get("ok") else HTTPStatus.BAD_REQUEST
            self._send_json(status, mit_res)
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
