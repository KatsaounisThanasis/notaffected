"""Local Web Dashboard (`notaffected ui`) for interactive vulnerability reachability
proofs, live CVE scanning, and OpenVEX v0.2.0 / HTML export.

Binds strictly to 127.0.0.1 by default with zero external framework dependencies.
"""

from __future__ import annotations

import hmac
import json
import re
import secrets
import subprocess
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
from notaffected.local_model import get_ai_status
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
        res = CommandResult(1, "", "not a labelled lab container") if not _is_lab_runner(r_ssh) else r_ssh.run(
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
        res = CommandResult(1, "", "not a labelled lab container") if not _is_lab_runner(r_win) else r_win.run(
            ["sh", "-c", "echo '0' > /etc/win-sim/DisabledComponents && echo 'Running' > /etc/win-sim/Spooler"]
        )
        if res.returncode == 0 and not res.transport_error:
            reset_targets.append("lab-win-dc01")

    return {"ok": True, "reset_targets": reset_targets}


def _is_lab_runner(runner: HostRunner) -> bool:
    """Mitigations may only touch the simulated fleet or a lab container labelled notaffected.lab=true.

    The label is read on the dashboard host with `docker inspect` (argv list, no shell); running it
    through `runner.run` would execute inside the container instead.
    """
    if isinstance(runner, MockRunner):
        return True
    if not isinstance(runner, DockerRunner) or not runner.container or runner.container.startswith("-"):
        return False
    try:
        proc = subprocess.run(
            ["docker", "inspect", "-f", '{{index .Config.Labels "notaffected.lab"}}', runner.container],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0 and proc.stdout.strip() == "true"


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
    if str(payload.get("command") or "") != cmd_text:
        return {
            "ok": False,
            "error": "The confirmed command differs from the one the server would run; re-run the evaluation.",
        }

    try:
        runners = _build_runners_for_mode(
            target_mode,
            custom_target_type=custom_target_type,
            custom_target_value=custom_target_value,
        )
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    runner = next((r for r in runners if r.host_name == host), None)
    if runner is None:
        return {"ok": False, "error": f"Target host {host!r} not found in {target_mode!r}"}
    if not _is_lab_runner(runner):
        return {
            "ok": False,
            "error": (
                "Mitigations run only on lab containers labelled notaffected.lab=true or on the simulated "
                "fleet; apply them on real hosts yourself."
            ),
        }

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
                # Lab sshd_config has no Include: replace the directive so the first value is 0.
                exec_cmd = (
                    "sed -i '/^[[:space:]]*LoginGraceTime/d' /etc/ssh/sshd_config "
                    "&& echo 'LoginGraceTime 0' >> /etc/ssh/sshd_config"
                )
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
        try:
            runners = _build_runners_for_mode(
                target_mode,
                custom_target_type=custom_target_type,
                custom_target_value=custom_target_value,
            )
        except ValueError as exc:
            runners = []
            feed_meta["error"] = str(exc)

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
                parsed_report = json.loads(raw_report) if isinstance(raw_report, str) else raw_report
                findings = parse_scanner_json(parsed_report)
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
        # Same rule as the CLI filter: one spec per (CVE, package), never a guess at "the" package.
        grouped_findings: dict[tuple[str, str | None], Any] = {}
        for f in findings:
            grouped_findings.setdefault((f.cve_id, f.package_name), f)
        specs = []
        for (cid, _pkg), f in list(grouped_findings.items())[:MAX_CUSTOM_CVES]:
            specs.append(
                resolve_check_spec(
                    cid,
                    use_llm=use_llm,
                    package_hint=f.package_name,
                    fixed_version_hint=f.fixed_version,
                    offline=offline,
                    package_class=f.package_class,
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
        briefing = build_remediation_briefing(
            specs, verdicts, use_llm=(use_llm and not offline)
        )
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
        "ai_status": get_ai_status(),
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
  <meta name="notaffected-token" content="__NOTAFFECTED_TOKEN__" />
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='8' fill='%230284c7'/><path d='M9 17l5 5 9-11' stroke='white' stroke-width='3' fill='none' stroke-linecap='round' stroke-linejoin='round'/></svg>" />
  <title>notaffected — Vulnerability Reachability &amp; OpenVEX Dashboard</title>
  <style>
    :root {
      --bg: #070b14;
      --bg-elevated: #0d1424;
      --panel: rgba(15, 23, 42, 0.84);
      --panel-solid: #0f172a;
      --panel-alt: #162033;
      --border: rgba(148, 163, 184, 0.16);
      --border-strong: rgba(148, 163, 184, 0.28);
      --text: #f1f5f9;
      --text-soft: #cbd5e1;
      --muted: #8b9bb4;
      --accent: #38bdf8;
      --accent-strong: #0284c7;
      --accent-glow: rgba(56, 189, 248, 0.16);
      --danger: #fb7185;
      --danger-strong: #f43f5e;
      --danger-bg: rgba(244, 63, 94, 0.13);
      --ok: #34d399;
      --ok-strong: #10b981;
      --ok-bg: rgba(16, 185, 129, 0.13);
      --warn: #fbbf24;
      --warn-bg: rgba(245, 158, 11, 0.13);
      --radius: 14px;
      --radius-sm: 9px;
      --shadow: 0 12px 32px rgba(2, 6, 23, 0.45);
    }
    * { box-sizing: border-box; }
    html, body {
      margin: 0;
      padding: 0;
      min-height: 100%;
    }
    body {
      font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg);
      background-image:
        radial-gradient(ellipse 80% 45% at 50% -12%, rgba(56, 189, 248, 0.13), transparent 70%),
        radial-gradient(ellipse 50% 35% at 95% 10%, rgba(16, 185, 129, 0.06), transparent 65%);
      background-attachment: fixed;
      color: var(--text);
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }

    /* Sticky glass topbar */
    header {
      position: sticky;
      top: 0;
      z-index: 30;
      border-bottom: 1px solid var(--border);
      background: rgba(7, 11, 20, 0.82);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      padding: 0.85rem 1.75rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 0.9rem;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      flex-wrap: wrap;
    }
    .brand-logo {
      width: 34px;
      height: 34px;
      border-radius: 10px;
      background: linear-gradient(135deg, #0ea5e9, #2563eb);
      box-shadow: 0 4px 14px rgba(14, 165, 233, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.25);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }
    .brand-title {
      display: flex;
      flex-direction: column;
      gap: 0.05rem;
      margin-right: 0.4rem;
    }
    .brand h1 {
      margin: 0;
      font-size: 1.18rem;
      font-weight: 700;
      letter-spacing: -0.025em;
      line-height: 1.15;
    }
    .brand-sub {
      font-size: 0.72rem;
      color: var(--muted);
      letter-spacing: 0.01em;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 0.42rem;
      font-size: 0.74rem;
      padding: 0.26rem 0.68rem;
      border-radius: 999px;
      background: rgba(30, 41, 59, 0.75);
      border: 1px solid var(--border);
      color: var(--text-soft);
      font-weight: 600;
      white-space: nowrap;
    }
    .pill.accent { color: var(--accent); border-color: rgba(56, 189, 248, 0.28); background: rgba(56, 189, 248, 0.09); }
    .status-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--muted);
      display: inline-block;
      flex-shrink: 0;
    }
    .status-dot.ok { background: var(--ok); box-shadow: 0 0 0 3px rgba(52, 211, 153, 0.18); }
    .status-dot.accent { background: var(--accent); box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.18); }
    .status-dot.warn { background: var(--warn); box-shadow: 0 0 0 3px rgba(251, 191, 36, 0.18); }

    main {
      width: 100%;
      max-width: 100%;
      margin: 0;
      padding: 1.35rem 1.75rem 3rem;
    }

    /* Controls panel */
    .controls-shell {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow), inset 0 1px 0 rgba(255, 255, 255, 0.04);
      padding: 1.2rem 1.3rem 1.05rem;
      margin-bottom: 1.25rem;
    }
    .controls-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 0.95rem 1.1rem;
      align-items: end;
    }
    .controls-footer {
      margin-top: 1rem;
      padding-top: 0.9rem;
      border-top: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 0.85rem;
    }
    .field label {
      display: block;
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--muted);
      margin-bottom: 0.38rem;
      font-weight: 700;
    }
    select, input[type="text"] {
      width: 100%;
      padding: 0.58rem 0.78rem;
      border-radius: var(--radius-sm);
      border: 1px solid var(--border);
      background: rgba(7, 11, 20, 0.85);
      color: var(--text);
      font-size: 0.88rem;
      transition: border-color 0.15s, box-shadow 0.15s;
      outline: none;
    }
    select:hover, input[type="text"]:hover {
      border-color: var(--border-strong);
    }
    select:focus, input[type="text"]:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px var(--accent-glow);
    }
    .btn-row {
      display: flex;
      align-items: center;
      gap: 0.55rem;
      flex-wrap: wrap;
    }
    button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.42rem;
      cursor: pointer;
      padding: 0.56rem 0.98rem;
      border-radius: var(--radius-sm);
      border: 1px solid var(--border-strong);
      background: rgba(30, 41, 59, 0.78);
      color: var(--text);
      font-weight: 600;
      font-size: 0.84rem;
      transition: transform 0.12s, background 0.15s, border-color 0.15s, box-shadow 0.15s;
      white-space: nowrap;
    }
    button:hover:not(:disabled) {
      background: rgba(51, 65, 85, 0.85);
      border-color: rgba(148, 163, 184, 0.45);
    }
    button:active:not(:disabled) {
      transform: translateY(1px);
    }
    button.primary {
      background: linear-gradient(135deg, #0ea5e9, #0284c7);
      border-color: rgba(56, 189, 248, 0.65);
      color: #fff;
      box-shadow: 0 4px 14px rgba(2, 132, 199, 0.34), inset 0 1px 0 rgba(255, 255, 255, 0.2);
    }
    button.primary:hover:not(:disabled) {
      background: linear-gradient(135deg, #38bdf8, #0284c7);
      box-shadow: 0 6px 18px rgba(14, 165, 233, 0.44);
    }
    button.ghost {
      background: transparent;
      border-color: var(--border);
      color: var(--text-soft);
      padding: 0.46rem 0.78rem;
      font-size: 0.8rem;
    }
    button.ghost:hover:not(:disabled) {
      background: rgba(30, 41, 59, 0.65);
      color: var(--text);
    }
    /* The one action that changes a host: outlined in the warning colour, never the loudest button. */
    button.caution {
      background: transparent;
      border-color: rgba(251, 191, 36, 0.45);
      color: var(--warn);
    }
    button.caution:hover:not(:disabled) {
      background: var(--warn-bg);
      border-color: var(--warn);
    }
    button:disabled {
      opacity: 0.45;
      cursor: not-allowed;
    }
    button svg {
      width: 14px;
      height: 14px;
      flex-shrink: 0;
    }

    /* Toggle switches */
    .toggles-group {
      display: flex;
      align-items: center;
      gap: 1.1rem;
      flex-wrap: wrap;
    }
    .switch-label {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      cursor: pointer;
      font-size: 0.82rem;
      color: var(--text-soft);
      user-select: none;
    }
    .switch-label input[type="checkbox"] {
      appearance: none;
      -webkit-appearance: none;
      width: 34px;
      height: 19px;
      border-radius: 999px;
      background: rgba(51, 65, 85, 0.9);
      border: 1px solid var(--border-strong);
      position: relative;
      cursor: pointer;
      transition: background 0.18s, border-color 0.18s;
      margin: 0;
      flex-shrink: 0;
    }
    .switch-label input[type="checkbox"]::after {
      content: "";
      position: absolute;
      top: 2px;
      left: 2px;
      width: 13px;
      height: 13px;
      border-radius: 50%;
      background: #e2e8f0;
      transition: transform 0.18s;
    }
    .switch-label input[type="checkbox"]:checked {
      background: var(--accent-strong);
      border-color: var(--accent);
    }
    .switch-label input[type="checkbox"]:checked::after {
      transform: translateX(15px);
      background: #fff;
    }

    /* Status strip */
    .feed-banner {
      display: flex;
      align-items: center;
      gap: 0.55rem;
      font-size: 0.82rem;
      color: var(--muted);
      background: rgba(15, 23, 42, 0.55);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 0.52rem 0.9rem;
      margin-bottom: 1.25rem;
    }

    /* KPI cards */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 0.95rem;
      margin-bottom: 1.35rem;
    }
    .kpi-card {
      position: relative;
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.05rem 1.15rem;
      box-shadow: var(--shadow), inset 0 1px 0 rgba(255, 255, 255, 0.04);
      overflow: hidden;
      transition: transform 0.15s, border-color 0.15s;
    }
    .kpi-card.clickable { cursor: pointer; }
    .kpi-card.clickable:hover {
      transform: translateY(-2px);
      border-color: var(--border-strong);
    }
    .kpi-card::before {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 2px;
      background: var(--border-strong);
    }
    .kpi-card.kpi-danger::before { background: linear-gradient(90deg, var(--danger-strong), var(--danger)); }
    .kpi-card.kpi-ok::before { background: linear-gradient(90deg, var(--ok-strong), var(--ok)); }
    .kpi-card.kpi-warn::before { background: linear-gradient(90deg, #d97706, var(--warn)); }
    .kpi-card.kpi-accent::before { background: linear-gradient(90deg, #0284c7, var(--accent)); }
    .kpi-top {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.5rem;
    }
    .kpi-card .label {
      font-size: 0.72rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.06em;
      font-weight: 700;
    }
    .kpi-card .val {
      font-size: 2rem;
      font-weight: 800;
      margin-top: 0.3rem;
      line-height: 1.1;
      letter-spacing: -0.03em;
      font-variant-numeric: tabular-nums;
    }
    /* Hierarchy: affected is the headline when it is non-zero; the raw total is context. */
    .kpi-card.kpi-hot {
      background: linear-gradient(160deg, rgba(244, 63, 94, 0.17), var(--panel) 65%);
      border-color: rgba(244, 63, 94, 0.45);
      box-shadow: var(--shadow), 0 0 0 1px rgba(244, 63, 94, 0.16), 0 8px 28px rgba(244, 63, 94, 0.14);
    }
    .kpi-card.kpi-hot .val { font-size: 2.6rem; }
    .kpi-card.kpi-muted .val { color: var(--text-soft); font-size: 1.6rem; }
    .val.danger { color: var(--danger); }
    .val.ok { color: var(--ok); }
    .val.warn { color: var(--warn); }
    .val.accent { color: var(--accent); }
    .kpi-bar {
      margin-top: 0.55rem;
      height: 5px;
      border-radius: 999px;
      background: rgba(148, 163, 184, 0.14);
      overflow: hidden;
    }
    .kpi-bar-fill {
      height: 100%;
      width: 0%;
      border-radius: 999px;
      background: linear-gradient(90deg, #0ea5e9, #34d399);
      transition: width 0.45s cubic-bezier(0.22, 1, 0.36, 1);
    }

    /* Section cards */
    .section-card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow), inset 0 1px 0 rgba(255, 255, 255, 0.04);
      padding: 1.2rem 1.3rem;
      margin-bottom: 1.35rem;
      overflow-x: auto;
    }
    .section-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.9rem;
      flex-wrap: wrap;
      margin-bottom: 1rem;
    }
    .section-title-wrap {
      display: flex;
      align-items: center;
      gap: 0.6rem;
    }
    .section-header h2 {
      margin: 0;
      font-size: 1.02rem;
      font-weight: 700;
      letter-spacing: -0.01em;
    }
    .count-chip {
      font-size: 0.72rem;
      font-weight: 700;
      padding: 0.16rem 0.52rem;
      border-radius: 999px;
      background: rgba(56, 189, 248, 0.12);
      color: var(--accent);
      border: 1px solid rgba(56, 189, 248, 0.25);
      font-variant-numeric: tabular-nums;
    }
    .filter-bar {
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
      align-items: center;
    }
    .seg-group {
      display: inline-flex;
      background: rgba(7, 11, 20, 0.75);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 2px;
      gap: 2px;
    }
    .seg-btn {
      border: none;
      background: transparent;
      color: var(--muted);
      padding: 0.34rem 0.65rem;
      font-size: 0.76rem;
      font-weight: 600;
      border-radius: 7px;
      box-shadow: none;
    }
    .seg-btn:hover:not(:disabled) {
      background: rgba(30, 41, 59, 0.75);
      color: var(--text);
    }
    .seg-btn.active {
      background: rgba(56, 189, 248, 0.18);
      color: var(--accent);
    }
    .search-wrap {
      position: relative;
      display: inline-flex;
      align-items: center;
    }
    .search-wrap svg {
      position: absolute;
      left: 0.65rem;
      width: 14px;
      height: 14px;
      color: var(--muted);
      pointer-events: none;
    }
    .search-wrap input[type="text"] {
      padding-left: 2rem;
      width: 225px;
      font-size: 0.83rem;
      padding-top: 0.44rem;
      padding-bottom: 0.44rem;
    }
    .filter-bar select {
      width: auto;
      font-size: 0.82rem;
      padding: 0.44rem 0.7rem;
    }

    /* Table: its own scroll box, so the header can stay visible and the page stays short */
    .table-scroll {
      max-height: calc(100vh - 150px);
      overflow: auto;
      border-radius: 9px;
    }
    table {
      width: 100%;
      min-width: 980px;
      table-layout: fixed;
      border-collapse: separate;
      border-spacing: 0;
      font-size: 0.875rem;
    }
    thead th {
      position: sticky;
      top: 0;
      z-index: 2;
      background: var(--panel-solid);
      color: var(--muted);
      font-size: 0.71rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      padding: 0.72rem 0.75rem;
      border-top: 1px solid var(--border);
      border-bottom: 1px solid var(--border);
      text-align: left;
    }
    thead th:first-child { border-top-left-radius: 9px; border-left: 1px solid var(--border); }
    thead th:last-child { border-top-right-radius: 9px; border-right: 1px solid var(--border); }
    tbody td {
      text-align: left;
      padding: 0.82rem 0.75rem;
      border-bottom: 1px solid rgba(148, 163, 184, 0.1);
      vertical-align: top;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    tbody tr {
      transition: background 0.12s;
    }
    tbody tr:hover {
      background: rgba(30, 41, 59, 0.38);
    }
    tbody tr.row-affected td:first-child {
      box-shadow: inset 3px 0 0 var(--danger-strong);
    }
    tbody tr.row-affected {
      background: rgba(244, 63, 94, 0.035);
    }
    tbody tr.row-affected:hover {
      background: rgba(244, 63, 94, 0.075);
    }
    th:nth-child(1), td:nth-child(1) { width: 150px; }
    th:nth-child(2), td:nth-child(2) { width: 96px; }
    th:nth-child(3), td:nth-child(3) { width: 172px; white-space: nowrap; }
    th:nth-child(4), td:nth-child(4) { width: 186px; }
    th:nth-child(5), td:nth-child(5) { width: 18%; }
    th:nth-child(6), td:nth-child(6) { width: auto; }

    code {
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.82rem;
      overflow-wrap: anywhere;
      word-break: break-word;
      white-space: pre-wrap;
    }
    .cve-code {
      color: #e2e8f0;
      font-weight: 600;
      background: rgba(30, 41, 59, 0.65);
      padding: 0.16rem 0.48rem;
      border-radius: 6px;
      border: 1px solid var(--border);
      display: inline-block;
      white-space: nowrap;
    }
    .just-code {
      color: #a7f3d0;
      background: rgba(16, 185, 129, 0.08);
      padding: 0.16rem 0.42rem;
      border-radius: 6px;
      border: 1px solid rgba(16, 185, 129, 0.22);
      display: inline-block;
      font-size: 0.77rem;
    }

    /* Badges */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 0.36rem;
      padding: 0.22rem 0.6rem;
      border-radius: 999px;
      font-size: 0.71rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      white-space: nowrap;
    }
    .badge::before {
      content: "";
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: currentColor;
      flex-shrink: 0;
    }
    .badge.affected { background: var(--danger-bg); color: var(--danger); border: 1px solid rgba(244, 63, 94, 0.38); }
    .badge.not_affected { background: var(--ok-bg); color: var(--ok); border: 1px solid rgba(16, 185, 129, 0.35); }
    .badge.under_investigation { background: var(--warn-bg); color: var(--warn); border: 1px solid rgba(245, 158, 11, 0.38); }
    .badge.os { background: rgba(30, 41, 59, 0.8); color: var(--accent); border: 1px solid rgba(56, 189, 248, 0.25); }
    .badge.os::before { display: none; }

    /* Mitigation command rows */
    .mit-row {
      display: flex;
      align-items: center;
      gap: 0.45rem;
      margin-top: 0.5rem;
      flex-wrap: wrap;
      max-width: 100%;
    }
    .mit-cmd {
      flex: 1 1 260px;
      min-width: 0;
      max-width: 100%;
      display: block;
      background: rgba(7, 11, 20, 0.92);
      border: 1px solid rgba(56, 189, 248, 0.24);
      border-radius: 8px;
      padding: 0.42rem 0.68rem;
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, monospace;
      font-size: 0.79rem;
      color: #bae6fd;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    button.mini {
      padding: 0.3rem 0.62rem;
      font-size: 0.74rem;
      border-radius: 7px;
    }

    /* Probe details drawer */
    details.probe-drawer {
      margin-top: 0.52rem;
    }
    details.probe-drawer summary {
      cursor: pointer;
      font-size: 0.78rem;
      color: var(--accent);
      font-weight: 600;
      user-select: none;
      list-style: none;
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.2rem 0.45rem;
      border-radius: 6px;
      background: rgba(56, 189, 248, 0.08);
      border: 1px solid rgba(56, 189, 248, 0.18);
      transition: background 0.15s;
    }
    details.probe-drawer summary::-webkit-details-marker { display: none; }
    details.probe-drawer summary::before {
      content: "▸";
      font-size: 0.72rem;
      transition: transform 0.15s;
    }
    details.probe-drawer[open] summary::before {
      transform: rotate(90deg);
    }
    details.probe-drawer summary:hover {
      background: rgba(56, 189, 248, 0.15);
    }
    .probe-item {
      margin-top: 0.48rem;
      padding: 0.55rem 0.75rem;
      background: rgba(7, 11, 20, 0.85);
      border: 1px solid var(--border);
      border-left: 3px solid var(--border-strong);
      border-radius: 8px;
      font-size: 0.8rem;
    }
    .probe-item.st-not_met { border-left-color: var(--ok); }
    .probe-item.st-met { border-left-color: var(--danger); }
    .probe-item.st-unknown { border-left-color: var(--warn); }

    /* Briefing box */
    pre.briefing {
      background: rgba(7, 11, 20, 0.88);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.05rem 1.15rem;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
      font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.83rem;
      line-height: 1.6;
      color: var(--text-soft);
      margin: 0;
    }

    /* Hidden select synced with segmented buttons for backward compatibility */
    .sr-select {
      display: none;
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <div class="brand-logo" aria-hidden="true">
        <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="m9 12 2 2 4-4"/>
        </svg>
      </div>
      <div class="brand-title">
        <h1>notaffected</h1>
        <span class="brand-sub">Deterministic Reachability &amp; OpenVEX Engine</span>
      </div>
      <span class="pill accent" id="verPill">v1.0.0</span>
      <span class="pill" id="dockerCountPill">Docker Targets: ...</span>
      <span class="pill" id="aiStatusPill">AI: Checking...</span>
    </div>
    <div class="btn-row">
      <button class="ghost" id="btnExportVex" disabled>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        OpenVEX (.vex.json)
      </button>
      <button class="ghost" id="btnExportJson" disabled>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
        Audit JSON
      </button>
      <button class="ghost" id="btnExportHtml" disabled>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
        HTML Report
      </button>
    </div>
  </header>

  <main>
    <div class="controls-shell">
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
          <input type="file" id="scannerFileInput" accept=".json,application/json" style="color:var(--muted); font-size:0.84rem;" />
        </div>
      </div>

      <div class="controls-footer">
        <div class="btn-row">
          <button class="primary" id="btnRun">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>
            Run Reachability Proof
          </button>
          <button id="btnResetLab" title="Restore Demo Fleet and Docker Lab containers to initial vulnerable state">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>
            Reset Lab / Demo
          </button>
        </div>

        <div class="toggles-group">
          <label class="switch-label">
            <input type="checkbox" id="chkOffline" />
            <span>Offline Only (Skip Live Feeds)</span>
          </label>
          <label class="switch-label">
            <input type="checkbox" id="chkUseLlm" />
            <span>Use AI Advisor</span>
          </label>
        </div>
      </div>
    </div>

    <div class="feed-banner" id="feedBanner">Ready. Click "Run Reachability Proof" to evaluate targets.</div>

    <div class="kpi-grid">
      <div class="kpi-card kpi-danger clickable" id="kpiAffectedCard" data-kpi-filter="affected" title="Filter Affected verdicts">
        <div class="kpi-top">
          <div class="label">Affected (Action Required)</div>
        </div>
        <div class="val danger" id="kpiAffected">0</div>
      </div>
      <div class="kpi-card kpi-ok clickable" data-kpi-filter="not_affected" title="Filter Not Affected verdicts">
        <div class="kpi-top">
          <div class="label">Not Affected (VEX Proven)</div>
        </div>
        <div class="val ok" id="kpiNotAffected">0</div>
      </div>
      <div class="kpi-card kpi-warn clickable" data-kpi-filter="under_investigation" title="Filter Under Investigation verdicts">
        <div class="kpi-top">
          <div class="label">Under Investigation</div>
        </div>
        <div class="val warn" id="kpiUnderInv">0</div>
      </div>
      <div class="kpi-card kpi-accent">
        <div class="kpi-top">
          <div class="label">False-Positive Noise Cut</div>
        </div>
        <div class="val accent" id="kpiNoise">0%</div>
        <div class="kpi-bar"><div class="kpi-bar-fill" id="noiseBar"></div></div>
      </div>
      <div class="kpi-card kpi-muted clickable" data-kpi-filter="all" title="Show all verdicts">
        <div class="kpi-top">
          <div class="label">Total Host-CVE Proofs</div>
        </div>
        <div class="val" id="kpiTotal">0</div>
      </div>
    </div>

    <div class="section-card">
      <div class="section-header">
        <div class="section-title-wrap">
          <h2>Host Reachability Verdicts &amp; Deterministic Proofs</h2>
          <span class="count-chip" id="rowCountChip">0 rows</span>
        </div>
        <div class="filter-bar">
          <div class="seg-group" id="statusSegments" role="group" aria-label="Filter by verdict status">
            <button type="button" class="seg-btn active" data-status="attention" title="Affected and under investigation">Needs Attention</button>
            <button type="button" class="seg-btn" data-status="all">All</button>
            <button type="button" class="seg-btn" data-status="affected">Affected</button>
            <button type="button" class="seg-btn" data-status="not_affected">Not Affected</button>
            <button type="button" class="seg-btn" data-status="under_investigation">Investigating</button>
          </div>
          <select id="filterStatus" class="sr-select" aria-label="Verdict status filter">
            <option value="attention" selected>Needs Attention</option>
            <option value="all">All Verdicts</option>
            <option value="affected">Affected Only</option>
            <option value="not_affected">Not Affected Only</option>
            <option value="under_investigation">Under Investigation</option>
          </select>
          <select id="filterOs" aria-label="OS family filter">
            <option value="all">All OS Families</option>
            <option value="linux">Linux</option>
            <option value="windows">Windows Server</option>
          </select>
          <div class="search-wrap">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input type="text" id="filterSearch" placeholder="Filter host, CVE, proof..." />
          </div>
        </div>
      </div>

      <div class="table-scroll">
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
    </div>

    <div class="section-card">
      <div class="section-header">
        <h2>Operational Risk &amp; Remediation Safety Briefing</h2>
        <button type="button" class="ghost" id="btnCopyBriefing">Copy Briefing</button>
      </div>
      <pre class="briefing" id="briefingBox">Run an evaluation to view host-aware remediation guidance.</pre>
    </div>
  </main>

  <script>
    const PAGE_TOKEN = document.querySelector('meta[name="notaffected-token"]').content;
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

    function setStatusFilter(val) {
      const sel = document.getElementById("filterStatus");
      sel.value = val;
      document.querySelectorAll("#statusSegments .seg-btn").forEach((b) => {
        b.classList.toggle("active", b.getAttribute("data-status") === val);
      });
      renderVerdictRows();
    }

    document.querySelectorAll("#statusSegments .seg-btn").forEach((b) => {
      b.addEventListener("click", () => setStatusFilter(b.getAttribute("data-status")));
    });
    document.querySelectorAll(".kpi-card[data-kpi-filter]").forEach((card) => {
      card.addEventListener("click", () => setStatusFilter(card.getAttribute("data-kpi-filter")));
    });

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
        document.getElementById("verPill").textContent = "v" + (data.version || "1.0.0");
        const count = (data.docker_containers || []).length;
        const dockerPill = document.getElementById("dockerCountPill");
        dockerPill.innerHTML = count > 0
          ? `<span class="status-dot ok"></span>Docker Targets: ${count}`
          : `<span class="status-dot"></span>Docker: 0 (Demo Ready)`;
        if (count === 0 && !data.has_lab_inventory) {
          document.getElementById("targetMode").value = "demo_fleet";
        }
        const customInvOpt = document.querySelector('#targetMode option[value="custom_inventory"]');
        if (customInvOpt && !data.has_custom_inventory) {
          customInvOpt.textContent = "Custom Inventory (inventory.yaml — not found)";
        }
        const ai = data.ai_status || {};
        const aiPill = document.getElementById("aiStatusPill");
        const llmToggle = document.getElementById("chkUseLlm");
        const setupHint = "Set NOTAFFECTED_LLM_MODEL plus NOTAFFECTED_LLM_PROVIDER, NOTAFFECTED_LLM_URL or one provider API key to enable the AI advisor.";
        if (llmToggle) {
          llmToggle.disabled = !ai.configured;
          llmToggle.closest("label").title = ai.configured ? "" : (ai.detail || "") + " " + setupHint;
        }
        if (aiPill) {
          if (!ai.configured) {
            aiPill.innerHTML = `<span class="status-dot"></span>AI: not configured`;
            aiPill.title = [ai.provider ? ai.provider + ": " + (ai.detail || "") : (ai.detail || ""), setupHint].join(" ").trim();
            aiPill.style.color = "var(--muted)";
          } else {
            const scope = ai.local_only ? "local" : "external";
            const unreachable = ai.online === false;
            const checked = ai.online === true;  // null: configured, but nothing was sent to check it
            aiPill.innerHTML = `<span class="status-dot ${unreachable ? "warn" : checked ? "ok" : ""}"></span>AI: ${esc(ai.provider)} · ${esc(ai.model)} (${scope}${unreachable ? ", unreachable" : ""})`;
            aiPill.title = unreachable ? (ai.detail || "") : checked ? "" : "Configured; not contacted until the AI advisor runs.";
            aiPill.style.color = unreachable ? "var(--warn)" : checked ? "var(--ok)" : "";
          }
        }
      } catch (err) {
        console.error(err);
      }
    }

    function renderVerdictRows() {
      const tbody = document.getElementById("verdictsBody");
      const chip = document.getElementById("rowCountChip");
      if (!latestResult || !latestResult.verdicts) {
        if (chip) chip.textContent = "0 rows";
        tbody.innerHTML = '<tr><td colspan="6" style="color:var(--muted);">No verdicts available.</td></tr>';
        return;
      }
      const specById = {};
      for (const sp of (latestResult.specs || [])) {
        if (sp && sp.cve_id) specById[sp.cve_id] = sp;
      }
      const stFilter = document.getElementById("filterStatus").value;
      const osFilter = document.getElementById("filterOs").value;
      const q = (document.getElementById("filterSearch").value || "").toLowerCase();

      const statusRank = { affected: 0, under_investigation: 1, not_affected: 2 };
      const filtered = latestResult.verdicts
        .filter((v) => {
          if (stFilter === "attention") {
            if (v.status === "not_affected") return false;
          } else if (stFilter !== "all" && v.status !== stFilter) {
            return false;
          }
          if (osFilter !== "all" && v.os_family !== osFilter) return false;
          if (q) {
            const blob = `${v.host} ${v.cve_id} ${v.reason} ${v.justification || ""}`.toLowerCase();
            if (!blob.includes(q)) return false;
          }
          return true;
        })
        .sort((a, b) => (statusRank[a.status] ?? 9) - (statusRank[b.status] ?? 9));

      if (chip) chip.textContent = `${filtered.length} / ${latestResult.verdicts.length} rows`;

      if (filtered.length === 0) {
        const emptyMsg = stFilter === "attention" && !q && osFilter === "all"
          ? "Nothing needs attention: every host-CVE pair is proven not affected."
          : "No matching verdicts for current filter.";
        tbody.innerHTML = `<tr><td colspan="6" style="color:var(--muted);">${esc(emptyMsg)}</td></tr>`;
        return;
      }
      const statusLabel = { affected: "Affected", not_affected: "Not affected", under_investigation: "Under investigation" };

      tbody.innerHTML = filtered.map((v) => {
        const spec = specById[v.cve_id] || null;
        const justOrPatch = v.status === "not_affected"
          ? `<code class="just-code">${esc(v.justification || "not_affected")}</code>`
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
                ? `<button type="button" class="mini caution" data-apply-host="${esc(v.host)}" data-apply-cve="${esc(v.cve_id)}" data-apply-idx="${idx}" data-apply-cmd="${esc(m)}" title="Changes the host (lab containers only)">Run Mitigation</button>`
                : "";
              return `
                <div class="mit-row">
                  <code class="mit-cmd">$ ${esc(m)}</code>
                  <button type="button" class="mini primary" data-copy-cmd="${esc(m)}">Copy</button>
                  ${runBtn}
                </div>
              `;
            }).join("")
          : "";
        const mitigationsBlock = mitigationsHtml
          ? `
            <details class="probe-drawer">
              <summary>Temporary Mitigations (${v.mitigation.length})</summary>
              ${mitigationsHtml}
            </details>
          `
          : "";

        const probes = v.probe_results || [];
        let probeListHtml = "";
        if (probes.length > 0) {
          probeListHtml = probes.map((pr, idx) => {
            const pSt = String(pr.status || "UNKNOWN");
            const pLow = pSt.toLowerCase();
            const pColor = pSt === "NOT_MET" ? "var(--ok)" : (pSt === "MET" ? "var(--danger)" : "var(--warn)");
            const pName = pr.precondition ? pr.precondition.probe : "probe";
            const pDesc = pr.precondition ? pr.precondition.description : "";
            return `
              <div class="probe-item st-${esc(pLow)}">
                <div>
                  <strong style="color:${pColor};">#${idx + 1} [${esc(pSt)}]</strong>
                  <code>${esc(pName)}</code> &mdash; <span style="color:var(--muted);">${esc(pDesc)}</span>
                </div>
                <div style="margin-top:0.25rem; color:var(--text-soft);">Command: <code>${esc(pr.command || "n/a")}</code></div>
                <div style="margin-top:0.18rem; color:var(--muted);">Output: ${esc(pr.evidence || "")}</div>
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
          <details class="probe-drawer">
            <summary>
              Inspect Probes &amp; Commands (${probes.length} executed${specMeta ? " — " + specMeta : ""})
            </summary>
            <div style="margin-top:0.4rem;">
              ${spec ? `<div style="font-size:0.81rem; color:var(--text-soft); margin-bottom:0.35rem;"><strong>Advisory:</strong> ${esc(spec.summary)}</div>` : ""}
              ${probeListHtml}
            </div>
          </details>
        `;

        const rowClass = v.status === "affected" ? ' class="row-affected"' : "";
        return `
          <tr${rowClass}>
            <td><strong>${esc(v.host)}</strong></td>
            <td><span class="badge os">${esc(v.os_family)}</span></td>
            <td><code class="cve-code">${esc(v.cve_id)}</code></td>
            <td><span class="badge ${esc(v.status)}">${esc(statusLabel[v.status] || v.status)}</span></td>
            <td>${justOrPatch}</td>
            <td>
              <div>${esc(v.reason)}</div>
              ${mitigationsBlock}
              ${inspectDrawer}
            </td>
          </tr>
        `;
      }).join("");
    }

    async function runEvaluation() {
      const btn = document.getElementById("btnRun");
      const origHtml = btn.innerHTML;
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
          headers: { "Content-Type": "application/json", "X-Notaffected-Token": PAGE_TOKEN },
          body: JSON.stringify(body),
        });
        latestResult = await res.json();
        const s = latestResult.summary || {};
        document.getElementById("kpiTotal").textContent = s.total || 0;
        document.getElementById("kpiAffected").textContent = s.affected || 0;
        document.getElementById("kpiAffectedCard").classList.toggle("kpi-hot", (s.affected || 0) > 0);
        document.getElementById("kpiNotAffected").textContent = s.not_affected || 0;
        document.getElementById("kpiUnderInv").textContent = s.under_investigation || 0;
        const noisePct = s.noise_reduction_pct || 0;
        document.getElementById("kpiNoise").textContent = noisePct + "%";
        const noiseBar = document.getElementById("noiseBar");
        if (noiseBar) noiseBar.style.width = Math.max(0, Math.min(100, Number(noisePct))) + "%";
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
        btn.innerHTML = origHtml;
      }
    }

    document.getElementById("btnRun").addEventListener("click", runEvaluation);
    document.getElementById("btnResetLab").addEventListener("click", async () => {
      const btn = document.getElementById("btnResetLab");
      const origHtml = btn.innerHTML;
      btn.disabled = true;
      btn.textContent = "Resetting...";
      try {
        await fetch("/api/reset", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Notaffected-Token": PAGE_TOKEN },
          body: JSON.stringify({}),
        });
        document.getElementById("feedBanner").textContent =
          "Restored Demo Fleet and Docker Lab containers to initial vulnerable state. Re-evaluating...";
        await runEvaluation();
      } catch (err) {
        window.alert("Error resetting lab: " + err);
      } finally {
        btn.disabled = false;
        btn.innerHTML = origHtml;
      }
    });
    document.getElementById("filterStatus").addEventListener("change", (e) => setStatusFilter(e.target.value));
    document.getElementById("filterOs").addEventListener("change", renderVerdictRows);
    document.getElementById("filterSearch").addEventListener("input", renderVerdictRows);

    document.getElementById("btnCopyBriefing").addEventListener("click", async (e) => {
      const text = document.getElementById("briefingBox").textContent || "";
      try {
        await navigator.clipboard.writeText(text);
        const btn = e.currentTarget;
        const orig = btn.textContent;
        btn.textContent = "Copied!";
        setTimeout(() => { btn.textContent = orig; }, 1200);
      } catch (err) {
        console.error(err);
      }
    });

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
            headers: { "Content-Type": "application/json", "X-Notaffected-Token": PAGE_TOKEN },
            body: JSON.stringify({
              target_mode: activeTargetConfig.target_mode,
              custom_target_type: activeTargetConfig.custom_target_type,
              custom_target_value: activeTargetConfig.custom_target_value,
              host: applyHost,
              cve_id: applyCve,
              mitigation_index: applyIdx,
              command: applyCmd,
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

    # Per-process secret embedded in the served page and required on every POST, so a local
    # process or a non-browser client cannot drive /api/* without first loading the page.
    request_token: str = secrets.token_urlsafe(32)

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
            self._send_html(HTTPStatus.OK, DASHBOARD_HTML.replace("__NOTAFFECTED_TOKEN__", self.request_token))
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
        sent_token = self.headers.get("X-Notaffected-Token") or ""
        if not hmac.compare_digest(sent_token.encode("utf-8"), self.request_token.encode("utf-8")):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "Missing or invalid request token"})
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


def check_bind_address(host: str, allow_remote: bool = False) -> None:
    """Refuse a non-loopback bind unless explicitly allowed (raises SystemExit with the reason)."""
    if host.strip().lower() not in ("127.0.0.1", "::1", "localhost") and not allow_remote:
        raise SystemExit(
            f"Refusing to bind the dashboard to {host!r}: it can run probes over SSH with your keys. "
            "Pass --allow-remote to do it anyway."
        )


def run_web_server(host: str = "127.0.0.1", port: int = 8484, allow_remote: bool = False) -> None:
    """Start the local notaffected Web UI server (loopback only unless `allow_remote`)."""
    check_bind_address(host, allow_remote)
    DashboardRequestHandler.request_token = secrets.token_urlsafe(32)
    server = ThreadingHTTPServer((host, port), DashboardRequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
