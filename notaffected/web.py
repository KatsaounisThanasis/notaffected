"""Local Web Dashboard (`notaffected ui`) for interactive vulnerability reachability
proofs, live CVE scanning, and OpenVEX v0.2.0 / HTML export.

Binds strictly to 127.0.0.1 by default with zero external framework dependencies.
"""

from __future__ import annotations

import hmac
import json
import os
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
        explicit_report = raw_report is not None and raw_report != ""
        try:
            if explicit_report:
                if isinstance(raw_report, str):
                    parsed_report = json.loads(raw_report)
                else:
                    parsed_report = raw_report
                if not isinstance(parsed_report, dict):
                    raise ValueError("Expected JSON object for scanner_report")
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
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="notaffected-token" content="__NOTAFFECTED_TOKEN__" />
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='8' fill='%2318181b'/><path d='M9 17l5 5 9-11' stroke='%23f08a59' stroke-width='3.2' fill='none' stroke-linecap='round' stroke-linejoin='round'/></svg>" />
  <title>notaffected — Vulnerability Reachability &amp; OpenVEX Dashboard</title>
  <style>
    :root, [data-theme="dark"] {
      --bg: #09090b;
      --surface: #111114;
      --surface-2: #18181b;
      --surface-hover: #1e1e23;
      --surface-selected: #23232a;
      --border: rgba(255, 255, 255, 0.08);
      --border-strong: rgba(255, 255, 255, 0.15);
      --text: #ededed;
      --text-soft: #d4d4d8;
      --muted: #a1a1aa;
      --subtle: #94949e;
      --accent: #f08a59;
      --accent-hover: #f59c71;
      --accent-soft: rgba(240, 138, 89, 0.13);
      --accent-border: rgba(240, 138, 89, 0.30);
      --link: #60a5fa;
      --link-soft: rgba(96, 165, 250, 0.12);
      --danger: #fb7185;
      --danger-strong: #f43f5e;
      --danger-soft: rgba(244, 63, 94, 0.12);
      --danger-border: rgba(244, 63, 94, 0.30);
      --ok: #34d399;
      --ok-soft: rgba(16, 185, 129, 0.12);
      --ok-border: rgba(16, 185, 129, 0.30);
      --warn: #fbbf24;
      --warn-soft: rgba(245, 158, 11, 0.12);
      --warn-border: rgba(245, 158, 11, 0.30);
      --code-bg: #18181b;
      --term-bg: #09090b;
      --term-text: #e4e4e7;
      --topbar-bg: rgba(9, 9, 11, 0.84);
      --drawer-backdrop: rgba(0, 0, 0, 0.45);
      --radius: 10px;
      --radius-sm: 7px;
      --ambient: radial-gradient(ellipse 65% 32% at 50% -10%, rgba(240, 138, 89, 0.09), transparent 70%);
    }

    [data-theme="light"] {
      --bg: #f6f7f9;
      --surface: #ffffff;
      --surface-2: #f1f3f6;
      --surface-hover: #f8fafc;
      --surface-selected: #eef2f6;
      --border: #e4e7ec;
      --border-strong: #d0d5dd;
      --text: #18181b;
      --text-soft: #3f3f46;
      --muted: #525866;
      --subtle: #5c6472;
      --accent: #eb6c36;
      --accent-hover: #d85a26;
      --accent-soft: rgba(235, 108, 54, 0.10);
      --accent-border: rgba(235, 108, 54, 0.28);
      --link: #2563eb;
      --link-soft: rgba(37, 99, 235, 0.08);
      --danger: #dc2626;
      --danger-strong: #dc2626;
      --danger-soft: #fef2f2;
      --danger-border: #fecaca;
      --ok: #059669;
      --ok-soft: #ecfdf5;
      --ok-border: #a7f3d0;
      --warn: #b45309;
      --warn-soft: #fffbeb;
      --warn-border: #fde68a;
      --code-bg: #f4f4f5;
      --term-bg: #18181b;
      --term-text: #f4f4f5;
      --topbar-bg: rgba(255, 255, 255, 0.88);
      --drawer-backdrop: rgba(15, 23, 42, 0.22);
      --ambient: none;
    }

    * { box-sizing: border-box; }
    html, body { margin: 0; padding: 0; min-height: 100%; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Inter", "Geist", "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg);
      background-image: var(--ambient);
      background-attachment: fixed;
      color: var(--text);
      line-height: 1.48;
      -webkit-font-smoothing: antialiased;
    }

    /* Sticky glass header */
    header {
      position: sticky;
      top: 0;
      z-index: 30;
      border-bottom: 1px solid var(--border);
      background: var(--topbar-bg);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      padding: 0.65rem 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 0.75rem;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 0.6rem;
      flex-wrap: wrap;
    }
    .brand-logo {
      width: 28px;
      height: 28px;
      border-radius: 7px;
      background: var(--surface-2);
      border: 1px solid var(--border-strong);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }
    .brand-title {
      display: flex;
      align-items: baseline;
      gap: 0.45rem;
      margin-right: 0.25rem;
    }
    .brand h1 {
      margin: 0;
      font-size: 1.02rem;
      font-weight: 700;
      letter-spacing: -0.025em;
    }
    .brand-sub {
      font-size: 0.74rem;
      color: var(--subtle);
      font-weight: 500;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 0.36rem;
      font-size: 0.71rem;
      padding: 0.18rem 0.56rem;
      border-radius: 999px;
      background: var(--surface-2);
      border: 1px solid var(--border);
      color: var(--muted);
      font-weight: 600;
      white-space: nowrap;
    }
    .pill.accent {
      color: var(--accent);
      background: var(--accent-soft);
      border-color: var(--accent-border);
    }
    .status-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--subtle);
      display: inline-block;
      flex-shrink: 0;
    }
    .status-dot.ok { background: var(--ok); }
    .status-dot.warn { background: var(--warn); }

    main {
      width: 100%;
      max-width: 100%;
      margin: 0;
      padding: 1rem 1.5rem 2.25rem;
    }

    /* Compact single-row command bar */
    .toolbar-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 0.65rem 0.85rem;
      margin-bottom: 0.75rem;
    }
    .toolbar-row {
      display: flex;
      align-items: center;
      gap: 0.55rem;
      flex-wrap: wrap;
    }
    .toolbar-field {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      flex: 1 1 220px;
      min-width: 200px;
    }
    .toolbar-field label {
      font-size: 0.68rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      color: var(--subtle);
      white-space: nowrap;
    }
    .toolbar-extras {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 0.7rem;
    }
    .toolbar-extras:has(> div[style*="block"]) {
      margin-top: 0.65rem;
      padding-top: 0.65rem;
      border-top: 1px solid var(--border);
    }
    .field label {
      display: block;
      font-size: 0.68rem;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      color: var(--subtle);
      margin-bottom: 0.28rem;
      font-weight: 700;
    }
    select, input[type="text"] {
      width: 100%;
      padding: 0.42rem 0.65rem;
      border-radius: var(--radius-sm);
      border: 1px solid var(--border);
      background: var(--surface-2);
      color: var(--text);
      font-size: 0.82rem;
      transition: border-color 0.12s, box-shadow 0.12s;
      outline: none;
    }
    select:hover, input[type="text"]:hover { border-color: var(--border-strong); }
    select:focus, input[type="text"]:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 2px var(--accent-soft);
    }
    .btn-row {
      display: flex;
      align-items: center;
      gap: 0.42rem;
      flex-wrap: wrap;
    }
    button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.36rem;
      cursor: pointer;
      padding: 0.42rem 0.78rem;
      border-radius: var(--radius-sm);
      border: 1px solid var(--border-strong);
      background: var(--surface-2);
      color: var(--text);
      font-weight: 600;
      font-size: 0.79rem;
      transition: background 0.1s, border-color 0.1s, color 0.1s;
      white-space: nowrap;
    }
    button:hover:not(:disabled) {
      background: var(--surface-hover);
      border-color: var(--subtle);
    }
    button.primary {
      background: var(--accent);
      border-color: var(--accent);
      color: #09090b;
    }
    button.primary:hover:not(:disabled) {
      background: var(--accent-hover);
      border-color: var(--accent-hover);
    }
    [data-theme="light"] button.primary { color: #ffffff; }
    button.ghost {
      background: transparent;
      border-color: var(--border);
      color: var(--muted);
      padding: 0.34rem 0.62rem;
      font-size: 0.75rem;
    }
    button.ghost:hover:not(:disabled) {
      background: var(--surface-2);
      color: var(--text);
      border-color: var(--border-strong);
    }
    button.caution {
      background: var(--warn-soft);
      border-color: var(--warn-border);
      color: var(--warn);
    }
    button.caution:hover:not(:disabled) { border-color: var(--warn); }
    button.icon-btn { padding: 0.34rem 0.48rem; }
    button:disabled { opacity: 0.4; cursor: not-allowed; }
    button svg { width: 13px; height: 13px; flex-shrink: 0; }

    /* Toggle switches */
    .toggles-group {
      display: flex;
      align-items: center;
      gap: 0.8rem;
      flex-wrap: wrap;
      margin-left: auto;
    }
    .switch-label {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      cursor: pointer;
      font-size: 0.76rem;
      color: var(--muted);
      font-weight: 500;
      user-select: none;
    }
    .switch-label input[type="checkbox"] {
      appearance: none;
      -webkit-appearance: none;
      width: 28px;
      height: 16px;
      border-radius: 999px;
      background: var(--surface-hover);
      border: 1px solid var(--border-strong);
      position: relative;
      cursor: pointer;
      transition: background 0.14s, border-color 0.14s;
      margin: 0;
      flex-shrink: 0;
    }
    .switch-label input[type="checkbox"]::after {
      content: "";
      position: absolute;
      top: 2px;
      left: 2px;
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: var(--muted);
      transition: transform 0.14s, background 0.14s;
    }
    .switch-label input[type="checkbox"]:checked {
      background: var(--accent-soft);
      border-color: var(--accent);
    }
    .switch-label input[type="checkbox"]:checked::after {
      transform: translateX(12px);
      background: var(--accent);
    }
    .switch-label input[type="checkbox"]:disabled { opacity: 0.4; cursor: not-allowed; }
    .switch-label:has(input[type="checkbox"]:disabled) { opacity: 0.52; cursor: not-allowed; }

    .feed-banner {
      font-size: 0.74rem;
      color: var(--subtle);
      margin: 0 0 0.75rem 0.1rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }

    /* Unified Telemetry Strip (KPIs + Verdict Split) */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 0.65rem;
      margin-bottom: 0.65rem;
    }
    @media (max-width: 1080px) {
      .kpi-grid { grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); }
    }
    .kpi-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 0.78rem 0.95rem;
      transition: border-color 0.12s, background 0.12s;
    }
    .kpi-card.clickable { cursor: pointer; }
    .kpi-card.clickable:hover {
      border-color: var(--border-strong);
      background: var(--surface-2);
    }
    .kpi-card.kpi-hot {
      border-color: var(--danger-border);
      background: linear-gradient(180deg, var(--danger-soft), var(--surface) 75%);
    }
    .kpi-card .label {
      font-size: 0.67rem;
      color: var(--subtle);
      text-transform: uppercase;
      letter-spacing: 0.07em;
      font-weight: 700;
    }
    .kpi-card .val {
      font-size: 1.75rem;
      font-weight: 700;
      margin-top: 0.18rem;
      line-height: 1.1;
      letter-spacing: -0.03em;
      font-variant-numeric: tabular-nums;
    }
    .kpi-card.kpi-hot .val { font-size: 1.95rem; }
    .kpi-card.kpi-muted .val { color: var(--muted); font-size: 1.55rem; }
    .val.danger { color: var(--danger); }
    .val.ok { color: var(--ok); }
    .val.warn { color: var(--warn); }
    .val.accent { color: var(--accent); }
    .kpi-bar {
      margin-top: 0.4rem;
      height: 4px;
      border-radius: 999px;
      background: var(--surface-2);
      overflow: hidden;
    }
    .kpi-bar-fill {
      height: 100%;
      width: 0%;
      border-radius: 999px;
      background: var(--ok);
      transition: width 0.35s ease;
    }

    /* Visual Verdict Split bar */
    .dist-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 0.45rem 0.85rem;
      margin-bottom: 0.85rem;
      display: flex;
      align-items: center;
      gap: 0.8rem;
      flex-wrap: wrap;
    }
    .dist-title {
      font-size: 0.67rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      color: var(--subtle);
      white-space: nowrap;
    }
    .dist-track {
      flex: 1 1 260px;
      height: 6px;
      border-radius: 999px;
      background: var(--surface-2);
      overflow: hidden;
      display: flex;
      gap: 2px;
    }
    .dist-seg { height: 100%; border-radius: 999px; transition: width 0.35s ease; }
    .dist-seg.aff { background: var(--danger-strong); }
    .dist-seg.inv { background: var(--warn); }
    .dist-seg.ok { background: var(--ok); }
    .dist-legend {
      display: flex;
      gap: 0.85rem;
      font-size: 0.72rem;
      color: var(--muted);
      font-variant-numeric: tabular-nums;
      white-space: nowrap;
    }
    .dist-legend span { display: inline-flex; align-items: center; gap: 0.3rem; }
    .dist-dot { width: 6px; height: 6px; border-radius: 50%; display: inline-block; }

    /* Workspace card + Tabs */
    .workspace-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      overflow: hidden;
    }
    .workspace-tabs {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.75rem;
      flex-wrap: wrap;
      padding: 0.62rem 0.95rem;
      border-bottom: 1px solid var(--border);
    }
    .tab-strip {
      display: inline-flex;
      align-items: center;
      gap: 2px;
      background: var(--surface-2);
      padding: 2px;
      border-radius: 8px;
      border: 1px solid var(--border);
    }
    .tab-btn {
      border: none;
      background: transparent;
      color: var(--muted);
      padding: 0.3rem 0.7rem;
      font-size: 0.77rem;
      font-weight: 600;
      border-radius: 6px;
    }
    .tab-btn:hover:not(:disabled) { color: var(--text); background: transparent; }
    .tab-btn.active {
      background: var(--surface-hover);
      color: var(--text);
    }
    .count-chip {
      font-size: 0.7rem;
      font-weight: 600;
      padding: 0.14rem 0.48rem;
      border-radius: 999px;
      background: var(--surface-2);
      color: var(--muted);
      border: 1px solid var(--border);
      font-variant-numeric: tabular-nums;
    }
    .filter-bar {
      display: flex;
      gap: 0.42rem;
      flex-wrap: wrap;
      align-items: center;
    }
    .seg-group {
      display: inline-flex;
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 2px;
      gap: 2px;
    }
    .seg-btn {
      border: none;
      background: transparent;
      color: var(--muted);
      padding: 0.26rem 0.56rem;
      font-size: 0.73rem;
      font-weight: 600;
      border-radius: 5px;
    }
    .seg-btn:hover:not(:disabled) { color: var(--text); background: transparent; }
    .seg-btn.active {
      background: var(--surface-hover);
      color: var(--accent);
    }
    .search-wrap {
      position: relative;
      display: inline-flex;
      align-items: center;
    }
    .search-wrap svg {
      position: absolute;
      left: 0.58rem;
      width: 13px;
      height: 13px;
      color: var(--subtle);
      pointer-events: none;
    }
    .search-wrap input[type="text"] {
      padding-left: 1.75rem;
      padding-right: 1.8rem;
      width: 220px;
      font-size: 0.78rem;
      padding-top: 0.34rem;
      padding-bottom: 0.34rem;
    }
    .kbd-hint {
      position: absolute;
      right: 0.45rem;
      font-family: ui-monospace, SFMono-Regular, monospace;
      font-size: 0.65rem;
      color: var(--subtle);
      border: 1px solid var(--border-strong);
      border-radius: 4px;
      padding: 0.02rem 0.28rem;
      pointer-events: none;
    }
    .filter-bar select {
      width: auto;
      font-size: 0.77rem;
      padding: 0.34rem 0.6rem;
    }

    /* Scannable High-Density Table (F-pattern left-to-right) */
    .table-scroll {
      max-height: calc(100vh - 235px);
      overflow: auto;
    }
    table {
      width: 100%;
      min-width: 960px;
      table-layout: fixed;
      border-collapse: separate;
      border-spacing: 0;
      font-size: 0.83rem;
    }
    thead th {
      position: sticky;
      top: 0;
      z-index: 2;
      background: var(--surface);
      color: var(--subtle);
      font-size: 0.67rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      padding: 0.55rem 0.8rem;
      border-bottom: 1px solid var(--border);
      text-align: left;
    }
    tbody tr {
      cursor: pointer;
      transition: background 0.08s;
    }
    tbody td {
      text-align: left;
      padding: 0.62rem 0.8rem;
      border-bottom: 1px solid var(--border);
      vertical-align: middle;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    tbody tr:hover { background: var(--surface-hover); }
    tbody tr.row-selected { background: var(--surface-selected); }
    tbody tr.row-affected td:first-child { box-shadow: inset 3px 0 0 var(--danger-strong); }
    tbody tr.row-investigating td:first-child { box-shadow: inset 3px 0 0 var(--warn); }
    tbody tr.row-safe td:first-child { box-shadow: inset 3px 0 0 var(--ok); }

    th:nth-child(1), td:nth-child(1) { width: 196px; }
    th:nth-child(2), td:nth-child(2) { width: 158px; white-space: nowrap; }
    th:nth-child(3), td:nth-child(3) { width: 148px; }
    th:nth-child(4), td:nth-child(4) { width: 88px; }
    th:nth-child(5), td:nth-child(5) { width: 19%; }
    th:nth-child(6), td:nth-child(6) { width: auto; }

    .proof-preview {
      display: -webkit-box;
      -webkit-line-clamp: 2;
      -webkit-box-orient: vertical;
      overflow: hidden;
      color: var(--muted);
      font-size: 0.8rem;
      line-height: 1.4;
    }
    .row-meta-chips {
      display: flex;
      align-items: center;
      gap: 0.45rem;
      margin-top: 0.25rem;
      font-size: 0.7rem;
      color: var(--subtle);
    }
    .meta-tag {
      display: inline-flex;
      align-items: center;
      gap: 0.22rem;
      padding: 0.06rem 0.38rem;
      border-radius: 4px;
      background: var(--surface-2);
      border: 1px solid var(--border);
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, monospace;
      font-size: 0.68rem;
    }
    .meta-tag.mit {
      color: var(--accent);
      background: var(--accent-soft);
      border-color: var(--accent-border);
    }

    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.78rem;
      overflow-wrap: anywhere;
      word-break: break-word;
      white-space: pre-wrap;
    }
    .cve-code {
      color: var(--text);
      font-weight: 600;
      background: var(--code-bg);
      padding: 0.14rem 0.44rem;
      border-radius: 5px;
      border: 1px solid var(--border);
      display: inline-block;
      white-space: nowrap;
    }
    .just-code {
      color: var(--ok);
      background: var(--ok-soft);
      padding: 0.12rem 0.4rem;
      border-radius: 5px;
      border: 1px solid var(--ok-border);
      display: inline-block;
      font-size: 0.74rem;
    }

    /* Badges */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 0.34rem;
      padding: 0.18rem 0.54rem;
      border-radius: 999px;
      font-size: 0.68rem;
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
    .badge.affected { background: var(--danger-soft); color: var(--danger); border: 1px solid var(--danger-border); }
    .badge.not_affected { background: var(--ok-soft); color: var(--ok); border: 1px solid var(--ok-border); }
    .badge.under_investigation { background: var(--warn-soft); color: var(--warn); border: 1px solid var(--warn-border); }
    .badge.os { background: var(--surface-2); color: var(--muted); border: 1px solid var(--border); }
    .badge.os::before { display: none; }

    /* Master-Detail Slide-Over Drawer */
    .drawer-backdrop {
      position: fixed;
      inset: 0;
      background: var(--drawer-backdrop);
      z-index: 50;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.16s ease;
    }
    .drawer-backdrop.open { opacity: 1; pointer-events: auto; }
    .detail-drawer {
      position: fixed;
      top: 0;
      right: 0;
      bottom: 0;
      width: min(620px, 94vw);
      background: var(--surface);
      border-left: 1px solid var(--border-strong);
      z-index: 60;
      display: flex;
      flex-direction: column;
      transform: translateX(100%);
      transition: transform 0.2s cubic-bezier(0.22, 1, 0.36, 1);
    }
    .detail-drawer.open { transform: translateX(0); }
    .drawer-header {
      padding: 1rem 1.25rem;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 0.75rem;
    }
    .drawer-title-row {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      flex-wrap: wrap;
    }
    .drawer-sub {
      margin-top: 0.35rem;
      font-size: 0.8rem;
      color: var(--muted);
    }
    .drawer-body {
      flex: 1;
      overflow-y: auto;
      padding: 1.1rem 1.25rem 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 1.1rem;
    }
    .drawer-section h3 {
      margin: 0 0 0.48rem;
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--subtle);
      font-weight: 700;
    }
    .drawer-box {
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 0.75rem 0.85rem;
      font-size: 0.83rem;
      color: var(--text-soft);
    }
    .drawer-footer {
      padding: 0.65rem 1.25rem;
      border-top: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 0.72rem;
      color: var(--subtle);
      background: var(--surface);
    }
    .drawer-footer kbd {
      font-family: ui-monospace, SFMono-Regular, monospace;
      font-size: 0.68rem;
      padding: 0.08rem 0.32rem;
      border-radius: 4px;
      border: 1px solid var(--border-strong);
      background: var(--surface-2);
      color: var(--muted);
    }

    /* Mitigation command rows inside drawer */
    .mit-row {
      display: flex;
      align-items: center;
      gap: 0.42rem;
      margin-top: 0.45rem;
      flex-wrap: wrap;
    }
    .mit-cmd {
      flex: 1 1 240px;
      min-width: 0;
      display: block;
      background: var(--term-bg);
      border: 1px solid var(--border-strong);
      border-radius: 7px;
      padding: 0.45rem 0.65rem;
      font-size: 0.78rem;
      color: var(--term-text);
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
    }
    button.mini { padding: 0.28rem 0.56rem; font-size: 0.72rem; border-radius: 6px; }

    /* Probe timeline cards inside drawer */
    .probe-item {
      margin-top: 0.45rem;
      padding: 0.6rem 0.78rem;
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-left: 3px solid var(--border-strong);
      border-radius: 7px;
      font-size: 0.79rem;
    }
    .probe-item.st-not_met { border-left-color: var(--ok); }
    .probe-item.st-met { border-left-color: var(--danger-strong); }
    .probe-item.st-unknown { border-left-color: var(--warn); }

    /* Briefing pane */
    .briefing-pane { padding: 1.05rem 1.2rem; }
    .briefing-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.75rem;
      gap: 0.75rem;
    }
    .briefing-header h2 { margin: 0; font-size: 0.94rem; font-weight: 700; }
    pre.briefing {
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: 9px;
      padding: 1rem 1.1rem;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.81rem;
      line-height: 1.62;
      color: var(--text-soft);
      margin: 0;
    }
    .pane-hidden { display: none; }
    .sr-select { display: none; }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <div class="brand-logo" aria-hidden="true">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f08a59" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="m9 12 2 2 4-4"/>
        </svg>
      </div>
      <div class="brand-title">
        <h1>notaffected</h1>
        <span class="brand-sub">Reachability &amp; OpenVEX</span>
      </div>
      <span class="pill accent" id="verPill">v1.0.0</span>
      <span class="pill" id="dockerCountPill">Docker Targets: ...</span>
      <span class="pill" id="aiStatusPill">AI: Checking...</span>
    </div>
    <div class="btn-row">
      <button class="ghost" id="btnExportVex" disabled>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        OpenVEX
      </button>
      <button class="ghost" id="btnExportJson" disabled>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
        Audit JSON
      </button>
      <button class="ghost" id="btnExportHtml" disabled>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
        HTML Report
      </button>
      <button class="ghost icon-btn" id="btnThemeToggle" type="button" title="Toggle Dark / Light theme" aria-label="Toggle Dark or Light theme">
        <svg id="themeIcon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
      </button>
    </div>
  </header>

  <main>
    <div class="toolbar-card">
      <div class="toolbar-row">
        <div class="toolbar-field">
          <label for="targetMode">Target</label>
          <select id="targetMode">
            <option value="docker_discovered">Running Docker Lab Containers (Auto-Discover)</option>
            <option value="lab_inventory">Lab Inventory (lab/inventory.yaml)</option>
            <option value="custom_inventory">Custom Inventory (inventory.yaml)</option>
            <option value="demo_fleet">Simulated Demo Fleet (3 Linux + 2 Windows Server)</option>
            <option value="local">Local Machine (localhost)</option>
            <option value="custom_target">Custom Target (Single Docker / SSH Host)</option>
          </select>
        </div>

        <div class="toolbar-field">
          <label for="scanMode">Mode</label>
          <select id="scanMode">
            <option value="live_scan">Auto-Scan (Built-in + OSV + CISA KEV)</option>
            <option value="custom_cves">Specific CVE ID(s)</option>
            <option value="scanner_json">Filter Trivy / Grype JSON Report</option>
          </select>
        </div>

        <div class="btn-row">
          <button class="primary" id="btnRun">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>
            Run Reachability Proof
          </button>
          <button id="btnResetLab" title="Restore Demo Fleet and Docker Lab containers to initial vulnerable state">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>
            Reset Lab
          </button>
        </div>

        <div class="toggles-group">
          <label class="switch-label">
            <input type="checkbox" id="chkOffline" />
            <span>Offline</span>
          </label>
          <label class="switch-label">
            <input type="checkbox" id="chkUseLlm" />
            <span>AI Advisor</span>
          </label>
        </div>
      </div>

      <div class="toolbar-extras">
        <div class="field" id="customTargetField" style="display:none;">
          <label for="customTargetValue">Custom Target Type &amp; Address</label>
          <div style="display:flex; gap:0.5rem;">
            <select id="customTargetType" style="width:45%;">
              <option value="docker_linux">Docker (Linux)</option>
              <option value="docker_windows">Docker (Win-Sim)</option>
              <option value="ssh_linux">SSH (Linux)</option>
              <option value="ssh_windows">SSH (Windows)</option>
            </select>
            <input type="text" id="customTargetValue" placeholder="e.g. lab-ssh-vuln or ubuntu@10.0.0.15" value="lab-ssh-vuln" style="width:55%;" />
          </div>
        </div>

        <div class="field" id="customCveField" style="display:none;">
          <label for="cveInput">CVE IDs (comma or space separated)</label>
          <input type="text" id="cveInput" placeholder="e.g. CVE-2024-6387, CVE-2024-38063, CVE-2021-34527" value="CVE-2024-6387, CVE-2024-38063, CVE-2021-34527" />
        </div>

        <div class="field" id="scannerJsonField" style="display:none;">
          <label for="scannerFileInput">Trivy / Grype JSON File (leave empty for examples/trivy-scan.json)</label>
          <input type="file" id="scannerFileInput" accept=".json,application/json" style="color:var(--muted); font-size:0.8rem;" />
        </div>
      </div>
    </div>

    <div class="feed-banner" id="feedBanner">Ready. Click "Run Reachability Proof" to evaluate targets.</div>

    <div class="kpi-grid">
      <div class="kpi-card clickable" id="kpiAffectedCard" data-kpi-filter="affected" tabindex="0" role="button" title="Filter Affected verdicts">
        <div class="label">Affected (Action Required)</div>
        <div class="val danger" id="kpiAffected">0</div>
      </div>
      <div class="kpi-card clickable" data-kpi-filter="not_affected" tabindex="0" role="button" title="Filter Not Affected verdicts">
        <div class="label">Not Affected (VEX Proven)</div>
        <div class="val ok" id="kpiNotAffected">0</div>
      </div>
      <div class="kpi-card clickable" data-kpi-filter="under_investigation" tabindex="0" role="button" title="Filter Under Investigation verdicts">
        <div class="label">Under Investigation</div>
        <div class="val warn" id="kpiUnderInv">0</div>
      </div>
      <div class="kpi-card">
        <div class="label">False-Positive Noise Cut</div>
        <div class="val accent" id="kpiNoise">0%</div>
        <div class="kpi-bar"><div class="kpi-bar-fill" id="noiseBar"></div></div>
      </div>
      <div class="kpi-card kpi-muted clickable" data-kpi-filter="all" tabindex="0" role="button" title="Show all verdicts">
        <div class="label">Total Host-CVE Proofs</div>
        <div class="val" id="kpiTotal">0</div>
      </div>
    </div>

    <div class="dist-card" aria-label="Verdict distribution">
      <span class="dist-title">Verdict Split</span>
      <div class="dist-track">
        <div class="dist-seg aff" id="distAff" style="width:0%"></div>
        <div class="dist-seg inv" id="distInv" style="width:0%"></div>
        <div class="dist-seg ok" id="distOk" style="width:0%"></div>
      </div>
      <div class="dist-legend">
        <span><i class="dist-dot" style="background:var(--danger-strong)"></i><b id="distAffLbl">0</b> Affected</span>
        <span><i class="dist-dot" style="background:var(--warn)"></i><b id="distInvLbl">0</b> Investigating</span>
        <span><i class="dist-dot" style="background:var(--ok)"></i><b id="distOkLbl">0</b> Proven Safe</span>
      </div>
    </div>

    <div class="workspace-card">
      <div class="workspace-tabs">
        <div style="display:flex; align-items:center; gap:0.55rem; flex-wrap:wrap;">
          <div class="tab-strip" role="tablist">
            <button type="button" class="tab-btn active" data-tab="verdicts" role="tab" aria-selected="true">Host Verdicts</button>
            <button type="button" class="tab-btn" data-tab="briefing" role="tab" aria-selected="false">Operational Briefing</button>
          </div>
          <span class="count-chip" id="rowCountChip">0 rows</span>
        </div>

        <div class="filter-bar" id="verdictsFilterBar">
          <div class="seg-group" id="statusSegments" role="group" aria-label="Filter by verdict status">
            <button type="button" class="seg-btn active" data-status="attention" aria-pressed="true" title="Affected and under investigation">Needs Attention</button>
            <button type="button" class="seg-btn" data-status="all" aria-pressed="false">All</button>
            <button type="button" class="seg-btn" data-status="affected" aria-pressed="false">Affected</button>
            <button type="button" class="seg-btn" data-status="not_affected" aria-pressed="false">Not Affected</button>
            <button type="button" class="seg-btn" data-status="under_investigation" aria-pressed="false">Investigating</button>
          </div>
          <select id="filterStatus" class="sr-select" aria-label="Verdict status filter">
            <option value="attention" selected>Needs Attention</option>
            <option value="all">All Verdicts</option>
            <option value="affected">Affected Only</option>
            <option value="not_affected">Not Affected Only</option>
            <option value="under_investigation">Under Investigation</option>
          </select>
          <select id="filterOs" aria-label="OS family filter">
            <option value="all">All OS</option>
            <option value="linux">Linux</option>
            <option value="windows">Windows Server</option>
          </select>
          <div class="search-wrap">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input type="text" id="filterSearch" placeholder="Filter host, CVE, proof..." />
            <span class="kbd-hint">/</span>
          </div>
        </div>
      </div>

      <div id="tabPaneVerdicts">
        <div class="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Verdict</th>
                <th>CVE ID</th>
                <th>Host</th>
                <th>OS</th>
                <th>Patch / VEX</th>
                <th>Deterministic Proof (Click row to inspect)</th>
              </tr>
            </thead>
            <tbody id="verdictsBody">
              <tr><td colspan="6" style="color:var(--muted);">Loading initial evaluation...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div id="tabPaneBriefing" class="briefing-pane pane-hidden">
        <div class="briefing-header">
          <h2>Operational Risk &amp; Remediation Safety Briefing</h2>
          <button type="button" class="ghost" id="btnCopyBriefing">Copy Briefing</button>
        </div>
        <pre class="briefing" id="briefingBox">Run an evaluation to view host-aware remediation guidance.</pre>
      </div>
    </div>
  </main>

  <!-- Master-Detail Inspector Drawer -->
  <div class="drawer-backdrop" id="drawerBackdrop"></div>
  <aside class="detail-drawer" id="detailDrawer" role="dialog" aria-modal="true" aria-hidden="true" inert aria-label="Verdict Inspector">
    <div class="drawer-header">
      <div>
        <div class="drawer-title-row" id="drawerTitleRow"></div>
        <div class="drawer-sub" id="drawerSub"></div>
      </div>
      <button type="button" class="ghost icon-btn" id="btnCloseDrawer" title="Close (Esc)" aria-label="Close inspector">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <div class="drawer-body" id="drawerBody"></div>
    <div class="drawer-footer">
      <span>Navigate rows: <kbd>↑</kbd> <kbd>↓</kbd> · Close: <kbd>Esc</kbd></span>
      <span id="drawerIndexLabel"></span>
    </div>
  </aside>

  <script>
    const PAGE_TOKEN = document.querySelector('meta[name="notaffected-token"]').content;
    let latestResult = null;
    let currentFiltered = [];
    let selectedIdx = -1;
    let activeTargetConfig = {
      target_mode: "docker_discovered",
      custom_target_type: "docker_linux",
      custom_target_value: "lab-ssh-vuln",
    };

    const STATUS_LABEL = {
      affected: "Affected",
      not_affected: "Not affected",
      under_investigation: "Under investigation",
    };

    /* Theme persistence (Dark default) */
    function applyTheme(theme) {
      const next = theme === "light" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try { localStorage.setItem("notaffected-theme", next); } catch (_) {}
      const icon = document.getElementById("themeIcon");
      if (icon) {
        icon.innerHTML = next === "dark"
          ? '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>'
          : '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>';
      }
    }
    try {
      const saved = localStorage.getItem("notaffected-theme");
      if (saved === "dark" || saved === "light") applyTheme(saved);
    } catch (_) {}
    document.getElementById("btnThemeToggle").addEventListener("click", () => {
      const cur = document.documentElement.getAttribute("data-theme");
      applyTheme(cur === "dark" ? "light" : "dark");
    });

    /* Workspace tabs */
    function setActiveTab(tabName) {
      const isVerdicts = tabName !== "briefing";
      document.getElementById("tabPaneVerdicts").classList.toggle("pane-hidden", !isVerdicts);
      document.getElementById("tabPaneBriefing").classList.toggle("pane-hidden", isVerdicts);
      document.getElementById("verdictsFilterBar").style.display = isVerdicts ? "flex" : "none";
      document.querySelectorAll(".tab-btn").forEach((b) => {
        const active = b.getAttribute("data-tab") === (isVerdicts ? "verdicts" : "briefing");
        b.classList.toggle("active", active);
        b.setAttribute("aria-selected", active ? "true" : "false");
      });
    }
    document.querySelectorAll(".tab-btn").forEach((b) => {
      b.addEventListener("click", () => setActiveTab(b.getAttribute("data-tab")));
    });

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
      setActiveTab("verdicts");
      const sel = document.getElementById("filterStatus");
      sel.value = val;
      document.querySelectorAll("#statusSegments .seg-btn").forEach((b) => {
        const isActive = b.getAttribute("data-status") === val;
        b.classList.toggle("active", isActive);
        b.setAttribute("aria-pressed", isActive ? "true" : "false");
      });
      closeDrawer();
      renderVerdictRows();
    }

    document.querySelectorAll("#statusSegments .seg-btn").forEach((b) => {
      b.addEventListener("click", () => setStatusFilter(b.getAttribute("data-status")));
    });
    document.querySelectorAll(".kpi-card[data-kpi-filter]").forEach((card) => {
      card.addEventListener("click", () => setStatusFilter(card.getAttribute("data-kpi-filter")));
      card.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          setStatusFilter(card.getAttribute("data-kpi-filter"));
        }
      });
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

    /* Master-Detail Inspector Drawer */
    let lastFocusedBeforeDrawer = null;
    function closeDrawer() {
      selectedIdx = -1;
      const drawer = document.getElementById("detailDrawer");
      drawer.classList.remove("open");
      drawer.setAttribute("aria-hidden", "true");
      drawer.inert = true;
      document.getElementById("drawerBody").innerHTML = "";
      document.getElementById("drawerBackdrop").classList.remove("open");
      document.querySelectorAll("#verdictsBody tr.row-selected").forEach((r) => r.classList.remove("row-selected"));
      if (lastFocusedBeforeDrawer && typeof lastFocusedBeforeDrawer.focus === "function") {
        lastFocusedBeforeDrawer.focus();
        lastFocusedBeforeDrawer = null;
      }
    }

    function openDrawer(idx) {
      if (idx < 0 || idx >= currentFiltered.length) return;
      if (selectedIdx < 0) lastFocusedBeforeDrawer = document.activeElement;
      selectedIdx = idx;
      const v = currentFiltered[idx];
      const specById = {};
      for (const sp of (latestResult && latestResult.specs ? latestResult.specs : [])) {
        if (sp && sp.cve_id) specById[sp.cve_id] = sp;
      }
      const spec = specById[v.cve_id] || null;

      document.querySelectorAll("#verdictsBody tr").forEach((r, i) => {
        const isSel = i === idx;
        r.classList.toggle("row-selected", isSel);
        if (isSel) r.scrollIntoView({ block: "nearest" });
      });

      document.getElementById("drawerTitleRow").innerHTML = `
        <span class="badge ${esc(v.status)}">${esc(STATUS_LABEL[v.status] || v.status)}</span>
        <code class="cve-code">${esc(v.cve_id)}</code>
        <span class="badge os">${esc(v.os_family)}</span>
      `;
      document.getElementById("drawerSub").innerHTML =
        `Host: <strong style="color:var(--text);">${esc(v.host)}</strong>` +
        (spec ? ` · Source: <code>${esc(spec.source)}</code> · Confidence: <code>${esc(spec.confidence)}</code> · Severity: <code>${esc(spec.severity)}</code>` : "");
      document.getElementById("drawerIndexLabel").textContent = `${idx + 1} / ${currentFiltered.length}`;

      const justOrPatch = v.status === "not_affected"
        ? `VEX Justification: <code class="just-code">${esc(v.justification || "not_affected")}</code>`
        : `Patch status: <strong>${esc(v.patch ? v.patch.status : "unknown")}</strong>` +
          (v.patch && v.patch.fixed_version ? ` · Fixed: <code>${esc(v.patch.fixed_version)}</code>` : "");

      const mitSection = (v.status === "affected" && v.mitigation && v.mitigation.length > 0)
        ? `
          <div class="drawer-section">
            <h3>Temporary Mitigations (${v.mitigation.length})</h3>
            ${v.mitigation.map((m, mIdx) => {
              const low = String(m || "").trim().toLowerCase();
              const canRun = (
                low.startsWith("sudo ") ||
                low.startsWith("echo ") ||
                low.startsWith("set-itemproperty ") ||
                low.startsWith("stop-service ") ||
                low.startsWith("set-service ")
              );
              const runBtn = canRun
                ? `<button type="button" class="mini caution" data-apply-host="${esc(v.host)}" data-apply-cve="${esc(v.cve_id)}" data-apply-idx="${mIdx}" data-apply-cmd="${esc(m)}" title="Applies temporary mitigation and re-verifies host">Run Mitigation</button>`
                : "";
              return `
                <div class="mit-row">
                  <code class="mit-cmd">$ ${esc(m)}</code>
                  <button type="button" class="mini primary" data-copy-cmd="${esc(m)}">Copy</button>
                  ${runBtn}
                </div>
              `;
            }).join("")}
          </div>
        `
        : "";

      const probes = v.probe_results || [];
      let probesHtml = "";
      if (probes.length > 0) {
        probesHtml = probes.map((pr, pIdx) => {
          const pSt = String(pr.status || "UNKNOWN");
          const pLow = pSt.toLowerCase();
          const pColor = pSt === "NOT_MET" ? "var(--ok)" : (pSt === "MET" ? "var(--danger)" : "var(--warn)");
          const pName = pr.precondition ? pr.precondition.probe : "probe";
          const pDesc = pr.precondition ? pr.precondition.description : "";
          return `
            <div class="probe-item st-${esc(pLow)}">
              <div>
                <strong style="color:${pColor};">#${pIdx + 1} [${esc(pSt)}]</strong>
                <code>${esc(pName)}</code> &mdash; <span style="color:var(--muted);">${esc(pDesc)}</span>
              </div>
              <div style="margin-top:0.25rem; color:var(--text-soft);">Command: <code>${esc(pr.command || "n/a")}</code></div>
              <div style="margin-top:0.18rem; color:var(--muted);">Output: ${esc(pr.evidence || "")}</div>
            </div>
          `;
        }).join("");
      } else if (spec && spec.preconditions && spec.preconditions.length > 0) {
        probesHtml = `<div class="drawer-box">` + spec.preconditions.map((pre, pIdx) => `
          <div style="margin-top:${pIdx ? "0.35rem" : "0"}; font-size:0.79rem; color:var(--muted);">
            #${pIdx + 1} <code>${esc(pre.probe)}</code>: ${esc(pre.description)} (skipped due to OS mismatch)
          </div>
        `).join("") + `</div>`;
      } else {
        probesHtml = `<div class="drawer-box" style="color:var(--muted);">No deterministic preconditions available for this advisory.</div>`;
      }

      document.getElementById("drawerBody").innerHTML = `
        <div class="drawer-section">
          <h3>Deterministic Proof</h3>
          <div class="drawer-box">
            <div>${esc(v.reason)}</div>
            <div style="margin-top:0.55rem; padding-top:0.5rem; border-top:1px solid var(--border); font-size:0.79rem;">${justOrPatch}</div>
          </div>
        </div>
        ${mitSection}
        ${spec ? `
          <div class="drawer-section">
            <h3>Advisory Summary</h3>
            <div class="drawer-box">${esc(spec.summary)}</div>
          </div>
        ` : ""}
        <div class="drawer-section">
          <h3>Inspect Probes &amp; Commands (${probes.length})</h3>
          ${probesHtml}
        </div>
      `;

      const drawer = document.getElementById("detailDrawer");
      drawer.removeAttribute("aria-hidden");
      drawer.inert = false;
      drawer.classList.add("open");
      document.getElementById("drawerBackdrop").classList.add("open");
      const closeBtn = document.getElementById("btnCloseDrawer");
      if (closeBtn) closeBtn.focus({ preventScroll: true });
    }

    document.getElementById("btnCloseDrawer").addEventListener("click", closeDrawer);
    document.getElementById("drawerBackdrop").addEventListener("click", closeDrawer);

    /* Keyboard shortcuts: '/' search, Esc close drawer, ArrowUp/Down navigate rows */
    document.addEventListener("keydown", (e) => {
      const tag = (document.activeElement && document.activeElement.tagName || "").toLowerCase();
      const inInput = tag === "input" || tag === "textarea" || tag === "select";
      if (e.key === "/" && !inInput) {
        e.preventDefault();
        setActiveTab("verdicts");
        document.getElementById("filterSearch").focus();
        return;
      }
      if (e.key === "Escape") {
        closeDrawer();
        return;
      }
      if (!inInput && selectedIdx >= 0) {
        if (e.key === "ArrowDown" && selectedIdx + 1 < currentFiltered.length) {
          e.preventDefault();
          openDrawer(selectedIdx + 1);
        } else if (e.key === "ArrowUp" && selectedIdx > 0) {
          e.preventDefault();
          openDrawer(selectedIdx - 1);
        }
      }
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
          } else {
            const scope = ai.local_only ? "local" : "external";
            const unreachable = ai.online === false;
            const checked = ai.online === true;
            aiPill.innerHTML = `<span class="status-dot ${unreachable ? "warn" : checked ? "ok" : ""}"></span>AI: ${esc(ai.provider)} · ${esc(ai.model)} (${scope}${unreachable ? ", unreachable" : ""})`;
            aiPill.title = unreachable ? (ai.detail || "") : checked ? "" : "Configured; not contacted until the AI advisor runs.";
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
        currentFiltered = [];
        if (chip) chip.textContent = "0 rows";
        tbody.innerHTML = '<tr><td colspan="6" style="color:var(--muted);">No verdicts available.</td></tr>';
        return;
      }
      const stFilter = document.getElementById("filterStatus").value;
      const osFilter = document.getElementById("filterOs").value;
      const q = (document.getElementById("filterSearch").value || "").toLowerCase();

      const statusRank = { affected: 0, under_investigation: 1, not_affected: 2 };
      currentFiltered = latestResult.verdicts
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

      if (chip) chip.textContent = `${currentFiltered.length} / ${latestResult.verdicts.length} rows`;

      if (currentFiltered.length === 0) {
        const emptyMsg = stFilter === "attention" && !q && osFilter === "all"
          ? "Nothing needs attention: every host-CVE pair is proven not affected."
          : "No matching verdicts for current filter.";
        tbody.innerHTML = `<tr><td colspan="6" style="color:var(--muted);">${esc(emptyMsg)}</td></tr>`;
        return;
      }

      tbody.innerHTML = currentFiltered.map((v, idx) => {
        const justOrPatch = v.status === "not_affected"
          ? `<code class="just-code">${esc(v.justification || "not_affected")}</code>`
          : `<strong>${esc(v.patch ? v.patch.status : "unknown")}</strong>` +
            (v.patch && v.patch.fixed_version ? ` <span style="color:var(--subtle);">(${esc(v.patch.fixed_version)})</span>` : "");
        const probeCount = (v.probe_results || []).length;
        const mitCount = (v.status === "affected" && v.mitigation) ? v.mitigation.length : 0;
        const rowClass = v.status === "affected"
          ? "row-affected"
          : (v.status === "under_investigation" ? "row-investigating" : "row-safe");

        return `
          <tr class="${rowClass}" data-row-idx="${idx}" tabindex="0">
            <td><span class="badge ${esc(v.status)}">${esc(STATUS_LABEL[v.status] || v.status)}</span></td>
            <td><code class="cve-code">${esc(v.cve_id)}</code></td>
            <td><strong>${esc(v.host)}</strong></td>
            <td><span class="badge os">${esc(v.os_family)}</span></td>
            <td>${justOrPatch}</td>
            <td>
              <div class="proof-preview">${esc(v.reason)}</div>
              <div class="row-meta-chips">
                <span class="meta-tag">${probeCount} probe${probeCount === 1 ? "" : "s"}</span>
                ${mitCount > 0 ? `<span class="meta-tag mit">${mitCount} mitigation${mitCount === 1 ? "" : "s"}</span>` : ""}
              </div>
            </td>
          </tr>
        `;
      }).join("");
    }

    async function runEvaluation() {
      const btn = document.getElementById("btnRun");
      const origHtml = btn.innerHTML;
      btn.disabled = true;
      btn.textContent = "Probing...";
      document.getElementById("feedBanner").textContent = "Executing read-only system probes and live CVE checks...";
      closeDrawer();

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
        const total = Number(s.total || 0);
        const aff = Number(s.affected || 0);
        const ok = Number(s.not_affected || 0);
        const inv = Number(s.under_investigation || 0);

        document.getElementById("kpiTotal").textContent = total;
        document.getElementById("kpiAffected").textContent = aff;
        document.getElementById("kpiAffectedCard").classList.toggle("kpi-hot", aff > 0);
        document.getElementById("kpiNotAffected").textContent = ok;
        document.getElementById("kpiUnderInv").textContent = inv;
        const noisePct = s.noise_reduction_pct || 0;
        document.getElementById("kpiNoise").textContent = noisePct + "%";
        const noiseBar = document.getElementById("noiseBar");
        if (noiseBar) noiseBar.style.width = Math.max(0, Math.min(100, Number(noisePct))) + "%";

        const denom = total || 1;
        document.getElementById("distAff").style.width = ((aff / denom) * 100).toFixed(1) + "%";
        document.getElementById("distInv").style.width = ((inv / denom) * 100).toFixed(1) + "%";
        document.getElementById("distOk").style.width = ((ok / denom) * 100).toFixed(1) + "%";
        document.getElementById("distAffLbl").textContent = aff;
        document.getElementById("distInvLbl").textContent = inv;
        document.getElementById("distOkLbl").textContent = ok;

        document.getElementById("briefingBox").textContent = latestResult.briefing || "";

        const fm = latestResult.feed_meta || {};
        const bannerEl = document.getElementById("feedBanner");
        if (fm.error) {
          bannerEl.style.color = "var(--danger)";
          bannerEl.textContent = "Notice: " + fm.error;
        } else {
          bannerEl.style.color = "var(--subtle)";
          const osvCount = (fm.osv_live_cves || []).length;
          const kevCount = (fm.cisa_kev_cves || []).length;
          bannerEl.textContent =
            `Evaluated ${s.hosts_evaluated || 0} host(s) across ${s.cves_evaluated || 0} CVE(s) · ` +
            `Built-in: ${fm.builtin_count || 0} · Live OSV: ${osvCount} · CISA KEV: ${kevCount}`;
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
    document.getElementById("filterOs").addEventListener("change", () => { closeDrawer(); renderVerdictRows(); });
    document.getElementById("filterSearch").addEventListener("input", () => { closeDrawer(); renderVerdictRows(); });

    document.getElementById("btnCopyBriefing").addEventListener("click", async (e) => {
      const btn = e.currentTarget;
      const text = document.getElementById("briefingBox").textContent || "";
      try {
        await navigator.clipboard.writeText(text);
        const orig = btn.textContent;
        btn.textContent = "Copied!";
        setTimeout(() => { btn.textContent = orig; }, 1200);
      } catch (err) {
        console.error(err);
      }
    });

    /* Row click or Enter/Space opens Master-Detail Inspector Drawer */
    document.getElementById("verdictsBody").addEventListener("click", (e) => {
      const row = e.target.closest("tr[data-row-idx]");
      if (!row) return;
      openDrawer(Number(row.getAttribute("data-row-idx")));
    });
    document.getElementById("verdictsBody").addEventListener("keydown", (e) => {
      if (e.key !== "Enter" && e.key !== " ") return;
      const row = e.target.closest("tr[data-row-idx]");
      if (!row) return;
      e.preventDefault();
      openDrawer(Number(row.getAttribute("data-row-idx")));
    });

    /* Copy & Run Mitigation actions inside the Inspector Drawer */
    document.getElementById("drawerBody").addEventListener("click", async (e) => {
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
    remote_mode: bool = False

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
        if self.remote_mode and srv_addr in ("0.0.0.0", "::", ""):
            return bool(host_only)
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
            if self.remote_mode and srv_addr in ("0.0.0.0", "::", ""):
                raw_host = (self.headers.get("Host") or "").strip().lower()
                host_only = raw_host.split(":")[0] if not raw_host.startswith("[") else raw_host.split("]")[0].lstrip("[")
                return bool(origin_host) and (origin_host == host_only or origin_host in _ALLOWED_LOCAL_HOSTS)
            if origin_host not in _ALLOWED_LOCAL_HOSTS and origin_host != srv_addr:
                return False
        return True

    def _has_valid_token(self) -> bool:
        sent_token = self.headers.get("X-Notaffected-Token") or ""
        return hmac.compare_digest(sent_token.encode("utf-8"), self.request_token.encode("utf-8"))

    def do_GET(self) -> None:  # noqa: N802
        if not self._is_allowed_host():
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "Forbidden Host header"})
            return
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            page_token = "" if self.remote_mode else self.request_token
            self._send_html(HTTPStatus.OK, DASHBOARD_HTML.replace("__NOTAFFECTED_TOKEN__", page_token))
            return
        if self.remote_mode and parsed.path.startswith("/api/") and not self._has_valid_token():
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "Missing or invalid request token"})
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
        if not self._has_valid_token():
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
    """Refuse a non-loopback bind unless explicitly allowed with NOTAFFECTED_REMOTE_TOKEN."""
    is_loopback = host.strip().lower() in ("127.0.0.1", "::1", "localhost")
    if is_loopback:
        return
    if not allow_remote:
        raise SystemExit(
            f"Refusing to bind the dashboard to {host!r}: it can run probes over SSH with your keys. "
            "Pass --allow-remote and set NOTAFFECTED_REMOTE_TOKEN (>= 16 chars) to do it anyway."
        )
    remote_token = (os.environ.get("NOTAFFECTED_REMOTE_TOKEN") or "").strip()
    if len(remote_token) < 16:
        raise SystemExit(
            f"Refusing to bind to {host!r} with --allow-remote without NOTAFFECTED_REMOTE_TOKEN (>= 16 chars)."
        )


def run_web_server(host: str = "127.0.0.1", port: int = 8484, allow_remote: bool = False) -> None:
    """Start the local notaffected Web UI server (loopback only unless `allow_remote`)."""
    check_bind_address(host, allow_remote)
    is_remote = host.strip().lower() not in ("127.0.0.1", "::1", "localhost")
    DashboardRequestHandler.remote_mode = is_remote
    DashboardRequestHandler.request_token = (
        (os.environ.get("NOTAFFECTED_REMOTE_TOKEN") or "").strip()
        if is_remote
        else secrets.token_urlsafe(32)
    )
    server = ThreadingHTTPServer((host, port), DashboardRequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
