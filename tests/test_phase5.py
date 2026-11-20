"""Tests for Phase 5: Live CVE discovery (`live_feed.py`), `scan` & `init` CLI
commands, and the local Web Dashboard (`web.py`).
"""

from __future__ import annotations

import io
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

from notaffected.advisories.live_feed import (
    collect_scan_specs,
    discover_host_package_cves,
    fetch_cisa_kev_cves,
)
from notaffected.cli import main
from notaffected.inventory import generate_inventory_yaml
from notaffected.probes.runner import CommandResult, DockerRunner, MockRunner, SSHRunner
from notaffected.web import (
    _DEMO_MITIGATED,
    DashboardRequestHandler,
    _build_runners_for_mode,
    apply_host_mitigation,
    evaluate_dashboard_request,
    get_targets_metadata,
    reset_lab_and_demo,
)


def test_fetch_cisa_kev_cves_from_cache(tmp_path: Path) -> None:
    sample_kev = {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-6387",
                "vendorProject": "OpenSSH",
                "product": "OpenSSH",
                "vulnerabilityName": "OpenSSH regreSSHion RCE",
                "dateAdded": "2024-07-02",
                "shortDescription": "OpenSSH server race condition in sshd.",
                "requiredAction": "Apply vendor updates.",
            },
            {
                "cveID": "CVE-2024-38063",
                "vendorProject": "Microsoft",
                "product": "Windows",
                "vulnerabilityName": "Windows TCP/IP IPv6 RCE",
                "dateAdded": "2024-08-14",
                "shortDescription": "Windows TCP/IP IPv6 integer underflow.",
                "requiredAction": "Apply KB5041585.",
            },
            {
                "cveID": "CVE-2024-99999",
                "vendorProject": "Cisco",
                "product": "Cisco Secure Firewall",
                "vulnerabilityName": "Cisco Bug",
                "dateAdded": "2024-09-01",
                "shortDescription": "Should not match 'isc' substring.",
                "requiredAction": "Update.",
            },
        ],
    }
    cache_file = tmp_path / "cisa_kev_catalog.json"
    cache_file.write_text(json.dumps(sample_kev), encoding="utf-8")

    items = fetch_cisa_kev_cves(limit=5, cache_dir=tmp_path)
    cve_ids = [i["cveID"] for i in items]
    assert "CVE-2024-38063" in cve_ids
    assert "CVE-2024-6387" in cve_ids
    assert "CVE-2024-99999" not in cve_ids
    # Sorted newest dateAdded first
    assert cve_ids[0] == "CVE-2024-38063"


def test_discover_host_package_cves_querybatch(monkeypatch: Any) -> None:
    runner = MockRunner(
        host_name="test-linux-01",
        responses={
            ("dpkg-query", "-W", "-f=${db:Status-Abbrev}\\t${Version}\\n", "openssh-server"): CommandResult(
                0, "ii \t1:9.6p1-3ubuntu13\n", ""
            ),
        },
    )

    class _FakeResp:
        def __enter__(self) -> io.BytesIO:
            payload = {
                "results": [
                    {"vulns": [{"id": "UBUNTU-CVE-2024-6387"}]},
                    {"vulns": []},
                ]
            }
            return io.BytesIO(json.dumps(payload).encode("utf-8"))

        def __exit__(self, *args: Any) -> None:
            pass

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=8: _FakeResp())
    found = discover_host_package_cves([runner])
    assert ("CVE-2024-6387", "openssh-server") in found


def test_collect_scan_specs_offline() -> None:
    runner = MockRunner(host_name="node-1", responses={})
    specs, meta = collect_scan_specs([runner], offline=True)
    assert meta["offline"] is True
    assert meta["builtin_count"] >= 7
    assert len(specs) == meta["builtin_count"]


def test_cli_init_and_scan_offline(tmp_path: Path) -> None:
    inv_file = tmp_path / "test-inventory.yaml"
    rc_init = main(["init", "-o", str(inv_file)])
    assert rc_init == 0
    assert inv_file.is_file()
    content = inv_file.read_text(encoding="utf-8")
    assert "hosts:" in content

    # Second run without --force returns 1
    assert main(["init", "-o", str(inv_file)]) == 1
    assert main(["init", "-o", str(inv_file), "--force"]) == 0

    vex_file = tmp_path / "scan.vex.json"
    rc_scan = main(["scan", "--offline", "--demo-fleet", "--emit-vex", str(vex_file)])
    assert rc_scan == 0
    assert vex_file.is_file()


def test_web_dashboard_endpoints_end_to_end() -> None:
    meta = get_targets_metadata()
    assert "builtin_cves" in meta
    assert len(meta["builtin_cves"]) >= 7

    eval_res = evaluate_dashboard_request(
        {
            "target_mode": "demo_fleet",
            "scan_mode": "live_scan",
            "offline": True,
        }
    )
    assert eval_res["summary"]["total"] == 35  # 5 demo hosts * 7 builtin CVEs
    assert eval_res["summary"]["affected"] == 4
    assert eval_res["openvex"]["@context"] == "https://openvex.dev/ns/v0.2.0"

    server = ThreadingHTTPServer(("127.0.0.1", 0), DashboardRequestHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as resp:
            html_body = resp.read().decode("utf-8")
            assert "notaffected" in html_body
            assert "Run Reachability Proof" in html_body

        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/api/spec?cve=CVE-2024-6387", timeout=5
        ) as resp:
            spec_json = json.load(resp)
            assert spec_json["cve_id"] == "CVE-2024-6387"

        post_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/evaluate",
            data=json.dumps(
                {
                    "target_mode": "demo_fleet",
                    "scan_mode": "custom_cves",
                    "cves": "CVE-2024-6387, CVE-2024-38063",
                    "offline": True,
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(post_req, timeout=5) as resp:
            post_json = json.load(resp)
            assert post_json["summary"]["cves_evaluated"] == 2
            assert post_json["summary"]["hosts_evaluated"] == 5

        # Cross-origin POST or non-JSON Content-Type must be rejected with 403
        csrf_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/evaluate",
            data=b'{"target_mode":"demo_fleet"}',
            headers={
                "Content-Type": "text/plain",
                "Origin": "https://evil.example.com",
            },
        )
        try:
            urllib.request.urlopen(csrf_req, timeout=5)
            raise AssertionError("Expected HTTPError 403")
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
    finally:
        server.shutdown()
        server.server_close()


def test_generate_inventory_yaml_structure() -> None:
    text = generate_inventory_yaml(discover_docker=False)
    assert "localhost" in text
    assert "hosts:" in text


def test_web_dashboard_scanner_json_mode() -> None:
    _DEMO_MITIGATED.clear()
    sample_trivy = {
        "Results": [
            {
                "Target": "ubuntu",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-6387",
                        "PkgName": "openssh-server",
                        "InstalledVersion": "1:9.6p1-3ubuntu13",
                        "FixedVersion": "1:9.6p1-3ubuntu13.3",
                        "Severity": "CRITICAL",
                    }
                ],
            }
        ]
    }
    res = evaluate_dashboard_request(
        {
            "target_mode": "demo_fleet",
            "scan_mode": "scanner_json",
            "scanner_report": sample_trivy,
            "offline": True,
        }
    )
    assert res["summary"]["cves_evaluated"] == 1
    assert res["summary"]["hosts_evaluated"] == 5
    assert res["summary"]["affected"] == 1


def test_apply_host_mitigation_flips_verdict_to_not_affected() -> None:
    _DEMO_MITIGATED.clear()
    try:
        before = evaluate_dashboard_request(
            {
                "target_mode": "demo_fleet",
                "scan_mode": "custom_cves",
                "cves": "CVE-2024-6387",
                "offline": True,
            }
        )
        assert before["summary"]["affected"] == 1

        mit_res = apply_host_mitigation(
            {
                "target_mode": "demo_fleet",
                "host": "prod-edge-api-01",
                "cve_id": "CVE-2024-6387",
                "mitigation_index": 0,
            }
        )
        assert mit_res["ok"] is True

        after = evaluate_dashboard_request(
            {
                "target_mode": "demo_fleet",
                "scan_mode": "custom_cves",
                "cves": "CVE-2024-6387",
                "offline": True,
            }
        )
        assert after["summary"]["affected"] == 0
        assert after["summary"]["not_affected"] == 5

        # Non-command prose mitigation must be rejected safely
        non_exec = apply_host_mitigation(
            {
                "target_mode": "demo_fleet",
                "host": "prod-edge-api-01",
                "cve_id": "CVE-2026-98432",
                "mitigation_index": 2,
            }
        )
        assert non_exec["ok"] is False
    finally:
        _DEMO_MITIGATED.clear()


def test_reset_lab_and_custom_target_runner() -> None:
    _DEMO_MITIGATED.add(("prod-edge-api-01", "CVE-2024-6387"))
    res = reset_lab_and_demo()
    assert res["ok"] is True
    assert "demo_fleet" in res["reset_targets"]
    assert len(_DEMO_MITIGATED) == 0

    r_docker = _build_runners_for_mode(
        "custom_target",
        custom_target_type="docker_linux",
        custom_target_value="lab-ssh-vuln",
    )
    assert len(r_docker) == 1
    assert isinstance(r_docker[0], DockerRunner)
    assert r_docker[0].host_name == "lab-ssh-vuln"

    r_ssh_win = _build_runners_for_mode(
        "custom_target",
        custom_target_type="ssh_windows",
        custom_target_value="Administrator@10.0.0.50",
    )
    assert len(r_ssh_win) == 1
    assert isinstance(r_ssh_win[0], SSHRunner)
    assert r_ssh_win[0].os_family == "windows"

    # Reject flag-injection target strings starting with '-'
    r_unsafe = _build_runners_for_mode(
        "custom_target",
        custom_target_type="ssh_linux",
        custom_target_value="-oProxyCommand=evil",
    )
    assert all(r.host_name != "-oProxyCommand=evil" for r in r_unsafe)


def test_osv_scoring_mitre_windows_and_fallback_verdict() -> None:
    from notaffected.advisories.extractor import extract_from_osv_payload, resolve_check_spec
    from notaffected.engine.evaluator import evaluate_host
    from notaffected.model import VerdictStatus

    # 1. Standard Ubuntu 24.04 package named in summary beats edk2 and FIPS derivatives
    osv_sample = {
        "id": "CVE-2024-2511",
        "summary": "OpenSSL TLS server session cache growth vulnerability",
        "details": "Issue in OpenSSL TLSv1.3 session handling.",
        "affected": [
            {
                "package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "edk2"},
                "ranges": [{"events": [{"fixed": "2024.02-2ubuntu0.6"}]}],
            },
            {
                "package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "openssl"},
                "ranges": [{"events": [{"fixed": "3.0.13-0ubuntu3.2"}]}],
            },
            {
                "package": {"ecosystem": "Ubuntu:Pro:FIPS-updates:24.04:LTS", "name": "openssl-fips"},
                "ranges": [{"events": [{"fixed": "3.0.13-0ubuntu3.6+Fips1"}]}],
            },
        ],
    }
    spec_openssl = extract_from_osv_payload("CVE-2024-2511", osv_sample)
    assert spec_openssl.preconditions[0].params["package"] == "openssl"
    assert spec_openssl.preconditions[0].params["fixed_version"] == "3.0.13-0ubuntu3.2"

    # 2. MITRE Windows CVE extracts fixed_build (20348.x) and windows_service_active
    mitre_win = {
        "id": "CVE-2024-38077",
        "summary": "Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability",
        "details": "Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability",
        "affected": [],
        "references": [{"type": "ADVISORY", "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38077"}],
        "database_specific": {
            "severity": "CRITICAL",
            "mitre_affected": [
                {
                    "vendor": "Microsoft",
                    "product": "Windows Server 2022",
                    "versions": [{"version": "10.0.20348.0", "lessThan": "10.0.20348.2582", "status": "affected"}],
                }
            ],
        },
    }
    spec_win = extract_from_osv_payload("CVE-2024-38077", mitre_win)
    assert spec_win.os_family == "windows"
    assert spec_win.confidence == "high"
    assert any(p.probe == "windows_build_vulnerable" and p.params.get("fixed_build") == "20348.2582" for p in spec_win.preconditions)
    assert any(p.probe == "windows_service_active" and p.params.get("service") == "TermServLicensing" for p in spec_win.preconditions)

    # 3. Unknown fallback CVE with 0 preconditions yields UNDER_INVESTIGATION on Windows too
    spec_unknown = resolve_check_spec("CVE-9999-99999", use_llm=False)
    win_host = MockRunner(host_name="win-dc-01", responses={}, os_family="windows")
    verdict_unk = evaluate_host(spec_unknown, win_host)
    assert verdict_unk.status == VerdictStatus.UNDER_INVESTIGATION


def test_customer_audit_regressions() -> None:
    from notaffected.advisories.extractor import extract_from_osv_payload
    from notaffected.importers.scanners import parse_scanner_json
    from notaffected.model import HostVerdict, Precondition, ProbeStatus, VerdictStatus
    from notaffected.probes.primitives import _normalize_kernel_release, run_probe
    from notaffected.web import DASHBOARD_HTML

    # 1. Ubuntu kernel upload/backport normalization ('6.8.0-45.45' == '6.8.0-45-generic')
    assert _normalize_kernel_release("6.8.0-45-generic") == "6.8.0-45"
    assert _normalize_kernel_release("6.8.0-45.45") == "6.8.0-45"
    assert _normalize_kernel_release("6.5.0-21.21~22.04.1") == "6.5.0-21"

    # 2. Git commit SHAs in OSV GIT ranges are never leaked into fixed_version
    osv_with_git_sha = {
        "id": "CVE-2026-123158",
        "summary": "OpenSSH unfixed advisory with upstream git range",
        "affected": [
            {
                "package": {"ecosystem": "", "name": ""},
                "ranges": [{"type": "GIT", "events": [{"fixed": "4353fdc43ef646c43a8dda7025cc1a898caf1482"}]}],
            },
            {
                "package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "openssh"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            },
        ],
    }
    spec_git = extract_from_osv_payload("CVE-2026-123158", osv_with_git_sha)
    assert spec_git.patch.fixed_version is None
    assert spec_git.preconditions[0].params["fixed_version"] == ""

    # 3. Multi-branch Windows fixed_build matches Server 2019 (17763) and Server 2022 (20348)
    ps_kb_cmd = (
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "$cv = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'; "
        "$build = \"$($cv.CurrentBuildNumber).$($cv.UBR)\"; "
        "$kbs = @(Get-HotFix -ErrorAction SilentlyContinue | Select-Object -ExpandProperty HotFixID) -join ','; "
        "Write-Output \"BUILD=$build|KBS=$kbs\"",
    )
    win2019 = MockRunner(
        host_name="win2019-01",
        os_family="windows",
        responses={ps_kb_cmd: CommandResult(0, "BUILD=17763.6100|KBS=\n", "")},
    )
    pre_multi = Precondition(
        "windows_build_vulnerable",
        {"fixed_build": "17763.6054,20348.2582"},
        "Multi-branch check",
    )
    assert run_probe(pre_multi, win2019).status == ProbeStatus.NOT_MET

    # 4. Grype GHSA match with CVE in relatedVulnerabilities is extracted
    grype_ghsa = {
        "matches": [
            {
                "vulnerability": {"id": "GHSA-xxxx-yyyy-zzzz", "fix": {"versions": ["1.2.3"]}, "severity": "High"},
                "relatedVulnerabilities": [{"id": "CVE-2024-9999"}],
                "artifact": {"name": "foo-server", "version": "1.0.0"},
            }
        ]
    }
    parsed_g = parse_scanner_json(grype_ghsa)
    assert len(parsed_g) == 1
    assert parsed_g[0].cve_id == "CVE-2024-9999"

    # 5. HostVerdict PURL encodes '@', ':', and '/' safely
    hv = HostVerdict(
        host="ubuntu@10.0.0.15:2222",
        cve_id="CVE-2024-6387",
        status=VerdictStatus.NOT_AFFECTED,
        reason="ok",
        justification=None,
    )
    assert hv.product_id == "pkg:generic/linux-host@ubuntu%4010.0.0.15%3A2222"

    # 6. DASHBOARD_HTML esc() escapes quotes to prevent attribute breakout
    assert '.replace(/"/g, "&quot;")' in DASHBOARD_HTML


def test_multi_release_fixes_apk_rpm_and_ui_inspect() -> None:
    from notaffected.advisories.extractor import extract_from_osv_payload
    from notaffected.model import Precondition, ProbeStatus
    from notaffected.probes.primitives import run_probe
    from notaffected.web import DASHBOARD_HTML

    # 1. Multi-release Ubuntu OSV payload populates release_fixes and evaluates 22.04 host accurately
    osv_multi = {
        "id": "CVE-2024-2511",
        "summary": "OpenSSL TLS server session cache vulnerability",
        "affected": [
            {
                "package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "openssl"},
                "ranges": [{"events": [{"fixed": "3.0.13-0ubuntu3.2"}]}],
            },
            {
                "package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "openssl"},
                "ranges": [{"events": [{"fixed": "3.0.2-0ubuntu1.16"}]}],
            },
        ],
    }
    spec = extract_from_osv_payload("CVE-2024-2511", osv_multi)
    pre = spec.preconditions[0]
    assert pre.params["release_fixes"]["ubuntu:22.04"] == "3.0.2-0ubuntu1.16"

    jammy_runner = MockRunner(
        host_name="ubuntu22-01",
        responses={
            ("dpkg-query", "-W", "-f=${db:Status-Abbrev}\\t${Version}\\n", "openssl"): CommandResult(
                0, "ii \t3.0.2-0ubuntu1.17\n", ""
            ),
            ("cat", "/etc/os-release"): CommandResult(0, 'ID=ubuntu\nVERSION_ID="22.04"\n', ""),
            ("dpkg", "--compare-versions", "3.0.2-0ubuntu1.17", "lt", "3.0.2-0ubuntu1.16"): CommandResult(
                1, "", ""
            ),
        },
    )
    res_jammy = run_probe(pre, jammy_runner)
    assert res_jammy.status == ProbeStatus.NOT_MET
    assert "3.0.2-0ubuntu1.16" in res_jammy.evidence

    # 2. Alpine apk and RHEL rpm package fallbacks when dpkg-query is absent (exit 127)
    alpine_runner = MockRunner(
        host_name="alpine-node",
        responses={
            ("apk", "info", "-v", "curl"): CommandResult(0, "curl-8.9.1-r1\n", ""),
        },
    )
    pre_curl = Precondition(
        "package_installed_vulnerable",
        {"package": "curl", "fixed_version": "8.9.0-r0"},
        "curl check",
    )
    res_apk = run_probe(pre_curl, alpine_runner)
    assert res_apk.status == ProbeStatus.NOT_MET
    assert res_apk.command == "apk info -v curl"

    rhel_runner = MockRunner(
        host_name="rhel-node",
        responses={
            ("rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}\\n", "httpd"): CommandResult(
                1, "package httpd is not installed\n", ""
            ),
        },
    )
    pre_httpd = Precondition(
        "package_installed_vulnerable",
        {"package": "httpd", "fixed_version": "2.4.57-8.el9"},
        "httpd check",
    )
    res_rpm = run_probe(pre_httpd, rhel_runner)
    assert res_rpm.status == ProbeStatus.NOT_MET
    assert "rpm -q" in res_rpm.evidence

    # 3. Invalid custom_target returns explicit error in feed_meta instead of demo_fleet
    bad_target_res = evaluate_dashboard_request(
        {
            "target_mode": "custom_target",
            "custom_target_type": "ssh_linux",
            "custom_target_value": "-oProxyCommand=evil",
            "scan_mode": "custom_cves",
            "cves": "CVE-2024-6387",
            "offline": True,
        }
    )
    assert bad_target_res["summary"]["hosts_evaluated"] == 0
    assert "Invalid or empty custom target" in bad_target_res["feed_meta"]["error"]
    assert "Inspect Probes &amp; Commands" in DASHBOARD_HTML






