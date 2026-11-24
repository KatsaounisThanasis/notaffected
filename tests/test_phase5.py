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

from notaffected.advisories.builtin_specs import BUILTIN_SPECS
from notaffected.advisories.live_feed import (
    collect_scan_specs,
    discover_host_package_cves,
    fetch_cisa_kev_cves,
)
from notaffected.cli import main
from notaffected.inventory import generate_inventory_yaml
from notaffected.probes.runner import CommandResult, DockerRunner, LocalRunner, MockRunner, SSHRunner
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
        import re as _re

        token = _re.search(r'<meta name="notaffected-token" content="([^"]+)"', html_body).group(1)
        assert token == DashboardRequestHandler.request_token and "__NOTAFFECTED_TOKEN__" not in html_body

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
            headers={"Content-Type": "application/json", "X-Notaffected-Token": token},
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

        # A same-origin JSON POST without the page's token (e.g. curl from another process) is refused
        for bad in ({}, {"X-Notaffected-Token": "wrong"}):
            no_token = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/mitigate",
                data=b'{"target_mode":"local","host":"x","cve_id":"CVE-2024-6387","mitigation_index":0}',
                headers={"Content-Type": "application/json", **bad},
            )
            try:
                urllib.request.urlopen(no_token, timeout=5)
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
                "command": BUILTIN_SPECS["CVE-2024-6387"].mitigation[0],
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


def test_reset_lab_and_custom_target_runner(monkeypatch) -> None:
    # Hermetic: never exec into real lab containers. Discovery and DockerRunner.run are faked
    # and the reset commands are only recorded.
    import notaffected.web as web_mod

    recorded: list[tuple[str, list[str]]] = []

    def _fake_run(self: DockerRunner, argv: list[str]) -> CommandResult:
        recorded.append((self.host_name, list(argv)))
        return CommandResult(0, "", "")

    monkeypatch.setattr(
        web_mod,
        "discover_docker_containers",
        lambda: [{"name": "lab-ssh-vuln", "docker": "lab-ssh-vuln"}, {"name": "lab-win-dc01", "docker": "lab-win-dc01"}],
    )
    monkeypatch.setattr(DockerRunner, "run", _fake_run)
    monkeypatch.setattr(web_mod, "_is_lab_runner", lambda runner: True)

    _DEMO_MITIGATED.add(("prod-edge-api-01", "CVE-2024-6387"))
    res = reset_lab_and_demo()
    assert res["ok"] is True
    assert res["reset_targets"] == ["demo_fleet", "lab-ssh-vuln", "lab-win-dc01"]
    assert len(_DEMO_MITIGATED) == 0
    assert [host for host, _ in recorded] == ["lab-ssh-vuln", "lab-win-dc01"]
    assert "/etc/ssh/sshd_config" in recorded[0][1][-1]
    assert "/etc/win-sim/Spooler" in recorded[1][1][-1]

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
    spec_unknown = resolve_check_spec("CVE-9999-99999", use_llm=False, offline=True)
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
            ("apk", "info", "-e", "-v", "curl"): CommandResult(0, "curl-8.9.1-r1\n", ""),
            # The host's own comparator decides (there is no digit-list fallback any more).
            ("apk", "version", "-t", "8.9.1-r1", "8.9.0-r0"): CommandResult(0, ">\n", ""),
        },
    )
    pre_curl = Precondition(
        "package_installed_vulnerable",
        {"package": "curl", "fixed_version": "8.9.0-r0"},
        "curl check",
    )
    res_apk = run_probe(pre_curl, alpine_runner)
    assert res_apk.status == ProbeStatus.NOT_MET
    assert res_apk.command == "apk info -e -v curl"

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


def test_llm_hallucination_grounding_guards() -> None:
    from notaffected.advisories.extractor import _is_grounded_llm_precondition
    from notaffected.model import Precondition

    curl_adv = "heap buffer overflow in curl socks5 proxy handshake"
    assert not _is_grounded_llm_precondition(
        Precondition("kernel_module_loaded", {"module": "curl"}, "bad"),
        curl_adv,
        is_kernel=False,
    )
    assert not _is_grounded_llm_precondition(
        Precondition("config_contains", {"path": "/etc/curlrc", "pattern": "socks5_host"}, "bad"),
        curl_adv,
        is_kernel=False,
    )
    assert not _is_grounded_llm_precondition(
        Precondition("systemd_service_active", {"service": "curl.service"}, "bad"),
        curl_adv,
        is_kernel=False,
    )
    assert not _is_grounded_llm_precondition(
        Precondition("process_running", {"process": "msmq.exe"}, "bad"),
        "microsoft message queuing remote code execution",
        is_kernel=False,
    )
    assert _is_grounded_llm_precondition(
        Precondition("windows_service_active", {"service": "MSMQ"}, "ok"),
        "microsoft message queuing remote code execution",
        is_kernel=False,
    )
    assert _is_grounded_llm_precondition(
        Precondition("config_contains", {"path": "/etc/ssh/sshd_config", "pattern": "LoginGraceTime"}, "ok"),
        "set logingracetime 0 in /etc/ssh/sshd_config",
        is_kernel=False,
    )


def test_final_qa_security_and_invariant_fixes() -> None:
    from notaffected.advisories.extractor import _is_safe_llm_mitigation
    from notaffected.advisories.fetcher import _is_safe_public_https_url
    from notaffected.model import Precondition, ProbeStatus
    from notaffected.probes.primitives import run_probe

    # 1. Strict LLM mitigation allowlist blocks prompt injection
    assert not _is_safe_llm_mitigation("sudo rm -rf /", is_kernel=False)
    assert not _is_safe_llm_mitigation("echo pwned > /etc/passwd", is_kernel=False)
    assert not _is_safe_llm_mitigation("sudo modprobe -r curl", is_kernel=False)
    assert _is_safe_llm_mitigation("sudo modprobe -r nf_tables", is_kernel=True)
    assert _is_safe_llm_mitigation("Stop-Service -Name MSMQ -Force", is_kernel=False)

    # 2. SSRF URL guard blocks alternate IP encodings and .internal metadata hosts
    assert not _is_safe_public_https_url("https://0x7f000001/")
    assert not _is_safe_public_https_url("https://2130706433/")
    assert not _is_safe_public_https_url("https://127.1/")
    assert not _is_safe_public_https_url("https://metadata.google.internal/")

    # 3. apk version -t transport error returns UNKNOWN (never NOT_MET)
    alpine_err = MockRunner(
        host_name="alpine-err",
        responses={
            ("apk", "info", "-e", "-v", "busybox"): CommandResult(0, "busybox-1.36.1-r29\n", ""),
            ("apk", "version", "-t", "1.36.1-r29", "0.0.1-r0"): CommandResult(
                255, "", "connection reset", transport_error=True
            ),
        },
    )
    res_err = run_probe(
        Precondition("package_installed_vulnerable", {"package": "busybox", "fixed_version": "0.0.1-r0"}, "bb"),
        alpine_err,
    )
    assert res_err.status == ProbeStatus.UNKNOWN

    # 4. Web API scanner_json rejects local file paths as string payload
    res_path = evaluate_dashboard_request(
        {
            "target_mode": "demo_fleet",
            "scan_mode": "scanner_json",
            "scanner_report": "examples/trivy-scan.json",
            "offline": True,
        }
    )
    assert "Invalid scanner JSON report" in res_path["feed_meta"].get("error", "")










def test_mitigation_runs_only_on_lab_containers_with_the_confirmed_command(monkeypatch) -> None:
    import notaffected.web as web_mod

    executed: list[tuple[str, list[str]]] = []

    class _Rec(LocalRunner):
        def run(self, argv):
            executed.append((self.host_name, list(argv)))
            return CommandResult(0, "", "")

    cmd0 = BUILTIN_SPECS["CVE-2024-6387"].mitigation[0]
    for runner in (_Rec(host_name="laptop"), SSHRunner(target="root@203.0.113.10")):
        monkeypatch.setattr(web_mod, "_build_runners_for_mode", lambda *a, _r=runner, **k: [_r])
        res = apply_host_mitigation(
            {"target_mode": "local", "host": runner.host_name, "cve_id": "CVE-2024-6387", "mitigation_index": 0, "command": cmd0}
        )
        assert res["ok"] is False and "lab containers" in res["error"]
    assert executed == []

    lab = DockerRunner(container="lab-ssh-vuln", host_name="lab-ssh-vuln")
    monkeypatch.setattr(web_mod, "_build_runners_for_mode", lambda *a, **k: [lab])
    monkeypatch.setattr(DockerRunner, "run", lambda self, argv: executed.append((self.host_name, list(argv))) or CommandResult(0, "", ""))
    monkeypatch.setattr(
        web_mod.subprocess,
        "run",
        lambda argv, **k: type("P", (), {"returncode": 0, "stdout": "true\n", "stderr": ""})(),
    )
    base = {"target_mode": "docker_discovered", "host": "lab-ssh-vuln", "cve_id": "CVE-2024-6387", "mitigation_index": 0}
    # the command shown to the user must be the one the server would run
    assert apply_host_mitigation(dict(base, command="echo something else"))["ok"] is False
    assert executed == []
    assert apply_host_mitigation(dict(base, command=cmd0))["ok"] is True
    assert executed and executed[0][0] == "lab-ssh-vuln"


def test_ui_refuses_non_loopback_bind_without_opt_in(monkeypatch) -> None:
    import pytest

    import notaffected.web as web_mod

    def _no_server(*_a, **_k):
        raise AssertionError("a server must never start in this test")

    # A regression must fail fast here, never bind 0.0.0.0 and block the suite.
    monkeypatch.setattr(web_mod, "ThreadingHTTPServer", _no_server)
    with pytest.raises(SystemExit, match="allow-remote"):
        web_mod.run_web_server(host="0.0.0.0", port=0)


def test_unlabelled_container_is_not_a_lab_runner(monkeypatch) -> None:
    import notaffected.web as web_mod

    monkeypatch.setattr(
        web_mod.subprocess,
        "run",
        lambda argv, **k: type("P", (), {"returncode": 0, "stdout": "<no value>\n", "stderr": ""})(),
    )
    assert web_mod._is_lab_runner(DockerRunner(container="prod-api")) is False
    assert web_mod._is_lab_runner(DockerRunner(container="-oops")) is False


def test_security_review_hardening_regressions(monkeypatch) -> None:
    import pytest

    import notaffected.advisories.fetcher as fetcher_mod
    import notaffected.web as web_mod

    # 1) scanner_json rejects JSON-encoded strings (cannot hit Path(data).is_file())
    res = evaluate_dashboard_request(
        {
            "target_mode": "demo_fleet",
            "scan_mode": "scanner_json",
            "scanner_report": '"/etc/passwd"',
            "offline": True,
        }
    )
    assert "Expected JSON object" in str(res.get("feed_meta", {}).get("error") or "")

    # 2) SSRF helper fails closed on DNS OSError
    def _dns_fail(*_a, **_k):
        raise OSError("temporary failure in name resolution")

    monkeypatch.setattr(fetcher_mod.socket, "getaddrinfo", _dns_fail)
    assert fetcher_mod._is_safe_public_https_url("https://unresolvable.example.invalid/advisory") is False

    # 3) --allow-remote requires NOTAFFECTED_REMOTE_TOKEN (>= 16 chars)
    monkeypatch.delenv("NOTAFFECTED_REMOTE_TOKEN", raising=False)
    with pytest.raises(SystemExit, match="NOTAFFECTED_REMOTE_TOKEN"):
        web_mod.check_bind_address("0.0.0.0", allow_remote=True)
    monkeypatch.setenv("NOTAFFECTED_REMOTE_TOKEN", "short")
    with pytest.raises(SystemExit, match="NOTAFFECTED_REMOTE_TOKEN"):
        web_mod.check_bind_address("0.0.0.0", allow_remote=True)
    monkeypatch.setenv("NOTAFFECTED_REMOTE_TOKEN", "a-strong-remote-token-123456")
    web_mod.check_bind_address("0.0.0.0", allow_remote=True)


def test_live_qa_round3_regressions(tmp_path) -> None:
    import urllib.error
    import urllib.request

    import notaffected.web as web_mod
    from notaffected import cli
    from notaffected.advisories.fetcher import _write_json_atomic
    from notaffected.model import Precondition, ProbeStatus
    from notaffected.probes.primitives import run_probe

    # 1) --offline supported on check, filter, and spec
    assert cli.main(["spec", "CVE-2024-99999", "--offline"]) == 0
    assert cli.main(["check", "CVE-2024-6387", "--demo-fleet", "--offline"]) == 0
    assert cli.main(["filter", "examples/trivy-scan.json", "--demo-fleet", "--offline"]) == 0

    # 2) kernel_module_loaded rejects leading '-'
    res_mod = run_probe(Precondition("kernel_module_loaded", {"module": "-foo"}, "bad mod"), MockRunner("h", {}))
    assert res_mod.status == ProbeStatus.UNKNOWN

    # 3) scanner_report {} or [] never silently falls back to examples/trivy-scan.json
    res_arr = evaluate_dashboard_request(
        {"target_mode": "demo_fleet", "scan_mode": "scanner_json", "scanner_report": [], "offline": True}
    )
    assert "Expected JSON object" in str(res_arr.get("feed_meta", {}).get("error") or "")
    res_empty = evaluate_dashboard_request(
        {"target_mode": "demo_fleet", "scan_mode": "scanner_json", "scanner_report": {}, "offline": True}
    )
    assert res_empty["summary"]["cves_evaluated"] == 0

    # 4) atomic cache write produces valid JSON
    p = tmp_path / "atomic.json"
    _write_json_atomic(p, {"ok": True})
    assert p.is_file()

    # 5) remote_mode requires X-Notaffected-Token on GET /api/targets & /api/spec
    class _RemoteHandler(web_mod.DashboardRequestHandler):
        remote_mode = True
        request_token = "remote-secret-token-1234567890"

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _RemoteHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        for path in ("/api/targets", "/api/spec?cve=CVE-2024-6387"):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5)
                raise AssertionError(f"Expected 403 for unauthenticated {path}")
            except urllib.error.HTTPError as exc:
                assert exc.code == 403
        req_ok = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/targets",
            headers={"X-Notaffected-Token": "remote-secret-token-1234567890"},
        )
        with urllib.request.urlopen(req_ok, timeout=5) as resp:
            assert resp.status == 200
    finally:
        srv.shutdown()
        srv.server_close()
