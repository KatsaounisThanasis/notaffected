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



