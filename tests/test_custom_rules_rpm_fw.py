"""Tests for custom YAML CheckSpec rules (`--rules`), native RPM EVR comparison,
RHEL/Rocky/Alma release matching, `firewalld`/`nftables` fallbacks, and the
unified standalone HTML audit report.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from notaffected.advisories.builtin_specs import BUILTIN_SPECS
from notaffected.advisories.custom_rules import load_custom_rules
from notaffected.advisories.extractor import extract_from_osv_payload, resolve_check_spec
from notaffected.advisories.live_feed import collect_scan_specs
from notaffected.cli import main
from notaffected.model import HostVerdict, Precondition, ProbeStatus, VerdictStatus, VexJustification
from notaffected.probes.primitives import _rpm_evr_lt, _rpmvercmp, run_probe
from notaffected.probes.runner import CommandResult, MockRunner
from notaffected.render.html import build_html_report

# ---------------------------------------------------------------------------
# 1. Custom YAML CheckSpec Rules (`--rules`)
# ---------------------------------------------------------------------------


def test_load_custom_rules_example_file_and_dir(tmp_path: Path) -> None:
    example = Path(__file__).resolve().parent.parent / "examples" / "custom-rule.yaml"
    rules = load_custom_rules([example])
    assert "CVE-2026-40123" in rules
    spec = rules["CVE-2026-40123"]
    assert spec.source == "custom-yaml"
    assert spec.os_source == "curated"
    assert spec.os_family == "linux"
    assert len(spec.preconditions) == 3
    assert all(p.origin == "curated" for p in spec.preconditions)

    # Directory loading + override precedence (b.yml overrides a.yaml)
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "a.yaml").write_text(
        """
cve_id: CVE-2024-6387
summary: "Override built-in OpenSSH check"
severity: CRITICAL
preconditions:
  - probe: process_running
    params:
      process: sshd
    description: "sshd running"
""",
        encoding="utf-8",
    )
    (rules_dir / "b.yml").write_text(
        """
- cve_id: CVE-2024-6387
  summary: "Second override wins"
  severity: HIGH
  preconditions:
    - probe: systemd_service_active
      params:
        service: ssh.service
- cve_id: INTERNAL-2026-001
  summary: "Windows Spooler policy check"
  os_family: windows
  preconditions:
    - probe: windows_service_active
      params:
        service: Spooler
""",
        encoding="utf-8",
    )

    loaded = load_custom_rules([rules_dir])
    assert loaded["CVE-2024-6387"].summary == "Second override wins"
    assert loaded["CVE-2024-6387"].severity == "HIGH"
    assert loaded["INTERNAL-2026-001"].os_family == "windows"

    # resolve_check_spec prioritizes custom rules over BUILTIN_SPECS
    resolved = resolve_check_spec("CVE-2024-6387", offline=True, custom_rules=loaded)
    assert resolved.source == "custom-yaml"
    assert resolved.summary == "Second override wins"

    # collect_scan_specs merges custom rules into scan
    specs, meta = collect_scan_specs([MockRunner("h", {})], offline=True, custom_rules=loaded)
    assert meta["custom_count"] == 2
    by_id = {s.cve_id: s for s in specs}
    assert by_id["CVE-2024-6387"].source == "custom-yaml"
    assert "INTERNAL-2026-001" in by_id


@pytest.mark.parametrize(
    ("yaml_body", "err_match"),
    [
        ("cve_id: CVE-2026-1\nsummary: x\npreconditions: []\n", "non-empty list"),
        (
            "cve_id: CVE-2026-1\nsummary: x\npreconditions:\n  - probe: exec_shell\n    params: {cmd: id}\n",
            "unsupported probe",
        ),
        (
            "cve_id: CVE-2026-1\nsummary: x\nos_family: linux\npreconditions:\n  - probe: windows_service_active\n    params: {service: Spooler}\n",
            "not valid for os_family",
        ),
        (
            "cve_id: CVE-2026-1\nsummary: x\npreconditions:\n  - probe: network_listener\n    params: {proto: tcp, bogus_param: 1}\n",
            "unknown parameter",
        ),
        (
            "cve_id: CVE-2026-1\nsummary: x\npreconditions:\n  - probe: sysctl_equals\n    params: {key: net.ipv4.ip_forward}\n",
            "missing required parameter",
        ),
        (
            "cve_id: CVE-2026-1\nsummary: x\npreconditions:\n  - probe: process_running\n    params: {process: nginx}\n    justification_if_not_met: made_up_reason\n",
            "justification_if_not_met",
        ),
    ],
)
def test_load_custom_rules_rejects_invalid_schema(tmp_path: Path, yaml_body: str, err_match: str) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml_body, encoding="utf-8")
    with pytest.raises(ValueError, match=err_match):
        load_custom_rules([bad])


def test_cli_rules_flag_e2e_and_error_exit(tmp_path: Path) -> None:
    example = Path(__file__).resolve().parent.parent / "examples" / "custom-rule.yaml"
    assert main(["spec", "CVE-2026-40123", "--offline", "--rules", str(example)]) == 0
    assert (
        main(["check", "CVE-2026-40123", "--demo-fleet", "--offline", "--rules", str(example)])
        == 0
    )
    assert main(["scan", "--demo-fleet", "--offline", "--rules", str(example)]) == 0
    # Missing rules path fails fast with exit code 2
    assert main(["spec", "CVE-2026-40123", "--rules", str(tmp_path / "missing.yaml")]) == 2
    assert main(["check", "CVE-2026-40123", "--demo-fleet", "--rules", str(tmp_path / "missing.yaml")]) == 2
    assert main(["ui", "--rules", str(tmp_path / "missing.yaml")]) == 2


def test_web_dashboard_custom_rules_integration() -> None:
    from notaffected.web import evaluate_dashboard_request, get_targets_metadata

    example = Path(__file__).resolve().parent.parent / "examples" / "custom-rule.yaml"
    rules = load_custom_rules([example])

    meta = get_targets_metadata(custom_rules=rules)
    assert meta["custom_rules_count"] == 1

    res = evaluate_dashboard_request(
        {
            "target_mode": "demo_fleet",
            "scan_mode": "live_scan",
            "offline": True,
        },
        custom_rules=rules,
    )
    assert res["feed_meta"]["custom_count"] == 1
    assert res["summary"]["cves_evaluated"] == len(BUILTIN_SPECS) + 1
    assert any(s["cve_id"] == "CVE-2026-40123" and s["source"] == "custom-yaml" for s in res["specs"])


# ---------------------------------------------------------------------------
# 2. Native RPM EVR Comparison + RHEL/Rocky/Alma Release Matching
# ---------------------------------------------------------------------------


def test_rpmvercmp_and_evr_edge_cases() -> None:
    assert _rpmvercmp("1.0", "1.0") == 0
    assert _rpmvercmp("1.0.2", "1.0.10") == -1
    assert _rpmvercmp("1.001", "1.1") == 0
    assert _rpmvercmp("1.0~rc1", "1.0") == -1
    assert _rpmvercmp("1.0~beta1", "1.0~rc1") == -1
    assert _rpmvercmp("1.0^git2024", "1.0") == 1
    assert _rpmvercmp("1.0^git2024", "1.0.1") == -1
    assert _rpmvercmp("8.7p1", "8.7p1") == 0
    assert _rpmvercmp("38.el9_4.1", "38.el9_4.4") == -1

    # EVR comparisons
    assert _rpm_evr_lt("0:8.7p1-38.el9_4.1", "0:8.7p1-38.el9_4.4") is True
    assert _rpm_evr_lt("0:8.7p1-38.el9_4.4", "0:8.7p1-38.el9_4.4") is False
    assert _rpm_evr_lt("0:8.7p1-38.el9_4.5", "0:8.7p1-38.el9_4.4") is False
    assert _rpm_evr_lt("0:9.9-1.el9", "1:1.0-1.el9") is True
    assert _rpm_evr_lt("1:1.0-1.el9", "0:9.9-1.el9") is False
    assert _rpm_evr_lt("8.7p1-38.el9_4.1", "0:8.7p1-38.el9_4.4") is True
    # Missing installed epoch vs non-zero fixed epoch -> None (safe UNKNOWN)
    assert _rpm_evr_lt("8.7p1-38.el9_4.1", "1:8.7p1-38.el9_4.4") is None
    # Cross-distro Ubuntu/Debian/Alpine fix strings are refused on RPM
    assert _rpm_evr_lt("0:8.7p1-38.el9", "1:9.6p1-3ubuntu13.3") is None
    assert _rpm_evr_lt("0:3.0.7-24.el9", "3.0.11-1~deb12u2") is None
    assert _rpm_evr_lt("0:8.9.1-1.el9", "8.9.1-r1") is None


def test_rpm_package_probe_native_evr_and_rocky_release_matching() -> None:
    osv_rhel = {
        "id": "CVE-2024-6387",
        "summary": "OpenSSH regreSSHion on RHEL 9",
        "affected": [
            {
                "package": {"ecosystem": "Red Hat:9", "name": "openssh-server"},
                "ranges": [{"events": [{"fixed": "0:8.7p1-38.el9_4.4"}]}],
            }
        ],
    }
    spec = extract_from_osv_payload("CVE-2024-6387", osv_rhel)
    pre = spec.preconditions[0]
    assert pre.params["release_fixes"]["rhel:9"] == "0:8.7p1-38.el9_4.4"

    # Vulnerable Rocky Linux 9.4 host matches rhel:9 release fix and compares EVR natively
    rocky_vuln = MockRunner(
        "rocky9-vuln",
        {
            ("rpm", "-q", "--qf", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n", "openssh-server"): CommandResult(
                0, "0:8.7p1-38.el9_4.1\n", ""
            ),
            ("cat", "/etc/os-release"): CommandResult(0, 'ID="rocky"\nVERSION_ID="9.4"\n', ""),
        },
    )
    res_vuln = run_probe(pre, rocky_vuln)
    assert res_vuln.status == ProbeStatus.MET
    assert res_vuln.facts["purl_type"] == "rpm"
    assert res_vuln.facts["epoch"] == ""  # epoch 0 omitted from PURL

    # Patched RHEL 9.4 host -> NOT_MET
    rhel_patched = MockRunner(
        "rhel9-patched",
        {
            ("rpm", "-q", "--qf", "%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n", "openssh-server"): CommandResult(
                0, "0:8.7p1-38.el9_4.4\n", ""
            ),
            ("cat", "/etc/os-release"): CommandResult(0, 'ID="rhel"\nVERSION_ID="9.4"\n', ""),
        },
    )
    res_patched = run_probe(pre, rhel_patched)
    assert res_patched.status == ProbeStatus.NOT_MET


# ---------------------------------------------------------------------------
# 3. `firewalld` & `nftables` Fallbacks in `firewall_allows_port`
# ---------------------------------------------------------------------------


def _fwd_runner(list_all_out: str, docker0: bool = False) -> MockRunner:
    return MockRunner(
        "rhel-fw",
        {
            ("firewall-cmd", "--state"): CommandResult(0, "running\n", ""),
            ("firewall-cmd", "--list-all"): CommandResult(0, list_all_out, ""),
            ("ip", "-o", "link", "show", "docker0"): (
                CommandResult(0, "4: docker0: <BROADCAST>\n", "") if docker0 else CommandResult(1, "", "")
            ),
        },
    )


def test_firewalld_fallback_probe() -> None:
    zone_ssh_only = (
        "public (active)\n"
        "  target: default\n"
        "  services: ssh dhcpv6-client\n"
        "  ports: 8443/tcp\n"
        "  protocols:\n"
        "  forward-ports:\n"
        "  rich rules:\n"
    )
    pre_22 = Precondition("firewall_allows_port", {"port": "22", "proto": "tcp"}, "ssh")
    pre_631 = Precondition("firewall_allows_port", {"port": "631", "proto": "udp"}, "cups")
    pre_8443 = Precondition("firewall_allows_port", {"port": "8443", "proto": "tcp"}, "https-alt")

    assert run_probe(pre_22, _fwd_runner(zone_ssh_only)).status == ProbeStatus.MET
    assert run_probe(pre_8443, _fwd_runner(zone_ssh_only)).status == ProbeStatus.MET
    assert run_probe(pre_631, _fwd_runner(zone_ssh_only)).status == ProbeStatus.NOT_MET
    # Docker bridge present -> fail-closed UNKNOWN
    assert run_probe(pre_631, _fwd_runner(zone_ssh_only, docker0=True)).status == ProbeStatus.UNKNOWN

    # Unknown custom service or rich rules -> fail-closed UNKNOWN
    zone_rich = zone_ssh_only + '  rich rules:\n    rule family="ipv4" port port="631" protocol="udp" accept\n'
    assert run_probe(pre_631, _fwd_runner(zone_rich)).status == ProbeStatus.UNKNOWN

    zone_custom_svc = zone_ssh_only.replace("services: ssh dhcpv6-client", "services: ssh corp-internal")
    assert run_probe(pre_631, _fwd_runner(zone_custom_svc)).status == ProbeStatus.UNKNOWN

    zone_accept = zone_ssh_only.replace("target: default", "target: ACCEPT")
    assert run_probe(pre_631, _fwd_runner(zone_accept)).status == ProbeStatus.MET


def test_nftables_fallback_probe() -> None:
    nft_drop = (
        "table inet filter {\n"
        "    chain input {\n"
        "        type filter hook input priority 0; policy drop;\n"
        '        iifname "lo" accept\n'
        "        ct state established,related accept\n"
        "        tcp dport { 22, 443 } accept\n"
        "    }\n"
        "}\n"
    )

    def _nft(ruleset: str, docker0: bool = False) -> MockRunner:
        return MockRunner(
            "nft-host",
            {
                ("nft", "list", "ruleset"): CommandResult(0, ruleset, ""),
                ("ip", "-o", "link", "show", "docker0"): (
                    CommandResult(0, "4: docker0: <BROADCAST>\n", "") if docker0 else CommandResult(1, "", "")
                ),
            },
        )

    pre_443 = Precondition("firewall_allows_port", {"port": "443", "proto": "tcp"}, "https")
    pre_6379 = Precondition("firewall_allows_port", {"port": "6379", "proto": "tcp"}, "redis")

    assert run_probe(pre_443, _nft(nft_drop)).status == ProbeStatus.MET
    assert run_probe(pre_6379, _nft(nft_drop)).status == ProbeStatus.NOT_MET
    assert run_probe(pre_6379, _nft(nft_drop, docker0=True)).status == ProbeStatus.UNKNOWN

    # Jump to subchain -> fail-closed UNKNOWN
    nft_jump = nft_drop.replace("tcp dport { 22, 443 } accept", "jump custom_in")
    assert run_probe(pre_6379, _nft(nft_jump)).status == ProbeStatus.UNKNOWN

    # Source-restricted accept -> fail-closed UNKNOWN
    nft_src = nft_drop.replace(
        "tcp dport { 22, 443 } accept", "ip saddr 10.0.0.0/8 tcp dport 6379 accept"
    )
    assert run_probe(pre_6379, _nft(nft_src)).status == ProbeStatus.UNKNOWN

    # Policy accept -> MET
    nft_open = nft_drop.replace("policy drop;", "policy accept;")
    assert run_probe(pre_6379, _nft(nft_open)).status == ProbeStatus.MET


# ---------------------------------------------------------------------------
# 4. Unified Dark Standalone HTML Report
# ---------------------------------------------------------------------------


def test_standalone_html_report_matches_dark_ui_and_escapes_xss() -> None:
    spec = BUILTIN_SPECS["CVE-2024-6387"]
    verdicts = [
        HostVerdict(
            host="edge-01",
            cve_id="CVE-2024-6387",
            status=VerdictStatus.AFFECTED,
            reason="All preconditions met",
            justification=None,
            mitigation=spec.mitigation,
            patch=spec.patch,
        ),
        HostVerdict(
            host="safe-01",
            cve_id="CVE-2024-6387",
            status=VerdictStatus.NOT_AFFECTED,
            reason="LoginGraceTime 0 active",
            justification=VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
            patch=spec.patch,
        ),
        HostVerdict(
            host='evil"<script>alert(1)</script>',
            cve_id="CVE-2024-6387",
            status=VerdictStatus.UNDER_INVESTIGATION,
            reason="<b>probe error</b>",
            justification=None,
        ),
    ]
    doc = build_html_report([spec], verdicts)
    assert 'data-theme="dark"' in doc
    assert "#09090b" in doc
    assert "#f08a59" in doc
    assert "toggleTheme()" in doc
    assert "False-Positive Noise Cut" in doc
    assert "Verdict Split" in doc
    # F-pattern column order: Verdict before CVE ID before Host
    assert doc.index("<th>Verdict</th>") < doc.index("<th>CVE ID</th>") < doc.index("<th>Host</th>")
    # Zero external CDN links and strict escaping
    assert "https://cdn." not in doc
    assert "<script>alert(1)</script>" not in doc
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in doc
    assert "&lt;b&gt;probe error&lt;/b&gt;" in doc
