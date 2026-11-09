"""Tests for the three-valued evaluation engine (Task 3)."""

from notaffected.engine.evaluator import evaluate_fleet, evaluate_host
from notaffected.model import (
    CheckSpec,
    PatchInfo,
    Precondition,
    VerdictStatus,
    VexJustification,
)
from notaffected.probes.runner import CommandResult, MockRunner


def _make_cve_spec(confidence: str = "high") -> CheckSpec:
    return CheckSpec(
        cve_id="CVE-2026-98432",
        summary="Linux kernel IPv4 TCP/MPTCP race condition",
        severity="CRITICAL",
        preconditions=[
            Precondition(
                probe="kernel_version_vulnerable",
                params={"fixed_version": "6.8.0-45"},
                description="Running kernel < 6.8.0-45",
                justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_PRESENT,
            ),
            Precondition(
                probe="network_listener",
                params={"proto": "tcp", "scope": "non_loopback"},
                description="Non-loopback TCP listener active",
                justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            ),
            Precondition(
                probe="firewall_allows_port",
                params={"port": "any", "proto": "tcp"},
                description="Host firewall allows incoming TCP traffic",
                justification_if_not_met=VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
            ),
        ],
        mitigation=["sudo ufw default deny incoming"],
        patch=PatchInfo(status="staged", fixed_version="6.8.0-45", pocket="noble-proposed"),
        confidence=confidence,
        source="builtin",
    )


def test_not_affected_when_any_precondition_is_not_met():
    spec = _make_cve_spec()
    # Host has vulnerable kernel, but only loopback listeners and active deny firewall
    runner = MockRunner(
        host_name="laptop-01",
        responses={
            ("uname", "-r"): CommandResult(0, "6.8.0-40-generic\n", ""),
            ("dpkg", "--compare-versions", "6.8.0-40", "lt", "6.8.0-45"): CommandResult(0, "", ""),
            ("ss", "-tulpnH"): CommandResult(0, "tcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*\n", ""),
            ("ufw", "status", "verbose"): CommandResult(
                0, "Status: active\nDefault: deny (incoming), allow (outgoing)\n", ""
            ),
        },
    )
    verdict = evaluate_host(spec, runner)
    assert verdict.status == VerdictStatus.NOT_AFFECTED
    assert verdict.justification == VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
    assert "loopback" in verdict.reason.lower()
    assert verdict.mitigation == []


def test_affected_when_all_preconditions_met_and_high_confidence():
    spec = _make_cve_spec()
    runner = MockRunner(
        host_name="edge-01",
        responses={
            ("uname", "-r"): CommandResult(0, "6.8.0-40-generic\n", ""),
            ("dpkg", "--compare-versions", "6.8.0-40", "lt", "6.8.0-45"): CommandResult(0, "", ""),
            ("ss", "-tulpnH"): CommandResult(0, "tcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:*\n", ""),
            ("ufw", "status", "verbose"): CommandResult(0, "Status: inactive\n", ""),
        },
    )
    verdict = evaluate_host(spec, runner)
    assert verdict.status == VerdictStatus.AFFECTED
    assert verdict.justification is None
    assert verdict.mitigation == ["sudo ufw default deny incoming"]
    assert verdict.patch is not None
    assert verdict.patch.pocket == "noble-proposed"


def test_probe_unknown_never_produces_not_affected():
    spec = _make_cve_spec()
    # Vulnerable kernel, exposed listener, but firewall check fails due to non-root permissions
    runner = MockRunner(
        host_name="unpriv-srv",
        responses={
            ("uname", "-r"): CommandResult(0, "6.8.0-40-generic\n", ""),
            ("dpkg", "--compare-versions", "6.8.0-40", "lt", "6.8.0-45"): CommandResult(0, "", ""),
            ("ss", "-tulpnH"): CommandResult(0, "tcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:*\n", ""),
            ("ufw", "status", "verbose"): CommandResult(1, "", "ERROR: You need to be root"),
            ("ufw", "status"): CommandResult(1, "", "ERROR: You need to be root"),
        },
    )
    verdict = evaluate_host(spec, runner)
    assert verdict.status == VerdictStatus.UNDER_INVESTIGATION
    assert verdict.justification is None
    assert "root" in verdict.reason.lower() or "could not verify" in verdict.reason.lower()


def test_low_confidence_spec_yields_under_investigation_when_version_matches():
    spec = CheckSpec(
        cve_id="CVE-2026-00001",
        summary="Vague advisory with only package version range",
        severity="HIGH",
        preconditions=[
            Precondition(
                probe="package_installed_vulnerable",
                params={"package": "openssl", "fixed_version": "3.0.15-1"},
                description="openssl < 3.0.15-1",
                justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_PRESENT,
            )
        ],
        mitigation=[],
        patch=PatchInfo(status="released", fixed_version="3.0.15-1"),
        confidence="low",
        source="osv",
    )
    runner = MockRunner(
        host_name="app-01",
        responses={
            ("dpkg-query", "-W", "-f=${db:Status-Abbrev}\\t${Version}\\n", "openssl"): CommandResult(
                0, "ii \t3.0.13-1ubuntu3\n", ""
            ),
            ("dpkg", "--compare-versions", "3.0.13-1ubuntu3", "lt", "3.0.15-1"): CommandResult(0, "", ""),
        },
    )
    verdict = evaluate_host(spec, runner)
    assert verdict.status == VerdictStatus.UNDER_INVESTIGATION

    # However, if openssl is already patched, even a low-confidence spec proves NOT_AFFECTED!
    runner_patched = MockRunner(
        host_name="app-02",
        responses={
            ("dpkg-query", "-W", "-f=${db:Status-Abbrev}\\t${Version}\\n", "openssl"): CommandResult(
                0, "ii \t3.0.15-1ubuntu1\n", ""
            ),
            ("dpkg", "--compare-versions", "3.0.15-1ubuntu1", "lt", "3.0.15-1"): CommandResult(1, "", ""),
        },
    )
    verdict_patched = evaluate_host(spec, runner_patched)
    assert verdict_patched.status == VerdictStatus.NOT_AFFECTED
    assert verdict_patched.justification == VexJustification.VULNERABLE_CODE_NOT_PRESENT


def test_evaluate_fleet_preserves_order():
    spec = _make_cve_spec()
    r1 = MockRunner(
        host_name="patched-01",
        responses={
            ("uname", "-r"): CommandResult(0, "6.8.0-48-generic\n", ""),
            ("dpkg", "--compare-versions", "6.8.0-48", "lt", "6.8.0-45"): CommandResult(1, "", ""),
            ("ss", "-tulpnH"): CommandResult(0, "", ""),
            ("ufw", "status", "verbose"): CommandResult(0, "Status: inactive\n", ""),
        },
    )
    verdicts = evaluate_fleet([spec], [r1])
    assert len(verdicts) == 1
    assert verdicts[0].status == VerdictStatus.NOT_AFFECTED


def test_os_mismatch_short_circuits_to_not_affected():
    linux_spec = _make_cve_spec()
    assert linux_spec.os_family == "linux"
    win_runner = MockRunner(host_name="win-srv-01", responses={}, os_family="windows")
    verdict = evaluate_host(linux_spec, win_runner)
    assert verdict.status == VerdictStatus.NOT_AFFECTED
    assert verdict.justification == VexJustification.COMPONENT_NOT_PRESENT
    assert "windows" in verdict.reason.lower()
    assert verdict.product_id == "pkg:generic/windows-host@win-srv-01"
    assert verdict.probe_results == []

