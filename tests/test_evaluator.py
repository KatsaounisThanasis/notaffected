"""Tests for the three-valued evaluation engine (Task 3)."""

from notaffected.engine.evaluator import evaluate_fleet, evaluate_host
from notaffected.model import (
    CheckSpec,
    PatchInfo,
    Precondition,
    VerdictStatus,
    VexJustification,
)
from notaffected.probes.primitives import WIN_BUILD_ARGV
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
    win_runner = MockRunner(
        host_name="win-srv-01",
        responses={tuple(WIN_BUILD_ARGV): CommandResult(0, "BUILD=20348.1|KBS=\n", "")},
        os_family="windows",
    )
    verdict = evaluate_host(linux_spec, win_runner)
    assert verdict.status == VerdictStatus.NOT_AFFECTED
    assert verdict.justification == VexJustification.COMPONENT_NOT_PRESENT
    assert "windows" in verdict.reason.lower()
    assert verdict.product_id == "pkg:generic/windows-host@win-srv-01"
    assert verdict.probe_results == []



def test_os_mismatch_needs_probe_confirmation_and_non_heuristic_os_source():
    linux_spec = _make_cve_spec()
    # Unconfirmed: the declared Windows host does not answer the Windows build probe
    # (e.g. a Linux container named "app-win-gateway" declared Windows by its name).
    fake_win = MockRunner(host_name="app-win-gateway", responses={}, os_family="windows")
    v = evaluate_host(linux_spec, fake_win)
    assert v.status == VerdictStatus.UNDER_INVESTIGATION
    assert "could not be confirmed" in v.reason

    # Heuristic OS source never short-circuits, even on a confirmed host.
    win_spec = CheckSpec(cve_id="CVE-2026-0002", summary="s", os_family="windows", os_source="heuristic")
    linux_host = MockRunner(
        host_name="lin-01", responses={("uname", "-s"): CommandResult(0, "Linux\n", "")}, os_family="linux"
    )
    v = evaluate_host(win_spec, linux_host)
    assert v.status == VerdictStatus.UNDER_INVESTIGATION
    assert "heuristics" in v.reason

    # Structured OS source + confirmed host keeps the short-circuit.
    win_spec.os_source = "structured"
    assert evaluate_host(win_spec, linux_host).status == VerdictStatus.NOT_AFFECTED


def test_not_met_from_non_authoritative_origin_is_not_proof():
    def spec_with(origin: str) -> CheckSpec:
        return CheckSpec(
            cve_id="CVE-2026-0003",
            summary="s",
            preconditions=[
                Precondition("sysctl_equals", {"key": "net.x", "value": "1"}, "x on", origin=origin),
            ],
        )

    runner = MockRunner(host_name="h", responses={("sysctl", "-n", "net.x"): CommandResult(0, "0\n", "")})
    for origin in ("llm", "heuristic"):
        v = evaluate_host(spec_with(origin), runner)
        assert v.status == VerdictStatus.UNDER_INVESTIGATION, origin
        assert v.reason.startswith("Only heuristic/LLM-proposed checks were NOT_MET")
    for origin in ("curated", "osv", "scanner"):
        assert evaluate_host(spec_with(origin), runner).status == VerdictStatus.NOT_AFFECTED, origin


def test_windows_confirmation_needs_a_real_build_number():
    spec = _make_cve_spec()
    empty_build = MockRunner(
        host_name="app-win-gateway",
        responses={tuple(WIN_BUILD_ARGV): CommandResult(0, "BUILD=.|KBS=\n", "")},
        os_family="windows",
    )
    assert evaluate_host(spec, empty_build).status == VerdictStatus.UNDER_INVESTIGATION


def test_fleet_with_duplicate_host_names_is_refused():
    import pytest

    spec = _make_cve_spec()
    with pytest.raises(ValueError, match="web"):
        evaluate_fleet([spec], [MockRunner("web", {}), MockRunner("web", {})])
