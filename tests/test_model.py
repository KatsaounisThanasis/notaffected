"""Tests for core domain models and probe type validation (Task 1)."""

import pytest

from notaffected.model import (
    PROBE_TYPES,
    CheckSpec,
    HostVerdict,
    PatchInfo,
    Precondition,
    ProbeResult,
    ProbeStatus,
    VerdictStatus,
    VexJustification,
)


def test_probe_types_closed_set():
    expected = {
        "kernel_version_vulnerable",
        "package_installed_vulnerable",
        "kernel_module_loaded",
        "sysctl_equals",
        "network_listener",
        "firewall_allows_port",
        "systemd_service_active",
        "process_running",
        "config_contains",
    }
    assert PROBE_TYPES == expected


def test_precondition_rejects_unknown_probe_type():
    with pytest.raises(ValueError, match="Unsupported probe type"):
        Precondition(
            probe="arbitrary_bash_command",
            params={"cmd": "rm -rf /"},
            description="Should fail",
            justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
        )


def test_check_spec_round_trip():
    spec = CheckSpec(
        cve_id="CVE-2026-98432",
        summary="Linux kernel IPv4 TCP/MPTCP race condition",
        severity="CRITICAL",
        preconditions=[
            Precondition(
                probe="kernel_version_vulnerable",
                params={"fixed_version": "6.8.0-45"},
                description="Running kernel is older than 6.8.0-45",
                justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_PRESENT,
            ),
            Precondition(
                probe="network_listener",
                params={"proto": "tcp", "scope": "non_loopback"},
                description="TCP service listening on non-loopback address",
                justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            ),
        ],
        mitigation=["sudo ufw default deny incoming"],
        patch=PatchInfo(
            status="staged",
            fixed_version="6.8.0-45.45",
            pocket="noble-proposed",
            advisory_url="https://ubuntu.com/security/CVE-2026-98432",
        ),
        confidence="high",
        source="builtin",
    )
    serialized = spec.to_dict()
    restored = CheckSpec.from_dict(serialized)
    assert restored.cve_id == "CVE-2026-98432"
    assert len(restored.preconditions) == 2
    assert restored.preconditions[1].justification_if_not_met == VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
    assert restored.patch.pocket == "noble-proposed"


def test_host_verdict_serialization():
    pre = Precondition(
        probe="kernel_module_loaded",
        params={"module": "ksmbd"},
        description="ksmbd module is loaded",
        justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
    )
    res = ProbeResult(
        precondition=pre,
        status=ProbeStatus.NOT_MET,
        evidence="Module 'ksmbd' not present in /proc/modules",
        command="cat /proc/modules",
    )
    verdict = HostVerdict(
        host="laptop-01",
        cve_id="CVE-2022-47942",
        status=VerdictStatus.NOT_AFFECTED,
        reason="Module 'ksmbd' not present in /proc/modules",
        justification=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
        probe_results=[res],
        mitigation=[],
        patch=None,
        product_id="pkg:generic/linux-kernel@laptop-01",
    )
    d = verdict.to_dict()
    assert d["status"] == "not_affected"
    assert d["justification"] == "vulnerable_code_not_in_execute_path"
    assert d["probe_results"][0]["status"] == "NOT_MET"
