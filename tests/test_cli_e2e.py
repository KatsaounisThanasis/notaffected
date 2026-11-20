"""End-to-end CLI and golden fleet tests (Task 7)."""

import json
from pathlib import Path

import pytest

from notaffected.advisories.builtin_specs import BUILTIN_SPECS
from notaffected.cli import main
from notaffected.engine.evaluator import evaluate_fleet
from notaffected.inventory import load_runners
from notaffected.model import VerdictStatus
from notaffected.probes.runner import CommandResult, MockRunner


def test_golden_fleet_cve_2026_98432():
    """Golden test reproducing the exact real-world scenario from the design:
    - laptop-01: services listen only on 127.0.0.1 and ufw blocks incoming -> NOT_AFFECTED
    - edge-api-01: nginx listens on 0.0.0.0:443 and ufw allows 443 -> AFFECTED (with mitigation & -proposed status)
    - db-patched-01: already running kernel 6.8.0-45-generic -> NOT_AFFECTED
    """
    spec = BUILTIN_SPECS["CVE-2026-98432"]

    laptop = MockRunner(
        host_name="laptop-01",
        responses={
            ("uname", "-r"): CommandResult(0, "6.8.0-40-generic\n", ""),
            ("dpkg", "--compare-versions", "6.8.0-40", "lt", "4.4.0"): CommandResult(1, "", ""),
            ("dpkg", "--compare-versions", "6.8.0-40", "lt", "6.8.0-45"): CommandResult(0, "", ""),
            ("ss", "-tulpnH"): CommandResult(
                0,
                "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n"
                "tcp LISTEN 0 128 127.0.0.1:631 0.0.0.0:*\n",
                "",
            ),
            ("ufw", "status", "verbose"): CommandResult(
                0,
                "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n",
                "",
            ),
        },
    )

    edge_server = MockRunner(
        host_name="edge-api-01",
        responses={
            ("uname", "-r"): CommandResult(0, "6.8.0-40-generic\n", ""),
            ("dpkg", "--compare-versions", "6.8.0-40", "lt", "4.4.0"): CommandResult(1, "", ""),
            ("dpkg", "--compare-versions", "6.8.0-40", "lt", "6.8.0-45"): CommandResult(0, "", ""),
            ("ss", "-tulpnH"): CommandResult(
                0,
                "tcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=900,fd=6))\n",
                "",
            ),
            ("ufw", "status", "verbose"): CommandResult(
                0,
                "Status: active\nDefault: deny (incoming)\n443/tcp ALLOW IN Anywhere\n",
                "",
            ),
        },
    )

    patched_db = MockRunner(
        host_name="db-patched-01",
        responses={
            ("uname", "-r"): CommandResult(0, "6.8.0-45-generic\n", ""),
            ("dpkg", "--compare-versions", "6.8.0-45", "lt", "4.4.0"): CommandResult(1, "", ""),
            ("dpkg", "--compare-versions", "6.8.0-45", "lt", "6.8.0-45"): CommandResult(1, "", ""),
            ("ss", "-tulpnH"): CommandResult(
                0,
                "tcp LISTEN 0 128 0.0.0.0:5432 0.0.0.0:*\n",
                "",
            ),
            ("ufw", "status", "verbose"): CommandResult(0, "Status: inactive\n", ""),
        },
    )

    verdicts = evaluate_fleet([spec], [laptop, edge_server, patched_db])
    by_host = {v.host: v for v in verdicts}

    assert by_host["laptop-01"].status == VerdictStatus.NOT_AFFECTED
    assert "loopback" in by_host["laptop-01"].reason.lower()

    assert by_host["edge-api-01"].status == VerdictStatus.AFFECTED
    assert any("ufw" in m for m in by_host["edge-api-01"].mitigation)
    assert by_host["edge-api-01"].patch.pocket == "noble-proposed"

    assert by_host["db-patched-01"].status == VerdictStatus.NOT_AFFECTED
    assert ">= fixed version" in by_host["db-patched-01"].reason


def test_inventory_yaml_loader(tmp_path: Path):
    inv_file = tmp_path / "hosts.yml"
    inv_file.write_text(
        "hosts:\n"
        "  - name: local-box\n"
        "    type: local\n"
        "  - name: web-01\n"
        "    ssh: ubuntu@10.0.0.10\n"
        "    port: 2222\n",
        encoding="utf-8",
    )
    runners = load_runners(host=None, ssh_targets=None, inventory_path=inv_file)
    assert len(runners) == 2
    assert runners[0].host_name == "local-box"
    assert runners[1].host_name == "web-01"


def test_inventory_docker_and_k8s_entries(tmp_path: Path):
    inv_file = tmp_path / "containers.yml"
    inv_file.write_text(
        "hosts:\n"
        "  - name: api-container\n"
        "    docker: api-v1\n"
        "  - name: worker-pod\n"
        "    k8s: payments/worker-0\n",
        encoding="utf-8",
    )
    runners = load_runners(
        host=None,
        ssh_targets=None,
        docker_targets=["redis-local"],
        k8s_targets=["default/web-pod"],
        inventory_path=inv_file,
    )
    names = [r.host_name for r in runners]
    assert names == ["api-container", "worker-pod", "docker:redis-local", "k8s:default/web-pod"]


def test_inventory_windows_ssh_entries(tmp_path: Path):
    inv_file = tmp_path / "win_hosts.yml"
    inv_file.write_text(
        "hosts:\n"
        "  - name: win-dc-01\n"
        "    ssh: Administrator@10.0.1.50\n"
        "    os: windows\n",
        encoding="utf-8",
    )
    runners = load_runners(
        host=None,
        ssh_targets=None,
        win_ssh_targets=["Administrator@10.0.1.51"],
        inventory_path=inv_file,
    )
    assert len(runners) == 2
    assert runners[0].host_name == "win-dc-01"
    assert runners[0].os_family == "windows"
    assert runners[1].host_name == "Administrator@10.0.1.51"
    assert runners[1].os_family == "windows"


def test_mixed_linux_and_windows_demo_fleet():
    from notaffected.inventory import load_demo_fleet

    fleet = load_demo_fleet()
    host_names = [r.host_name for r in fleet]
    assert "win-dc-01" in host_names
    assert "win-filesrv-02" in host_names

    specs = [
        BUILTIN_SPECS["CVE-2026-98432"],
        BUILTIN_SPECS["CVE-2024-38063"],
        BUILTIN_SPECS["CVE-2021-34527"],
    ]
    verdicts = evaluate_fleet(specs, fleet)
    by_pair = {(v.host, v.cve_id): v for v in verdicts}

    # Linux CVE on Windows host -> NOT_AFFECTED (component_not_present)
    assert by_pair[("win-dc-01", "CVE-2026-98432")].status == VerdictStatus.NOT_AFFECTED
    # Windows CVE on Linux host -> NOT_AFFECTED (component_not_present)
    assert by_pair[("prod-edge-api-01", "CVE-2024-38063")].status == VerdictStatus.NOT_AFFECTED
    # Windows CVE on unpatched Windows DC -> AFFECTED
    assert by_pair[("win-dc-01", "CVE-2024-38063")].status == VerdictStatus.AFFECTED
    assert by_pair[("win-dc-01", "CVE-2021-34527")].status == VerdictStatus.AFFECTED
    # Windows CVE on mitigated Windows file server -> NOT_AFFECTED
    assert by_pair[("win-filesrv-02", "CVE-2024-38063")].status == VerdictStatus.NOT_AFFECTED
    assert by_pair[("win-filesrv-02", "CVE-2021-34527")].status == VerdictStatus.NOT_AFFECTED





@pytest.mark.live
def test_cli_spec_check_and_filter_live_local(tmp_path: Path):
    # Runs real probes on this machine, so its verdicts depend on the live kernel and services.
    # Skipped by default; run with `pytest -m live`.
    # 1. `notaffected spec CVE-2026-98432`
    rc_spec = main(["spec", "CVE-2026-98432"])
    assert rc_spec == 0

    # 2. `notaffected check CVE-2022-47942 --host local --emit-vex ... --json ...`
    vex_path = tmp_path / "out.vex.json"
    json_path = tmp_path / "out.report.json"
    rc_check = main(
        [
            "check",
            "CVE-2022-47942",
            "--host",
            "local",
            "--emit-vex",
            str(vex_path),
            "--json",
            str(json_path),
        ]
    )
    assert rc_check == 0
    assert vex_path.is_file()
    vex_doc = json.loads(vex_path.read_text(encoding="utf-8"))
    assert vex_doc["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert len(vex_doc["statements"]) == 1
    # ksmbd is not loaded on this workstation, so it must be deterministically not_affected!
    assert vex_doc["statements"][0]["status"] == "not_affected"

    # 3. `notaffected filter fixtures/trivy_ubuntu_sample.json --host local --emit-vex ... --html ...`
    fixture_path = Path(__file__).resolve().parent.parent / "fixtures" / "trivy_ubuntu_sample.json"
    vex_filter_path = tmp_path / "filtered.vex.json"
    html_filter_path = tmp_path / "filtered.report.html"
    rc_filter = main(
        [
            "filter",
            str(fixture_path),
            "--host",
            "local",
            "--emit-vex",
            str(vex_filter_path),
            "--html",
            str(html_filter_path),
        ]
    )
    assert rc_filter == 0
    filtered_vex = json.loads(vex_filter_path.read_text(encoding="utf-8"))
    assert len(filtered_vex["statements"]) == 3
    assert html_filter_path.is_file()
    assert "<!DOCTYPE html>" in html_filter_path.read_text(encoding="utf-8")


def test_duplicate_host_names_are_refused(tmp_path: Path):
    inv_file = tmp_path / "dup.yml"
    inv_file.write_text(
        "hosts:\n  - name: web\n    ssh: ops@10.0.0.10\n  - name: web\n    ssh: ops@10.0.0.11\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="web"):
        load_runners(inventory_path=inv_file)
    # the CLI reports it instead of crashing, and never builds a VEX with colliding hosts
    vex = tmp_path / "x.vex.json"
    assert main(["check", "CVE-2024-6387", "-i", str(inv_file), "--emit-vex", str(vex)]) == 2
    assert not vex.exists()
