"""Regression tests from the independent QA audit of 2026-11-20.

Each test asserts the CORRECT, fail-safe behaviour required by the design
(`.plans/2026-11-04-notaffected-design.md`, anti-goals "False not_affected on
uncertainty" and "AI deciding the verdict"). All eleven failed on the audited code
(0a5ee55) and were tracked as strict xfails until fixed; they now guard against the
same false `not_affected` paths coming back.

The tests are hermetic: no network (blocked by the ``no_network`` fixture), no Docker,
no real host probes. OSV/USN records live in ``fixtures/qa/osv`` (public data, gzipped)
and are unpacked into ``tmp_path``.
"""

from __future__ import annotations

import gzip
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from notaffected.advisories import extractor
from notaffected.advisories.builtin_specs import BUILTIN_SPECS
from notaffected.advisories.extractor import extract_from_osv_payload, resolve_check_spec
from notaffected.engine.evaluator import evaluate_host
from notaffected.importers.scanners import parse_scanner_json
from notaffected.model import CheckSpec, Precondition, ProbeStatus, VerdictStatus
from notaffected.probes.primitives import run_probe
from notaffected.probes.runner import CommandResult
from notaffected.render.vex import build_openvex

QA_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "qa"
NA = VerdictStatus.NOT_AFFECTED
MODS = ("cat", "/proc/modules")
DPKG_FMT = "-f=${db:Status-Abbrev}\\t${Version}\\n"

needs_dpkg = pytest.mark.skipif(shutil.which("dpkg") is None, reason="needs the real dpkg --compare-versions")


class FakeRunner:
    """Boundary fake: canned output per argv.

    ``dpkg --compare-versions`` runs the real local dpkg (pure, read-only computation)
    so version semantics are realistic. A response may be an exception instance,
    which is raised to simulate a crashing transport.
    """

    def __init__(self, host_name: str = "qa-host", responses: dict | None = None, os_family: str = "linux"):
        self.host_name = host_name
        self.os_family = os_family
        self._responses = dict(responses or {})
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv):
        self.calls.append(tuple(argv))
        key = tuple(argv)
        if key in self._responses:
            r = self._responses[key]
            if isinstance(r, BaseException):
                raise r
            return r
        if list(argv[:2]) == ["dpkg", "--compare-versions"]:
            p = subprocess.run(list(argv), capture_output=True, text=True, check=False)
            return CommandResult(p.returncode, p.stdout, p.stderr)
        return CommandResult(127, "", f"{argv[0]}: command not found")


def ok(out: str = "") -> CommandResult:
    return CommandResult(0, out, "")


def fail(rc: int = 1, err: str = "") -> CommandResult:
    return CommandResult(rc, "", err)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Keep every test hermetic: any HTTP attempt fails like an offline machine."""

    def _offline(*_a, **_k):
        raise urllib.error.URLError("network disabled in QA regression tests")

    monkeypatch.setattr(urllib.request, "urlopen", _offline)


@pytest.fixture
def osv_cache(tmp_path) -> Path:
    """Unpack the gzipped OSV/USN fixtures into a throwaway cache directory."""
    cache = tmp_path / "osv"
    cache.mkdir()
    for gz in (QA_FIXTURES / "osv").glob("*.json.gz"):
        (cache / gz.name[: -len(".gz")]).write_bytes(gzip.decompress(gz.read_bytes()))
    return cache


# --- B1: kernel fix taken from one track only; other tracks/distros compared against it ---------
def _kernel_1086_verdict(osv_cache: Path, uname: str):
    spec = resolve_check_spec("CVE-2024-1086", cache_dir=osv_cache)
    runner = FakeRunner(responses={("uname", "-r"): ok(uname + "\n"), MODS: ok("nf_tables 1 0 - Live\n")})
    return spec, evaluate_host(spec, runner)


@needs_dpkg
def test_b1_ubuntu_2204_hwe_6_5_vulnerable_kernel_is_not_declared_not_affected(osv_cache):
    # USN data: linux-hwe-6.5 on 22.04 is fixed only in 6.5.0-26.26~22.04.1; 6.5.0-14 is vulnerable.
    spec, v = _kernel_1086_verdict(osv_cache, "6.5.0-14-generic")
    assert v.status != NA, f"FALSE not_affected: {v.reason} [{v.justification}] fixed={spec.preconditions[0].params}"


@needs_dpkg
def test_b1_debian12_6_1_0_17_vulnerable_kernel_is_not_declared_not_affected(osv_cache):
    # 6.1.0-17 is 6.1.69; the upstream fix for CVE-2024-1086 landed in 6.1.76.
    _, v = _kernel_1086_verdict(osv_cache, "6.1.0-17-amd64")
    assert v.status != NA, f"FALSE not_affected: {v.reason}"


# --- B2: package fix chosen from another distro release when the host release is not listed ----
@needs_dpkg
def test_b2_debian12_openssh_not_compared_against_ubuntu_2204_fix(osv_cache):
    spec = resolve_check_spec("CVE-2023-38408", cache_dir=osv_cache)
    src_fmt = "-f=${db:Status-Abbrev}\\t${binary:Package}\\t${source:Package}\\t${Version}\\t${source:Version}\\n"
    runner = FakeRunner(
        responses={
            ("dpkg-query", "-W", DPKG_FMT, "openssh"): fail(1, "dpkg-query: no packages found matching openssh"),
            ("dpkg-query", "-W", src_fmt): ok("ii \topenssh-client\topenssh\t1:9.2p1-2\t1:9.2p1-2\n"),
            ("cat", "/etc/os-release"): ok('ID=debian\nVERSION_ID="12"\n'),
        }
    )
    v = evaluate_host(spec, runner)
    assert v.status != NA, f"FALSE not_affected: {v.reason}"


# --- B3: unparseable probe output treated as proof -------------------------------------------------
@needs_dpkg
def test_b3_garbage_uname_output_is_unknown_not_patched():
    pre = Precondition("kernel_version_vulnerable", {"fixed_version": "6.8.0-45"}, "k")
    res = run_probe(pre, FakeRunner(responses={("uname", "-r"): ok("abc\n")}))
    assert res.status == ProbeStatus.UNKNOWN, res.evidence


# --- B4: ufw port ranges ---------------------------------------------------------------------------
def test_b4_ufw_port_range_allow_rule_counts_as_allowed():
    pre = Precondition("firewall_allows_port", {"port": "8080", "proto": "tcp"}, "fw")
    ufw = "Status: active\nDefault: deny (incoming), allow (outgoing)\n\nTo Action From\n8000:9000/tcp ALLOW IN Anywhere\n"
    res = run_probe(pre, FakeRunner(responses={("ufw", "status", "verbose"): ok(ufw)}))
    assert res.status == ProbeStatus.MET, res.evidence


# --- B5: a transport exception aborts the whole run instead of resolving to UNKNOWN ---------------
def test_b5_exception_in_transport_resolves_to_under_investigation():
    pre = Precondition("config_contains", {"path": "/etc/ssh/sshd_config", "pattern": "x"}, "cfg")
    spec = CheckSpec(cve_id="CVE-QA-5", summary="qa", preconditions=[pre])
    # This is what LocalRunner raises today when a command prints Latin-1 bytes.
    boom = UnicodeDecodeError("utf-8", b"\xe9", 0, 1, "invalid continuation byte")
    runner = FakeRunner(responses={("cat", "/etc/ssh/sshd_config"): boom})
    assert evaluate_host(spec, runner).status == VerdictStatus.UNDER_INVESTIGATION


# --- B6: the LLM alone flips os_family, giving not_affected with zero probes (design anti-goal) ----
def test_b6_llm_os_family_guess_cannot_produce_not_affected_without_a_probe(monkeypatch):
    osv = {
        "id": "CVE-2025-0001",
        "summary": "Heap overflow in the libfoo image parser",
        "details": "Crafted images overflow a heap buffer.",
        "affected": [],
    }
    monkeypatch.setattr(
        extractor, "generate_json", lambda *a, **k: {"os_family": "windows", "preconditions": [], "mitigation": []}
    )
    spec = extract_from_osv_payload("CVE-2025-0001", osv, use_llm=True)
    v = evaluate_host(spec, FakeRunner())
    assert not (v.status == NA and not v.probe_results), f"LLM-decided not_affected: {v.reason} os={spec.os_family}"


# --- B7: an LLM-chosen service name not grounded in the advisory text -------------------------------
def test_b7_llm_service_not_named_in_advisory_is_rejected(monkeypatch):
    osv = {
        "id": "CVE-2025-0002",
        "summary": "nginx resolver off-by-one allows remote code execution",
        "details": "The nginx DNS resolver mishandles responses.",
        "affected": [],
    }
    monkeypatch.setattr(
        extractor,
        "generate_json",
        lambda *a, **k: {
            "os_family": "linux",
            "preconditions": [
                {
                    "probe": "systemd_service_active",
                    "params": {"service": "apache2.service"},
                    "description": "apache running",
                }
            ],
            "mitigation": [],
        },
    )
    spec = extract_from_osv_payload("CVE-2025-0002", osv, use_llm=True)
    runner = FakeRunner(
        responses={
            ("systemctl", "is-active", "apache2.service"): CommandResult(
                4, "inactive\n", "Unit apache2.service could not be found."
            )
        }
    )
    v = evaluate_host(spec, runner)
    assert v.status != NA, f"not_affected decided by an ungrounded LLM probe: {v.reason}"


# --- B8: a Trivy lang-pkgs finding probed with dpkg becomes component_not_present ------------------
def test_b8_trivy_pip_finding_is_not_declared_not_affected_because_dpkg_lacks_it():
    finding = parse_scanner_json(QA_FIXTURES / "trivy_langpkg.json")[0]
    # The importer is the source of the package class (Trivy Class/Type, Grype artifact.type).
    spec = resolve_check_spec(
        finding.cve_id,
        package_hint=finding.package_name,
        fixed_version_hint=finding.fixed_version,
        offline=True,
        package_class=finding.package_class,
    )
    runner = FakeRunner(
        responses={
            ("dpkg-query", "-W", DPKG_FMT, "requests"): fail(1, "dpkg-query: no packages found matching requests")
        }
    )
    v = evaluate_host(spec, runner)
    assert v.status != NA, f"FALSE not_affected for a pip package: {v.reason} [{v.justification}]"


# --- B9: VEX product identifiers cannot match scanner findings --------------------------------------
def test_b9_vex_for_package_finding_carries_package_purl():
    finding = parse_scanner_json(QA_FIXTURES / "grype_min.json")[1]  # cups-browsed, pkg:deb/ubuntu/...
    runner = FakeRunner(responses={("dpkg-query", "-W", DPKG_FMT, "cups-browsed"): ok("ii \t2.0.0-0ubuntu10.3\n")})
    doc = build_openvex([evaluate_host(BUILTIN_SPECS[finding.cve_id], runner)])
    ids = [p["@id"] for s in doc["statements"] for p in s["products"]]
    ids += [sc["@id"] for s in doc["statements"] for p in s["products"] for sc in p.get("subcomponents", [])]
    assert any(i.startswith("pkg:deb/") for i in ids), ids


# --- B10: non-root `ss -p` hides the process column; a process-filtered listener reads as absent ---
def test_b10_process_filtered_listener_without_process_info_is_unknown():
    pre = Precondition("network_listener", {"proto": "tcp", "port": 8080, "process": "java"}, "l")
    res = run_probe(pre, FakeRunner(responses={("ss", "-tulpnH"): ok("tcp LISTEN 0 100 0.0.0.0:8080 0.0.0.0:*\n")}))
    assert res.status != ProbeStatus.NOT_MET, res.evidence
