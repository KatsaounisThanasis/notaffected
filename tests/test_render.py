"""Tests for OpenVEX v0.2.0, JSON report, and Rich console renderers (Task 6)."""

from io import StringIO

from rich.console import Console

from notaffected.advisories.builtin_specs import BUILTIN_SPECS
from notaffected.model import (
    HostVerdict,
    PatchInfo,
    Precondition,
    ProbeResult,
    ProbeStatus,
    VerdictStatus,
    VexJustification,
)
from notaffected.render.console import render_spec, render_verdicts
from notaffected.render.json_out import build_json_report
from notaffected.render.vex import build_openvex


def _sample_verdicts() -> list[HostVerdict]:
    pre = Precondition(
        probe="network_listener",
        params={"proto": "tcp", "scope": "non_loopback"},
        description="TCP non-loopback listener",
        justification_if_not_met=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
    )
    v_safe = HostVerdict(
        host="laptop-01",
        cve_id="CVE-2026-98432",
        status=VerdictStatus.NOT_AFFECTED,
        reason="No non-loopback listeners found; only loopback listener(s) active",
        justification=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
        probe_results=[
            ProbeResult(
                precondition=pre,
                status=ProbeStatus.NOT_MET,
                evidence="No non-loopback listeners found; only loopback listener(s) active",
                command="ss -tulpnH",
            )
        ],
        mitigation=[],
        patch=PatchInfo(status="staged", fixed_version="6.8.0-45.45", pocket="noble-proposed"),
    )
    v_aff = HostVerdict(
        host="edge-api-01",
        cve_id="CVE-2026-98432",
        status=VerdictStatus.AFFECTED,
        reason="Running kernel '6.8.0-40-generic' (< '6.8.0-45'); Exposed non-loopback listener: tcp 0.0.0.0:443",
        justification=None,
        probe_results=[],
        mitigation=["sudo ufw default deny incoming && sudo ufw enable"],
        patch=PatchInfo(status="staged", fixed_version="6.8.0-45.45", pocket="noble-proposed"),
    )
    return [v_safe, v_aff]


def test_openvex_schema_compliance():
    verdicts = _sample_verdicts()
    vex = build_openvex(verdicts, author="notaffected-test")
    assert vex["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert vex["author"] == "notaffected-test"
    assert vex["version"] == 1
    assert "timestamp" in vex
    statements = vex["statements"]
    assert len(statements) == 2

    st_safe = statements[0]
    assert st_safe["status"] == "not_affected"
    assert st_safe["justification"] == "vulnerable_code_not_in_execute_path"
    assert "loopback" in st_safe["impact_statement"].lower()
    assert st_safe["vulnerability"]["name"] == "CVE-2026-98432"

    st_aff = statements[1]
    assert st_aff["status"] == "affected"
    assert "justification" not in st_aff
    assert "ufw" in st_aff["action_statement"]
    assert "noble-proposed" in st_aff["action_statement"]


def test_build_json_report():
    spec = BUILTIN_SPECS["CVE-2026-98432"]
    verdicts = _sample_verdicts()
    report = build_json_report([spec], verdicts)
    assert report["summary"]["total_checks"] == 2
    assert report["summary"]["affected"] == 1
    assert report["summary"]["not_affected"] == 1
    assert report["summary"]["under_investigation"] == 0
    assert len(report["verdicts"]) == 2


def test_console_renderers_produce_clean_english_output():
    spec = BUILTIN_SPECS["CVE-2026-98432"]
    verdicts = _sample_verdicts()

    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=100)
    render_spec(spec, console=console)
    render_verdicts([spec], verdicts, console=console)
    out = buf.getvalue()

    assert "CVE-2026-98432" in out
    assert "AFFECTED (1)" in out
    assert "NOT AFFECTED (1)" in out
    assert "edge-api-01" in out
    assert "laptop-01" in out
    assert "noble-proposed" in out


def test_html_report_generation_and_xss_escaping():
    from notaffected.render.html import build_html_report

    spec = BUILTIN_SPECS["CVE-2026-98432"]
    verdicts = _sample_verdicts()
    # Add a verdict with untrusted HTML/JS in reason to verify XSS escaping
    verdicts.append(
        HostVerdict(
            host="xss-host<script>alert(1)</script>",
            cve_id="CVE-2026-98432",
            status=VerdictStatus.UNDER_INVESTIGATION,
            reason="Output: <img src=x onerror=alert(1)>",
            justification=None,
        )
    )

    html_doc = build_html_report([spec], verdicts)
    assert "<!DOCTYPE html>" in html_doc
    assert "CVE-2026-98432" in html_doc
    assert "edge-api-01" in html_doc
    assert "laptop-01" in html_doc
    # No external CDN stylesheets or scripts
    assert "https://cdn." not in html_doc
    assert "https://unpkg." not in html_doc
    # Untrusted tags are HTML-escaped
    assert "<script>alert(1)</script>" not in html_doc
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_doc
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_doc



def _pkg_verdict(host: str, status, ver: str = "1:9.6p1-3ubuntu13.3"):
    from notaffected.engine.evaluator import evaluate_host
    from notaffected.model import CheckSpec, Precondition
    from notaffected.probes.runner import CommandResult, MockRunner

    spec = CheckSpec(
        cve_id="CVE-2024-6387",
        summary="s",
        preconditions=[Precondition("package_installed_vulnerable", {"package": "openssh-server", "fixed_version": "1:9.8p1-1"}, "p")],
    )
    lt = 0 if status == "affected" else 1
    runner = MockRunner(
        host,
        {
            ("dpkg-query", "-W", "-f=${db:Status-Abbrev}\\t${Version}\\n", "openssh-server"): CommandResult(0, f"ii \t{ver}\n", ""),
            ("cat", "/etc/os-release"): CommandResult(0, 'ID=ubuntu\nVERSION_ID="24.04"\n', ""),
            ("dpkg", "--compare-versions", ver, "lt", "1:9.8p1-1"): CommandResult(lt, "", ""),
        },
    )
    return evaluate_host(spec, runner)


def test_vex_products_carry_package_purl_single_and_multi_host():
    v = _pkg_verdict("h1", "not_affected")
    assert v.component_purl == "pkg:deb/ubuntu/openssh-server@9.6p1-3ubuntu13.3?epoch=1"
    single = build_openvex([v])
    assert single["@id"].startswith("urn:uuid:")
    assert single["statements"][0]["products"] == [{"@id": v.component_purl}]
    assert "[h1]" in single["statements"][0]["impact_statement"]

    multi = build_openvex([v, _pkg_verdict("h2", "affected")])
    for st in multi["statements"]:
        (prod,) = st["products"]
        assert prod["@id"].startswith("pkg:generic/linux-host@")
        assert prod["subcomponents"] == [{"@id": "pkg:deb/ubuntu/openssh-server@9.6p1-3ubuntu13.3?epoch=1"}]


def test_vex_documents_validate_against_official_schema():
    """Schema: fixtures/openvex_json_schema.json, copied from
    https://github.com/openvex/spec (openvex_json_schema_0.2.0.json, Apache-2.0)."""
    import json
    from pathlib import Path

    import pytest

    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((Path(__file__).resolve().parent.parent / "fixtures" / "openvex_json_schema.json").read_text())
    from notaffected.model import HostVerdict, VerdictStatus

    ui = HostVerdict("h3", "CVE-2024-6387", VerdictStatus.UNDER_INVESTIGATION, "unknown", None)
    for doc in (
        build_openvex([_pkg_verdict("h1", "not_affected")]),
        build_openvex([_pkg_verdict("h1", "not_affected"), _pkg_verdict("h2", "affected"), ui]),
    ):
        jsonschema.validate(doc, schema)


def test_untrusted_strings_never_break_console_markup_and_files_are_written_first(tmp_path, monkeypatch):
    import pytest

    from notaffected import cli
    from notaffected.model import CheckSpec, HostVerdict, VerdictStatus

    hostile = "proc [/bold] [red]x"
    spec = CheckSpec(cve_id="CVE-2026-0009", summary=f"summary {hostile}", severity="[/b]", mitigation=[f"echo {hostile}"])
    verdicts = [
        HostVerdict(f"host{hostile}", "CVE-2026-0009", VerdictStatus.AFFECTED, f"reason {hostile}", None, mitigation=[hostile]),
        HostVerdict("h2", "CVE-2026-0009", VerdictStatus.UNDER_INVESTIGATION, f"why {hostile}", None),
        HostVerdict("h3", "CVE-2026-0009", VerdictStatus.NOT_AFFECTED, f"proof {hostile}", None),
    ]
    buf = StringIO()
    con = Console(file=buf, width=200, color_system=None)
    render_spec(spec, console=con)
    render_verdicts([spec], verdicts, console=con)
    assert "[/bold]" in buf.getvalue()  # shown literally, not parsed

    def _boom(*_a, **_k):
        raise RuntimeError("render failed")

    monkeypatch.setattr(cli, "render_verdicts", _boom)
    vex = tmp_path / "out.vex.json"
    with pytest.raises(RuntimeError):
        cli.main(["check", "CVE-2026-98432", "--demo-fleet", "--emit-vex", str(vex)])
    assert vex.is_file()  # outputs are written before rendering


def test_agy_runs_without_skipping_permissions_and_claude_cli_does_not_fall_back(monkeypatch):
    from notaffected import local_model

    seen: list[list[str]] = []

    def _fake_run(cmd, **_k):
        seen.append(list(cmd))
        return type("P", (), {"returncode": 1, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(local_model.subprocess, "run", _fake_run)
    local_model._run_agy_cli("hello")
    assert seen and "--dangerously-skip-permissions" not in seen[0]

    seen.clear()
    monkeypatch.setattr(local_model, "detect_provider", lambda: "claude-cli")
    monkeypatch.setattr(local_model.shutil, "which", lambda name: f"/usr/bin/{name}")
    assert local_model.generate("hello") == ""
    assert all(c[0] != "agy" for c in seen)


def test_repeated_package_statement_never_becomes_a_bare_purl_product():
    a, b = _pkg_verdict("web", "not_affected"), _pkg_verdict("web", "affected")
    doc = build_openvex([a, b])
    for st in doc["statements"]:
        (prod,) = st["products"]
        assert prod["@id"] == "pkg:generic/linux-host@web" and prod["subcomponents"] == [{"@id": a.component_purl}]
