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

