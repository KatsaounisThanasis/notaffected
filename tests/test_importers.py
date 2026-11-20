"""Tests for Trivy and Grype scanner JSON importers (Task 5)."""

import json

from notaffected.importers.scanners import parse_scanner_json


def test_parse_trivy_json():
    trivy_payload = {
        "SchemaVersion": 2,
        "ArtifactName": "ubuntu:24.04",
        "Results": [
            {
                "Target": "ubuntu:24.04 (ubuntu 24.04)",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-98432",
                        "PkgName": "linux-image-generic",
                        "InstalledVersion": "6.8.0-40.40",
                        "FixedVersion": "6.8.0-45.45",
                        "Severity": "CRITICAL",
                    },
                    {
                        "VulnerabilityID": "CVE-2024-47176",
                        "PkgName": "cups-browsed",
                        "InstalledVersion": "2.0.0-0ubuntu10.1",
                        "FixedVersion": "2.0.0-0ubuntu10.2",
                        "Severity": "CRITICAL",
                    },
                    # Duplicate entry should be deduplicated
                    {
                        "VulnerabilityID": "CVE-2024-47176",
                        "PkgName": "cups-browsed",
                        "InstalledVersion": "2.0.0-0ubuntu10.1",
                        "FixedVersion": "2.0.0-0ubuntu10.2",
                        "Severity": "CRITICAL",
                    },
                ],
            }
        ],
    }
    findings = parse_scanner_json(trivy_payload)
    assert len(findings) == 2
    assert findings[0].cve_id == "CVE-2026-98432"
    assert findings[0].package_name == "linux-image-generic"
    assert findings[0].fixed_version == "6.8.0-45.45"
    assert findings[1].cve_id == "CVE-2024-47176"


def test_parse_grype_json_from_string():
    grype_payload = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2022-47942",
                    "severity": "Critical",
                    "fix": {"versions": ["5.19.0-28"], "state": "fixed"},
                },
                "artifact": {
                    "name": "linux-image",
                    "version": "5.19.0-21",
                },
            }
        ]
    }
    findings = parse_scanner_json(json.dumps(grype_payload))
    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2022-47942"
    assert findings[0].package_name == "linux-image"
    assert findings[0].installed_version == "5.19.0-21"
    assert findings[0].fixed_version == "5.19.0-28"
    assert findings[0].severity == "CRITICAL"


def test_scanner_findings_keep_package_class_and_purl():
    from pathlib import Path

    from notaffected.importers.scanners import parse_scanner_json

    qa = Path(__file__).resolve().parent.parent / "fixtures" / "qa"
    trivy = parse_scanner_json(qa / "trivy_langpkg.json")
    assert (trivy[0].package_class, trivy[0].purl) == ("lang", "pkg:pypi/requests@2.25.1")
    grype = parse_scanner_json(qa / "grype_min.json")
    assert [(f.package_name, f.package_class) for f in grype] == [("requests", "lang"), ("cups-browsed", "os")]
    assert grype[1].purl == "pkg:deb/ubuntu/cups-browsed@2.0.0-0ubuntu10.1"
    # Trivy output without Class/Type stays "unknown" (old behaviour: probed as an OS package)
    sample = parse_scanner_json(Path(__file__).resolve().parent.parent / "fixtures" / "trivy_ubuntu_sample.json")
    assert {f.package_class for f in sample} == {"unknown"}


def test_language_package_spec_has_no_host_probes():
    from notaffected.advisories.extractor import resolve_check_spec
    from notaffected.engine.evaluator import evaluate_host
    from notaffected.model import VerdictStatus
    from notaffected.probes.runner import MockRunner

    spec = resolve_check_spec("CVE-2023-32681", package_hint="requests", package_class="lang", offline=True)
    assert spec.preconditions == [] and spec.source == "fallback"
    assert evaluate_host(spec, MockRunner("h", {})).status == VerdictStatus.UNDER_INVESTIGATION


def test_filter_keeps_every_package_of_a_cve(tmp_path, monkeypatch):
    import json
    import urllib.error
    import urllib.request

    from notaffected.cli import main

    def _offline(*_a, **_k):
        raise urllib.error.URLError("network disabled in tests")

    monkeypatch.setattr(urllib.request, "urlopen", _offline)

    report = {
        "Results": [
            {
                "Target": "ubuntu",
                "Class": "os-pkgs",
                "Type": "ubuntu",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2026-1111", "PkgName": "libfoo1", "InstalledVersion": "1.0-1"},
                    {"VulnerabilityID": "CVE-2026-1111", "PkgName": "libfoo-dev", "InstalledVersion": "1.0-1"},
                ],
            }
        ]
    }
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps(report), encoding="utf-8")
    out = tmp_path / "out.json"
    assert main(["filter", str(scan), "--demo-fleet", "--json", str(out)]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    pkgs = {p["params"]["package"] for s in doc["specs"] for p in s["preconditions"]}
    assert pkgs == {"libfoo1", "libfoo-dev"}
