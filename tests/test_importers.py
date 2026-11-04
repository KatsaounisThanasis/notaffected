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
