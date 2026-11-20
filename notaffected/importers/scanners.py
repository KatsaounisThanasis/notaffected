"""Parsers for Trivy JSON and Grype JSON vulnerability scan reports."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ScannedFinding:
    """A single CVE finding extracted from a scanner report."""

    cve_id: str
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    severity: str = "UNKNOWN"
    package_class: str = "unknown"  # "os" | "lang" | "unknown"
    purl: str | None = None


# Trivy `Type` values for OS package databases (anything else with a Type is a language ecosystem).
_TRIVY_OS_TYPES = frozenset(
    {
        "ubuntu", "debian", "alpine", "redhat", "centos", "rocky", "alma", "amazon", "oracle",
        "suse", "opensuse", "opensuse.leap", "opensuse.tumbleweed", "sles", "photon", "fedora",
        "wolfi", "chainguard", "cbl-mariner", "azurelinux", "echo", "minimos", "bottlerocket",
    }
)
_OS_PURL_TYPES = ("pkg:deb/", "pkg:rpm/", "pkg:apk/")


def _trivy_class(res_block: dict[str, Any]) -> str:
    cls = str(res_block.get("Class") or "").lower()
    if cls == "os-pkgs":
        return "os"
    if cls == "lang-pkgs":
        return "lang"
    typ = str(res_block.get("Type") or "").lower()
    if not typ:
        return "unknown"
    return "os" if typ in _TRIVY_OS_TYPES else "lang"


def _grype_class(artifact: dict[str, Any]) -> str:
    typ = str(artifact.get("type") or "").lower()
    purl = str(artifact.get("purl") or "").lower()
    if typ in ("deb", "rpm", "apk") or purl.startswith(_OS_PURL_TYPES):
        return "os"
    return "lang" if typ or purl else "unknown"


def parse_scanner_json(data: dict[str, Any] | str | Path) -> list[ScannedFinding]:
    """Auto-detect and parse Trivy JSON or Grype JSON into deduplicated ScannedFindings."""
    if isinstance(data, Path):
        payload = json.loads(data.read_text(encoding="utf-8"))
    elif isinstance(data, str):
        is_file_path = False
        if "\n" not in data and len(data) <= 240 and not data.lstrip().startswith(("{", "[")):
            try:
                path_candidate = Path(data)
                is_file_path = path_candidate.is_file()
            except OSError:
                is_file_path = False
        if is_file_path:
            payload = json.loads(Path(data).read_text(encoding="utf-8"))
        else:
            payload = json.loads(data)
    elif isinstance(data, dict):
        payload = data
    else:
        raise ValueError("Unsupported scanner input type")

    if not isinstance(payload, dict):
        raise ValueError("Scanner JSON payload must be a JSON object")

    findings: list[ScannedFinding] = []
    seen: set[tuple[str, str | None]] = set()

    # Trivy format (`Results[].Vulnerabilities[]`)
    if "Results" in payload and isinstance(payload["Results"], list):
        for res_block in payload["Results"]:
            if not isinstance(res_block, dict):
                continue
            block_class = _trivy_class(res_block)
            for vuln in res_block.get("Vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                cve = str(vuln.get("VulnerabilityID") or "").strip().upper()
                if not cve.startswith("CVE-"):
                    continue
                pkg = vuln.get("PkgName")
                key = (cve, pkg)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    ScannedFinding(
                        cve_id=cve,
                        package_name=str(pkg) if pkg else None,
                        installed_version=(
                            str(vuln["InstalledVersion"]) if vuln.get("InstalledVersion") else None
                        ),
                        fixed_version=(
                            str(vuln["FixedVersion"]) if vuln.get("FixedVersion") else None
                        ),
                        severity=str(vuln.get("Severity") or "UNKNOWN").upper(),
                        package_class=block_class,
                        purl=str((vuln.get("PkgIdentifier") or {}).get("PURL") or "") or None,
                    )
                )

    # Grype format (`matches[].vulnerability` + `artifact`)
    elif "matches" in payload and isinstance(payload["matches"], list):
        for match in payload["matches"]:
            if not isinstance(match, dict):
                continue
            vuln = match.get("vulnerability") or {}
            artifact = match.get("artifact") or {}
            cve = str(vuln.get("id") or "").strip().upper()
            if not cve.startswith("CVE-"):
                for rel in match.get("relatedVulnerabilities") or []:
                    if isinstance(rel, dict):
                        cand_id = str(rel.get("id") or "").strip().upper()
                        if cand_id.startswith("CVE-"):
                            cve = cand_id
                            break
            if not cve.startswith("CVE-"):
                continue
            pkg = artifact.get("name")
            key = (cve, pkg)
            if key in seen:
                continue
            seen.add(key)
            fix_block = vuln.get("fix") or {}
            fix_versions = [
                str(v).strip()
                for v in (fix_block.get("versions") or [])
                if v is not None and str(v).strip()
            ]
            fixed_ver = fix_versions[0] if fix_versions else None
            findings.append(
                ScannedFinding(
                    cve_id=cve,
                    package_name=str(pkg) if pkg else None,
                    installed_version=(
                        str(artifact["version"]) if artifact.get("version") else None
                    ),
                    fixed_version=fixed_ver,
                    severity=str(vuln.get("severity") or "UNKNOWN").upper(),
                    package_class=_grype_class(artifact),
                    purl=str(artifact.get("purl") or "") or None,
                )
            )

    return findings
