"""Core domain models for notaffected.

Every verdict traces back to deterministic ProbeResults. Preconditions are
restricted to a closed set of read-only probe types (PROBE_TYPES).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ProbeStatus(str, Enum):
    """Three-valued outcome of a single deterministic probe."""

    MET = "MET"
    NOT_MET = "NOT_MET"
    UNKNOWN = "UNKNOWN"


class VerdictStatus(str, Enum):
    """OpenVEX-aligned host verdict status."""

    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNDER_INVESTIGATION = "under_investigation"


class VexJustification(str, Enum):
    """Official OpenVEX v0.2.0 justifications for not_affected status."""

    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"


PROBE_TYPES: frozenset[str] = frozenset(
    {
        "kernel_version_vulnerable",
        "package_installed_vulnerable",
        "kernel_module_loaded",
        "sysctl_equals",
        "network_listener",
        "firewall_allows_port",
        "systemd_service_active",
        "process_running",
        "config_contains",
        "windows_build_vulnerable",
        "windows_registry_equals",
        "windows_service_active",
    }
)


@dataclass(frozen=True)
class Precondition:
    """A single required condition for a vulnerability to be exploitable."""

    probe: str
    params: dict[str, Any]
    description: str
    justification_if_not_met: VexJustification = (
        VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
    )

    def __post_init__(self) -> None:
        if self.probe not in PROBE_TYPES:
            raise ValueError(
                f"Unsupported probe type '{self.probe}'. Must be one of {sorted(PROBE_TYPES)}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe": self.probe,
            "params": dict(self.params),
            "description": self.description,
            "justification_if_not_met": self.justification_if_not_met.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Precondition:
        just_raw = data.get(
            "justification_if_not_met",
            VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH.value,
        )
        return cls(
            probe=str(data["probe"]),
            params=dict(data.get("params") or {}),
            description=str(data.get("description") or ""),
            justification_if_not_met=VexJustification(just_raw),
        )


@dataclass(frozen=True)
class PatchInfo:
    """Tracks upstream/distro fix availability and staging pocket."""

    status: str  # "released" | "staged" | "unfixed" | "unknown"
    fixed_version: str | None = None
    pocket: str | None = None
    advisory_url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "fixed_version": self.fixed_version,
            "pocket": self.pocket,
            "advisory_url": self.advisory_url,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> PatchInfo:
        if not data:
            return cls(status="unknown")
        return cls(
            status=str(data.get("status") or "unknown"),
            fixed_version=data.get("fixed_version"),
            pocket=data.get("pocket"),
            advisory_url=data.get("advisory_url"),
        )


@dataclass
class CheckSpec:
    """Structured precondition specification for a CVE."""

    cve_id: str
    summary: str
    severity: str = "UNKNOWN"
    preconditions: list[Precondition] = field(default_factory=list)
    mitigation: list[str] = field(default_factory=list)
    patch: PatchInfo = field(default_factory=lambda: PatchInfo(status="unknown"))
    confidence: str = "high"  # "high" | "low"
    source: str = "builtin"  # "builtin" | "osv" | "osv+llm" | "fallback"
    os_family: str = "linux"  # "linux" | "windows"

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "summary": self.summary,
            "severity": self.severity,
            "preconditions": [p.to_dict() for p in self.preconditions],
            "mitigation": list(self.mitigation),
            "patch": self.patch.to_dict(),
            "confidence": self.confidence,
            "source": self.source,
            "os_family": self.os_family,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CheckSpec:
        return cls(
            cve_id=str(data["cve_id"]),
            summary=str(data.get("summary") or ""),
            severity=str(data.get("severity") or "UNKNOWN"),
            preconditions=[
                Precondition.from_dict(p) for p in (data.get("preconditions") or [])
            ],
            mitigation=[str(m) for m in (data.get("mitigation") or [])],
            patch=PatchInfo.from_dict(data.get("patch")),
            confidence=str(data.get("confidence") or "high"),
            source=str(data.get("source") or "builtin"),
            os_family=str(data.get("os_family") or "linux").lower(),
        )


@dataclass(frozen=True)
class ProbeResult:
    """Result of executing a single Precondition probe on a target host."""

    precondition: Precondition
    status: ProbeStatus
    evidence: str
    command: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "precondition": self.precondition.to_dict(),
            "status": self.status.value,
            "evidence": self.evidence,
            "command": self.command,
        }


@dataclass
class HostVerdict:
    """Final deterministic verdict for a (host, cve_id) pair."""

    host: str
    cve_id: str
    status: VerdictStatus
    reason: str
    justification: VexJustification | None
    probe_results: list[ProbeResult] = field(default_factory=list)
    mitigation: list[str] = field(default_factory=list)
    patch: PatchInfo | None = None
    product_id: str = ""
    os_family: str = "linux"

    def __post_init__(self) -> None:
        if not self.product_id:
            self.product_id = f"pkg:generic/{self.os_family}-host@{self.host}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "cve_id": self.cve_id,
            "status": self.status.value,
            "reason": self.reason,
            "justification": self.justification.value if self.justification else None,
            "probe_results": [r.to_dict() for r in self.probe_results],
            "mitigation": list(self.mitigation),
            "patch": self.patch.to_dict() if self.patch else None,
            "product_id": self.product_id,
            "os_family": self.os_family,
        }
