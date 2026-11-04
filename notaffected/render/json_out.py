"""Full machine-readable JSON audit report."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from notaffected.model import CheckSpec, HostVerdict, VerdictStatus


def build_json_report(
    specs: list[CheckSpec],
    verdicts: list[HostVerdict],
) -> dict[str, Any]:
    """Build a comprehensive JSON audit report with summary counts and probe proofs."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    affected_count = sum(1 for v in verdicts if v.status == VerdictStatus.AFFECTED)
    not_affected_count = sum(1 for v in verdicts if v.status == VerdictStatus.NOT_AFFECTED)
    under_inv_count = sum(
        1 for v in verdicts if v.status == VerdictStatus.UNDER_INVESTIGATION
    )

    return {
        "generated_at": now_iso,
        "summary": {
            "total_checks": len(verdicts),
            "affected": affected_count,
            "not_affected": not_affected_count,
            "under_investigation": under_inv_count,
        },
        "specs": [s.to_dict() for s in specs],
        "verdicts": [v.to_dict() for v in verdicts],
    }


def write_json_report(
    specs: list[CheckSpec],
    verdicts: list[HostVerdict],
    path: Path,
) -> dict[str, Any]:
    report = build_json_report(specs, verdicts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
