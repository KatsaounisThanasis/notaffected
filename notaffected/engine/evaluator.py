"""Three-valued evaluation engine.

Core invariant:
1. If ANY required precondition is NOT_MET with deterministic proof -> NOT_AFFECTED.
2. Else if ANY required precondition is UNKNOWN, or the CheckSpec has empty
   preconditions or confidence == "low" -> UNDER_INVESTIGATION (never NOT_AFFECTED).
3. Else (all preconditions MET and confidence == "high") -> AFFECTED.
"""

from __future__ import annotations

from notaffected.model import (
    CheckSpec,
    HostVerdict,
    ProbeResult,
    ProbeStatus,
    VerdictStatus,
)
from notaffected.probes.primitives import run_probe
from notaffected.probes.runner import HostRunner


def evaluate_host(spec: CheckSpec, runner: HostRunner) -> HostVerdict:
    """Evaluate all preconditions in `spec` against `runner`."""
    if not spec.preconditions:
        return HostVerdict(
            host=runner.host_name,
            cve_id=spec.cve_id,
            status=VerdictStatus.UNDER_INVESTIGATION,
            reason="Advisory did not yield any deterministic preconditions to probe",
            justification=None,
            probe_results=[],
            mitigation=list(spec.mitigation),
            patch=spec.patch,
        )

    results: list[ProbeResult] = []
    first_not_met: ProbeResult | None = None
    first_unknown: ProbeResult | None = None

    # Intentionally execute all preconditions (no short-circuit) so `probe_results`
    # preserves a complete, auditable record of every check run on the host.
    for pre in spec.preconditions:
        res = run_probe(pre, runner)
        results.append(res)
        if res.status == ProbeStatus.NOT_MET and first_not_met is None:
            first_not_met = res
        elif res.status == ProbeStatus.UNKNOWN and first_unknown is None:
            first_unknown = res

    if first_not_met is not None:
        return HostVerdict(
            host=runner.host_name,
            cve_id=spec.cve_id,
            status=VerdictStatus.NOT_AFFECTED,
            reason=first_not_met.evidence,
            justification=first_not_met.precondition.justification_if_not_met,
            probe_results=results,
            mitigation=[],
            patch=spec.patch,
        )

    if first_unknown is not None:
        return HostVerdict(
            host=runner.host_name,
            cve_id=spec.cve_id,
            status=VerdictStatus.UNDER_INVESTIGATION,
            reason=f"Indeterminate check ({first_unknown.precondition.probe}): {first_unknown.evidence}",
            justification=None,
            probe_results=results,
            mitigation=list(spec.mitigation),
            patch=spec.patch,
        )

    if spec.confidence.lower() != "high":
        met_summaries = "; ".join(r.evidence for r in results)
        return HostVerdict(
            host=runner.host_name,
            cve_id=spec.cve_id,
            status=VerdictStatus.UNDER_INVESTIGATION,
            reason=(
                f"Version/baseline matched ({met_summaries}), but advisory lacks "
                "narrowing runtime preconditions; manual review required"
            ),
            justification=None,
            probe_results=results,
            mitigation=list(spec.mitigation),
            patch=spec.patch,
        )

    met_summaries = "; ".join(r.evidence for r in results)
    return HostVerdict(
        host=runner.host_name,
        cve_id=spec.cve_id,
        status=VerdictStatus.AFFECTED,
        reason=met_summaries,
        justification=None,
        probe_results=results,
        mitigation=list(spec.mitigation),
        patch=spec.patch,
    )


def evaluate_fleet(
    specs: list[CheckSpec],
    runners: list[HostRunner],
) -> list[HostVerdict]:
    """Evaluate every CheckSpec across all target HostRunners."""
    verdicts: list[HostVerdict] = []
    for spec in specs:
        for runner in runners:
            verdicts.append(evaluate_host(spec, runner))
    return verdicts
