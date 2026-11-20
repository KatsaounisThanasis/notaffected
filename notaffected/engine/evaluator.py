"""Three-valued evaluation engine.

Core invariant:
1. If ANY required precondition from an authoritative origin is NOT_MET with deterministic
   proof -> NOT_AFFECTED. A NOT_MET from a heuristic or LLM-proposed precondition is never
   proof on its own -> UNDER_INVESTIGATION.
2. Else if ANY required precondition is UNKNOWN, or the CheckSpec has empty
   preconditions or confidence == "low" -> UNDER_INVESTIGATION (never NOT_AFFECTED).
3. Else (all preconditions MET and confidence == "high") -> AFFECTED.

An OS-family mismatch gives NOT_AFFECTED only when the spec's OS is curated or comes from
structured data AND a read-only probe confirms the host's declared OS.
"""

from __future__ import annotations

import re
import urllib.parse

from notaffected.model import (
    NON_AUTHORITATIVE_ORIGINS,
    CheckSpec,
    HostVerdict,
    ProbeResult,
    ProbeStatus,
    VerdictStatus,
    VexJustification,
)
from notaffected.probes.patch_tracker import resolve_host_patch_info
from notaffected.probes.primitives import WIN_BUILD_ARGV, run_probe
from notaffected.probes.runner import HostRunner


def _confirm_host_os(runner: HostRunner, declared: str) -> bool:
    """Confirm the host's declared OS family with a read-only probe (never trust names or labels)."""
    try:
        if declared == "linux":
            res = runner.run(["uname", "-s"])
            return not res.transport_error and res.returncode == 0 and res.stdout.strip().startswith("Linux")
        if declared == "windows":
            res = runner.run(list(WIN_BUILD_ARGV))
            # A real build number: the script prints "BUILD=.|KBS=" when the registry read fails.
            return not res.transport_error and res.returncode == 0 and bool(re.search(r"BUILD=\d+\.\d+", res.stdout))
    except Exception:  # noqa: BLE001 - a crashing transport means "not confirmed"
        return False
    return False


def _component_purl(facts: dict[str, str]) -> str:
    """Package URL of an installed package: pkg:<type>/<namespace>/<name>@<version>[?epoch=N].

    Matches how Trivy names OS packages (epoch as a qualifier, not in the version). No arch/distro
    qualifiers, so the statement applies to that package version whatever the scanner adds.
    """
    name = urllib.parse.quote(facts.get("name", ""), safe="+")
    version = urllib.parse.quote(facts.get("version", ""), safe="+~")
    namespace = urllib.parse.quote(facts.get("namespace", ""), safe="")
    path = f"{namespace}/{name}" if namespace else name
    purl = f"pkg:{facts.get('purl_type', 'generic')}/{path}@{version}"
    if facts.get("epoch"):
        purl += f"?epoch={urllib.parse.quote(facts['epoch'], safe='')}"
    return purl


def evaluate_host(spec: CheckSpec, runner: HostRunner) -> HostVerdict:
    """Evaluate all preconditions in `spec` against `runner`."""
    host_os = getattr(runner, "os_family", "linux").lower()
    spec_os = (spec.os_family or "linux").lower()
    if host_os not in ("linux", "windows") or spec_os not in ("linux", "windows"):
        return HostVerdict(
            host=runner.host_name,
            cve_id=spec.cve_id,
            status=VerdictStatus.UNDER_INVESTIGATION,
            reason=f"Unsupported or unknown OS family (host='{host_os}', spec='{spec_os}')",
            justification=None,
            probe_results=[],
            mitigation=list(spec.mitigation),
            patch=spec.patch,
            os_family=host_os,
        )
    if not spec.preconditions and spec.source == "fallback":
        return HostVerdict(
            host=runner.host_name,
            cve_id=spec.cve_id,
            status=VerdictStatus.UNDER_INVESTIGATION,
            reason="Advisory did not yield any deterministic preconditions to probe",
            justification=None,
            probe_results=[],
            mitigation=list(spec.mitigation),
            patch=spec.patch,
            os_family=host_os,
        )
    if spec_os != host_os:
        if spec.os_source not in ("curated", "structured"):
            reason = (
                f"{spec.cve_id} targets '{spec_os}' only according to advisory text heuristics; "
                f"host OS family is '{host_os}', manual review required"
            )
        elif not _confirm_host_os(runner, host_os):
            reason = (
                f"Host OS family '{host_os}' could not be confirmed by a probe; "
                f"{spec.cve_id} targets '{spec_os}'"
            )
        else:
            return HostVerdict(
                host=runner.host_name,
                cve_id=spec.cve_id,
                status=VerdictStatus.NOT_AFFECTED,
                reason=f"Host OS family is '{host_os}' (confirmed), whereas {spec.cve_id} targets '{spec_os}'",
                justification=VexJustification.COMPONENT_NOT_PRESENT,
                probe_results=[],
                mitigation=[],
                patch=spec.patch,
                os_family=host_os,
            )
        return HostVerdict(
            host=runner.host_name,
            cve_id=spec.cve_id,
            status=VerdictStatus.UNDER_INVESTIGATION,
            reason=reason,
            justification=None,
            probe_results=[],
            mitigation=list(spec.mitigation),
            patch=spec.patch,
            os_family=host_os,
        )

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
            os_family=host_os,
        )

    results: list[ProbeResult] = []
    first_not_met: ProbeResult | None = None
    first_weak_not_met: ProbeResult | None = None
    first_unknown: ProbeResult | None = None

    # Intentionally execute all preconditions (no short-circuit) so `probe_results`
    # preserves a complete, auditable record of every check run on the host.
    for pre in spec.preconditions:
        res = run_probe(pre, runner)
        results.append(res)
        if res.status == ProbeStatus.NOT_MET:
            if pre.origin in NON_AUTHORITATIVE_ORIGINS:
                if first_weak_not_met is None:
                    first_weak_not_met = res
            elif first_not_met is None:
                first_not_met = res
        elif res.status == ProbeStatus.UNKNOWN and first_unknown is None:
            first_unknown = res

    component_purl = next((_component_purl(r.facts) for r in results if r.facts.get("name")), None)

    if first_not_met is not None:
        just = first_not_met.precondition.justification_if_not_met
        if first_not_met.precondition.probe == "package_installed_vulnerable":
            if "is not installed" in first_not_met.evidence:
                just = VexJustification.COMPONENT_NOT_PRESENT
            elif ">= fixed version" in first_not_met.evidence:
                just = VexJustification.VULNERABLE_CODE_NOT_PRESENT
        return HostVerdict(
            host=runner.host_name,
            cve_id=spec.cve_id,
            status=VerdictStatus.NOT_AFFECTED,
            reason=first_not_met.evidence,
            justification=just,
            probe_results=results,
            mitigation=[],
            patch=spec.patch,
            os_family=host_os,
            component_purl=component_purl,
        )

    if first_weak_not_met is not None:
        live_patch = resolve_host_patch_info(spec, runner)
        return HostVerdict(
            host=runner.host_name,
            cve_id=spec.cve_id,
            status=VerdictStatus.UNDER_INVESTIGATION,
            reason=(
                f"Only heuristic/LLM-proposed checks were NOT_MET ({first_weak_not_met.precondition.probe}): "
                f"{first_weak_not_met.evidence}"
            ),
            justification=None,
            probe_results=results,
            mitigation=list(spec.mitigation),
            patch=live_patch,
            os_family=host_os,
            component_purl=component_purl,
        )

    if first_unknown is not None:
        live_patch = resolve_host_patch_info(spec, runner)
        return HostVerdict(
            host=runner.host_name,
            cve_id=spec.cve_id,
            status=VerdictStatus.UNDER_INVESTIGATION,
            reason=f"Indeterminate check ({first_unknown.precondition.probe}): {first_unknown.evidence}",
            justification=None,
            probe_results=results,
            mitigation=list(spec.mitigation),
            patch=live_patch,
            os_family=host_os,
            component_purl=component_purl,
        )

    if spec.confidence.lower() != "high":
        met_summaries = "; ".join(r.evidence for r in results)
        live_patch = resolve_host_patch_info(spec, runner)
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
            patch=live_patch,
            os_family=host_os,
            component_purl=component_purl,
        )

    met_summaries = "; ".join(r.evidence for r in results)
    live_patch = resolve_host_patch_info(spec, runner)
    return HostVerdict(
        host=runner.host_name,
        cve_id=spec.cve_id,
        status=VerdictStatus.AFFECTED,
        reason=met_summaries,
        justification=None,
        probe_results=results,
        mitigation=list(spec.mitigation),
        patch=live_patch,
        os_family=host_os,
        component_purl=component_purl,
    )


def ensure_unique_host_names(runners: list[HostRunner]) -> None:
    """Host names identify verdict rows and VEX products; two targets sharing one name would merge
    into contradictory statements about "the same" host, so they are refused."""
    names = [r.host_name for r in runners]
    dups = sorted({n for n in names if names.count(n) > 1})
    if dups:
        raise ValueError(f"Duplicate host name(s) in the target list: {', '.join(dups)}; host names must be unique")


def evaluate_fleet(
    specs: list[CheckSpec],
    runners: list[HostRunner],
) -> list[HostVerdict]:
    """Evaluate every CheckSpec across all target HostRunners."""
    ensure_unique_host_names(runners)
    verdicts: list[HostVerdict] = []
    for spec in specs:
        for runner in runners:
            verdicts.append(evaluate_host(spec, runner))
    return verdicts
