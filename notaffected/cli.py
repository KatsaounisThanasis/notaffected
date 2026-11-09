"""CLI entrypoint for `notaffected`."""

from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console

from notaffected import __version__
from notaffected.advisories.ai_advisor import build_remediation_briefing
from notaffected.advisories.builtin_specs import BUILTIN_SPECS
from notaffected.advisories.extractor import resolve_check_spec
from notaffected.advisories.fetcher import fetch_advisories_concurrent
from notaffected.engine.evaluator import evaluate_fleet
from notaffected.importers.scanners import parse_scanner_json
from notaffected.inventory import load_demo_fleet, load_runners
from notaffected.model import CheckSpec
from notaffected.render.console import render_ai_briefing, render_spec, render_verdicts
from notaffected.render.html import write_html_report
from notaffected.render.json_out import write_json_report
from notaffected.render.vex import write_openvex


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="notaffected",
        description=(
            "Deterministically prove whether CVEs actually affect your Linux hosts "
            "and emit OpenVEX v0.2.0."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"notaffected {__version__}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # `notaffected check`
    p_check = sub.add_parser(
        "check",
        help="Check one or more CVE IDs against local or SSH hosts",
    )
    p_check.add_argument("cves", nargs="+", help="CVE ID(s) to evaluate (e.g. CVE-2026-98432)")
    _add_target_and_output_args(p_check)

    # `notaffected filter`
    p_filter = sub.add_parser(
        "filter",
        help="Filter a Trivy or Grype JSON scan report against real host state",
    )
    p_filter.add_argument("scan_file", type=Path, help="Path to Trivy or Grype JSON output")
    _add_target_and_output_args(p_filter)

    # `notaffected spec`
    p_spec = sub.add_parser(
        "spec",
        help="Inspect the extracted attack preconditions and mitigations for a CVE",
    )
    p_spec.add_argument("cve", help="CVE ID to inspect (e.g. CVE-2026-98432)")
    p_spec.add_argument(
        "--llm",
        action="store_true",
        help="Use configured local/OpenAI-compatible LLM to extract preconditions from prose",
    )

    return parser


def _add_target_and_output_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--host",
        default=None,
        help="Target host ('local' or SSH destination, default: local)",
    )
    p.add_argument(
        "--ssh",
        action="append",
        dest="ssh_targets",
        default=None,
        help="Remote SSH target (user@host); may be passed multiple times",
    )
    p.add_argument(
        "--win-ssh",
        action="append",
        dest="win_ssh_targets",
        default=None,
        help="Remote Windows OpenSSH target (user@win-host); executes read-only PowerShell probes",
    )
    p.add_argument(
        "--docker",
        action="append",
        dest="docker_targets",
        default=None,
        help="Running Docker container name/ID to probe via 'docker exec'",
    )
    p.add_argument(
        "--k8s",
        action="append",
        dest="k8s_targets",
        default=None,
        help="Kubernetes pod ('pod' or 'namespace/pod') to probe via 'kubectl exec'",
    )
    p.add_argument(
        "-i",
        "--inventory",
        type=Path,
        default=None,
        help="Path to YAML or host-list inventory file",
    )
    p.add_argument(
        "--demo-fleet",
        action="store_true",
        help="Run against a built-in 3-host simulated fleet (laptop, exposed server, patched DB)",
    )
    p.add_argument(
        "--emit-vex",
        type=Path,
        default=None,
        help="Write OpenVEX v0.2.0 statements to this JSON file",
    )
    p.add_argument(
        "--json",
        dest="json_out",
        type=Path,
        default=None,
        help="Write full audit report (specs + verdicts + probe evidence) to JSON file",
    )
    p.add_argument(
        "--html",
        dest="html_out",
        type=Path,
        default=None,
        help="Write standalone interactive HTML report to this file",
    )
    p.add_argument(
        "--llm",
        action="store_true",
        help="Allow optional local/configured LLM to extract preconditions for unknown CVEs",
    )
    p.add_argument(
        "--ai-explain",
        action="store_true",
        help="Generate a post-verdict AI/operational risk and remediation safety briefing",
    )
    p.add_argument(
        "--fail-on-affected",
        action="store_true",
        help="Exit with code 1 if any host is AFFECTED",
    )


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    console = Console()

    if args.command == "spec":
        spec = resolve_check_spec(args.cve, use_llm=args.llm)
        render_spec(spec, console=console)
        return 0

    if args.command == "check":
        non_builtin = [c for c in args.cves if c.strip().upper() not in BUILTIN_SPECS]
        if len(non_builtin) > 1:
            fetch_advisories_concurrent(non_builtin)
        specs: list[CheckSpec] = [
            resolve_check_spec(cve, use_llm=args.llm) for cve in args.cves
        ]
    elif args.command == "filter":
        findings = parse_scanner_json(args.scan_file)
        non_builtin = [
            f.cve_id for f in findings if f.cve_id.strip().upper() not in BUILTIN_SPECS
        ]
        if len(non_builtin) > 1:
            fetch_advisories_concurrent(non_builtin)
        specs = []
        seen_cves: set[str] = set()
        for f in findings:
            if f.cve_id in seen_cves:
                continue
            seen_cves.add(f.cve_id)
            specs.append(
                resolve_check_spec(
                    f.cve_id,
                    use_llm=args.llm,
                    package_hint=f.package_name,
                    fixed_version_hint=f.fixed_version,
                )
            )
    else:
        return 2

    if args.demo_fleet:
        runners = load_demo_fleet()
    else:
        runners = load_runners(
            host=args.host,
            ssh_targets=args.ssh_targets,
            win_ssh_targets=args.win_ssh_targets,
            docker_targets=args.docker_targets,
            k8s_targets=args.k8s_targets,
            inventory_path=args.inventory,
        )
    verdicts = evaluate_fleet(specs, runners)
    render_verdicts(specs, verdicts, console=console)

    if args.ai_explain:
        briefing = build_remediation_briefing(specs, verdicts)
        render_ai_briefing(briefing, console=console)

    if args.emit_vex:
        write_openvex(verdicts, args.emit_vex)
        console.print(
            f"\n[bold cyan]OpenVEX v0.2.0 written to:[/bold cyan] {args.emit_vex} "
            f"({len(verdicts)} statement(s))"
        )

    if args.json_out:
        write_json_report(specs, verdicts, args.json_out)
        console.print(
            f"[bold cyan]JSON audit report written to:[/bold cyan] {args.json_out}"
        )

    if args.html_out:
        write_html_report(specs, verdicts, args.html_out)
        console.print(
            f"[bold cyan]Standalone HTML report written to:[/bold cyan] {args.html_out}"
        )

    if args.fail_on_affected and any(v.status.value == "affected" for v in verdicts):
        return 1
    return 0
