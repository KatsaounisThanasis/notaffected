"""Rich terminal output for notaffected."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from notaffected.model import CheckSpec, HostVerdict, VerdictStatus


def render_spec(spec: CheckSpec, console: Console | None = None) -> None:
    """Render a CheckSpec (preconditions, mitigations, patch status) to the terminal."""
    con = console or Console()
    title = f"[bold cyan]{spec.cve_id}[/bold cyan] ({spec.severity}) — source: {spec.source}, confidence: {spec.confidence}"
    lines: list[str] = [f"[bold]Summary:[/bold] {spec.summary}", ""]

    lines.append("[bold]Required Attack Preconditions (all must hold for host to be AFFECTED):[/bold]")
    if not spec.preconditions:
        lines.append("  • (None extracted — defaults to under_investigation)")
    else:
        for idx, pre in enumerate(spec.preconditions, start=1):
            lines.append(
                f"  {idx}. [yellow]{pre.probe}[/yellow] {pre.params} — {pre.description} "
                f"[dim](if false -> {pre.justification_if_not_met.value})[/dim]"
            )

    if spec.mitigation:
        lines.append("")
        lines.append("[bold]Temporary Mitigations (until patch is installed):[/bold]")
        for m in spec.mitigation:
            lines.append(f"  $ [green]{m}[/green]")

    lines.append("")
    patch_desc = f"status={spec.patch.status}"
    if spec.patch.fixed_version:
        patch_desc += f", fixed_version={spec.patch.fixed_version}"
    if spec.patch.pocket:
        patch_desc += f", pocket={spec.patch.pocket}"
    lines.append(f"[bold]Patch Status:[/bold] {patch_desc}")

    con.print(Panel("\n".join(lines), title=title, expand=False))


def render_verdicts(
    specs: list[CheckSpec],
    verdicts: list[HostVerdict],
    console: Console | None = None,
) -> None:
    """Render fleet evaluation verdicts grouped by status with concrete proofs."""
    con = console or Console()
    spec_map = {s.cve_id: s for s in specs}

    for spec in specs:
        con.print(
            f"\n[bold cyan]{spec.cve_id}[/bold cyan] [{spec.severity}] — {spec.summary}"
        )
        con.print(
            f"[dim]Source: {spec.source} | Confidence: {spec.confidence} | "
            f"Preconditions: {len(spec.preconditions)}[/dim]"
        )

    affected = [v for v in verdicts if v.status == VerdictStatus.AFFECTED]
    under_inv = [v for v in verdicts if v.status == VerdictStatus.UNDER_INVESTIGATION]
    not_affected = [v for v in verdicts if v.status == VerdictStatus.NOT_AFFECTED]

    con.print("")
    con.print(f"[bold red]AFFECTED ({len(affected)})[/bold red]")
    if not affected:
        con.print("  [dim]None[/dim]")
    for v in affected:
        con.print(f"  • [bold]{v.host}[/bold] ({v.cve_id})")
        con.print(f"    Proof: {v.reason}")
        if v.mitigation:
            con.print("    Temporary Mitigation:")
            for cmd in v.mitigation:
                con.print(f"      $ [yellow]{cmd}[/yellow]")
        spec_obj = spec_map.get(v.cve_id)
        patch = v.patch or (spec_obj.patch if spec_obj else None)
        if patch and (patch.fixed_version or patch.pocket):
            pocket_note = f" in {patch.pocket}" if patch.pocket else ""
            con.print(
                f"    Patch Status: {patch.status} (fixed version: {patch.fixed_version or 'pending'}{pocket_note})"
            )

    if under_inv:
        con.print("")
        con.print(
            f"[bold yellow]UNDER INVESTIGATION ({len(under_inv)})[/bold yellow]"
        )
        for v in under_inv:
            con.print(f"  • [bold]{v.host}[/bold] ({v.cve_id}) — {v.reason}")

    con.print("")
    con.print(f"[bold green]NOT AFFECTED ({len(not_affected)})[/bold green]")
    if not not_affected:
        con.print("  [dim]None[/dim]")
    else:
        table = Table(show_header=True, header_style="bold green", box=None, pad_edge=False)
        table.add_column("Host", style="bold")
        table.add_column("CVE")
        table.add_column("VEX Justification", style="cyan")
        table.add_column("Deterministic Proof")
        for v in not_affected:
            just_str = v.justification.value if v.justification else "n/a"
            table.add_row(v.host, v.cve_id, just_str, v.reason)
        con.print(table)
