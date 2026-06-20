"""Render a scan result as a readable terminal report, or as JSON.

The overall score ranks the packages; the report leans on the per-dimension
reasons to explain *why* each flagged package is risky, so a real finding (a
known vulnerability, a long-stale release) is never hidden behind one number.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from depwatch.core.models import ScanDiff, ScanResult, ScoredPackage
from depwatch.report.summary import (
    dominant_driver,
    high_risk_count,
    key_finding,
    select_risky,
)
from depwatch.scoring.bands import RiskBand, classify

# How each kind of change is marked and coloured, worst news first.
_CHANGE_STYLE: dict[str, tuple[str, str]] = {
    "worsened": ("▲", "red"),
    "added": ("+", "yellow"),
    "removed": ("-", "dim"),
    "improved": ("✓", "green"),
}
_CHANGE_ORDER = ["worsened", "added", "removed", "improved"]

# Band -> (label shown in the table, rich style).
_BAND_STYLE: dict[RiskBand, tuple[str, str]] = {
    RiskBand.LOW: ("LOW", "green"),
    RiskBand.MODERATE: ("MODERATE", "yellow"),
    RiskBand.HIGH: ("HIGH", "red"),
    RiskBand.CRITICAL: ("CRITICAL", "bold white on red"),
}


def render_scan(console: Console, result: ScanResult, *, limit: int = 10) -> None:
    """Print the report: a summary panel, then the riskiest packages."""
    if not result.packages:
        console.print("No packages to scan.")
        _print_skipped(console, result)
        return
    console.print(_summary_panel(result))
    _print_skipped(console, result)
    risky = select_risky(result.packages)
    if not risky:
        console.print(f"[green]All {len(result.packages)} packages look low-risk.[/green]")
        return
    console.print(_risk_table(risky[:limit]))
    _print_footer(console, result, risky, limit)


def _print_skipped(console: Console, result: ScanResult) -> None:
    if result.skipped:
        console.print(
            f"[yellow]⚠ {result.skipped} package(s) could not be scanned — "
            f"a data source may be down, so results may be incomplete.[/yellow]"
        )


def scan_to_json(result: ScanResult) -> str:
    """Serialise the full result for piping into other tools."""
    return result.model_dump_json(indent=2)


def render_diff(console: Console, diff: ScanDiff) -> None:
    """Print what changed since the previous scan."""
    if not diff.changes:
        console.print(f"[dim]No changes since scan #{diff.previous_scan_id}.[/dim]")
        return
    console.print(f"\n[bold]Changes since scan #{diff.previous_scan_id}:[/bold]")
    for change in sorted(diff.changes, key=lambda c: _CHANGE_ORDER.index(c.status)):
        marker, style = _CHANGE_STYLE[change.status]
        console.print(f"  [{style}]{marker} {change.name:<18}[/{style}] {change.detail}")


def _summary_panel(result: ScanResult) -> Panel:
    total = len(result.packages)
    high = high_risk_count(result.packages)
    lines = [f"Scanned [bold]{total}[/bold] package(s) from [cyan]{result.source}[/cyan]"]
    detail = f"[bold]{high}[/bold] high-risk"
    driver = dominant_driver(result.packages)
    if driver:
        detail += f"  ·  top risk driver: [bold]{driver}[/bold]"
    if result.scan_id is not None:
        detail += f"  ·  saved as scan #{result.scan_id}"
    lines.append(detail)
    return Panel("\n".join(lines), title="depwatch", title_align="left", expand=False)


def _risk_table(packages: list[ScoredPackage]) -> Table:
    table = Table(show_edge=False, header_style="bold", pad_edge=False)
    table.add_column("#", justify="right")
    table.add_column("Package")
    table.add_column("Version")
    table.add_column("Type")
    table.add_column("Risk")
    table.add_column("Key finding")
    for rank, package in enumerate(packages, start=1):
        label, style = _BAND_STYLE[classify(package.risk.overall)]
        risk = Text(f"{label:<8} {package.risk.overall:.2f}", style=style)
        kind = "direct" if package.signals.is_direct else "transitive"
        table.add_row(
            str(rank),
            package.signals.name,
            package.signals.version,
            kind,
            risk,
            key_finding(package),
        )
    return table


def _print_footer(
    console: Console, result: ScanResult, risky: list[ScoredPackage], limit: int
) -> None:
    if len(risky) > limit:
        hidden = len(risky) - limit
        console.print(f"[dim]… and {hidden} more risky package(s) not shown (raise --limit).[/dim]")
    low = len(result.packages) - len(risky)
    if low:
        console.print(f"[dim]{low} package(s) look low-risk.[/dim]")
