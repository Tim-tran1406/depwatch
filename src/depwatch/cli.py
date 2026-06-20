"""Command-line entry point for depwatch."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import typer
from rich.console import Console

from depwatch import service
from depwatch.config import settings
from depwatch.core.models import ScanResult
from depwatch.report.html import scan_to_html
from depwatch.report.markdown import scan_to_markdown
from depwatch.report.render import render_diff, render_scan, scan_to_json
from depwatch.report.sarif import scan_to_sarif
from depwatch.report.summary import worst_band
from depwatch.scoring.bands import FailOn, should_fail

app = typer.Typer(
    help="Scan Python dependencies and rank the ones that are actually risky.",
    no_args_is_help=True,
)


class OutputFormat(StrEnum):
    TABLE = "table"
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    SARIF = "sarif"


@app.callback()
def main() -> None:
    """depwatch reads a requirements file and ranks its dependencies by risk."""


@app.command()
def scan(
    requirements: Path = typer.Argument(
        ..., exists=True, readable=True, help="Path to a requirements.txt file."
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", "-f", help="How to render the report."
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write the report to a file instead of stdout."
    ),
    limit: int = typer.Option(10, "--limit", "-n", help="How many risky packages to show."),
    save: bool = typer.Option(True, help="Save this scan to the local database."),
    fail_on: FailOn = typer.Option(
        FailOn.OFF, "--fail-on", help="Exit non-zero when the worst risk reaches this band."
    ),
    since_last: bool = typer.Option(
        False, "--since-last", help="Show what changed since the previous scan of this file."
    ),
    fail_on_incomplete: bool = typer.Option(
        False, "--fail-on-incomplete", help="Exit non-zero if any package could not be scanned."
    ),
) -> None:
    """Scan a requirements file and report the riskiest dependencies."""
    result = service.run_scan(requirements, settings, save=save)
    _emit(result, output_format, output, limit, requirements)
    if since_last and output_format is OutputFormat.TABLE and output is None:
        diff = service.diff_against_previous(result, settings)
        console = Console()
        if diff is None:
            console.print("[dim]No previous scan of this file to compare against.[/dim]")
        else:
            render_diff(console, diff)
    risk_gate = should_fail(worst_band(result.packages), fail_on)
    incomplete_gate = fail_on_incomplete and result.skipped > 0
    if risk_gate or incomplete_gate:
        raise typer.Exit(code=1)


def _emit(
    result: ScanResult,
    output_format: OutputFormat,
    output: Path | None,
    limit: int,
    requirements: Path,
) -> None:
    if output_format is OutputFormat.TABLE and output is None:
        render_scan(Console(), result, limit=limit)
        return
    if output_format is OutputFormat.TABLE:
        console = Console(width=100, force_terminal=False)
        with console.capture() as capture:
            render_scan(console, result, limit=limit)
        text = capture.get()
    elif output_format is OutputFormat.JSON:
        text = scan_to_json(result)
    elif output_format is OutputFormat.MARKDOWN:
        text = scan_to_markdown(result, limit=limit)
    elif output_format is OutputFormat.SARIF:
        text = scan_to_sarif(result, requirements)
    else:
        text = scan_to_html(result, limit=limit)

    if output is not None:
        output.write_text(text, encoding="utf-8")
    else:
        print(text)


if __name__ == "__main__":
    app()
