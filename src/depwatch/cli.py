"""Command-line entry point for depwatch."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from depwatch import service
from depwatch.config import settings
from depwatch.report.render import render_scan, scan_to_json

app = typer.Typer(
    help="Scan Python dependencies and rank the ones that are actually risky.",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """depwatch reads a requirements file and ranks its dependencies by risk."""


@app.command()
def scan(
    requirements: Path = typer.Argument(
        ..., exists=True, readable=True, help="Path to a requirements.txt file."
    ),
    limit: int = typer.Option(10, "--limit", "-n", help="How many risky packages to show."),
    save: bool = typer.Option(True, help="Save this scan to the local database."),
    as_json: bool = typer.Option(
        False, "--json", help="Print the result as JSON instead of a table."
    ),
) -> None:
    """Scan a requirements file and report the riskiest dependencies."""
    result = service.run_scan(requirements, settings, save=save)
    if as_json:
        print(scan_to_json(result))
    else:
        render_scan(Console(), result, limit=limit)


if __name__ == "__main__":
    app()
