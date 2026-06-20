"""Command-line entry point for depwatch."""

from __future__ import annotations

from pathlib import Path

import typer

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
) -> None:
    """Scan a requirements file and print a risk report."""
    typer.echo(f"Scanning {requirements} ... (the scoring pipeline lands in a later part)")


if __name__ == "__main__":
    app()
