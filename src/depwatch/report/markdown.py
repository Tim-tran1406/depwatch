"""Render a scan result as GitHub-flavoured Markdown.

Used for the CI job summary: the GitHub Action appends this to the run summary so
a pull request shows the risky dependencies inline.
"""

from __future__ import annotations

from depwatch.core.models import ScanResult
from depwatch.report.summary import (
    any_fix,
    dominant_driver,
    fix_hint,
    high_risk_count,
    key_finding,
    select_risky,
)
from depwatch.scoring.bands import RiskBand, classify

_LABEL: dict[RiskBand, str] = {
    RiskBand.LOW: "LOW",
    RiskBand.MODERATE: "MODERATE",
    RiskBand.HIGH: "HIGH",
    RiskBand.CRITICAL: "CRITICAL",
}


def scan_to_markdown(result: ScanResult, *, limit: int = 10) -> str:
    """The scan as a Markdown report, headline first then a table of the risky packages."""
    lines = ["## depwatch — dependency risk", ""]
    if not result.packages:
        lines.append("_No packages to scan._")
        return "\n".join(lines) + "\n"

    total = len(result.packages)
    lines.append(f"Scanned **{total}** package(s) from `{result.source}`.")
    headline = f"**{high_risk_count(result.packages)}** high-risk"
    driver = dominant_driver(result.packages)
    if driver:
        headline += f" · top risk driver: **{driver}**"
    if result.scan_id is not None:
        headline += f" · saved as scan #{result.scan_id}"
    lines += [headline, ""]
    if result.skipped:
        lines += [
            f"> ⚠️ {result.skipped} package(s) could not be scanned — results may be incomplete.",
            "",
        ]

    risky = select_risky(result.packages)
    if not risky:
        lines.append(f"All **{total}** packages look low-risk. ✅")
        return "\n".join(lines) + "\n"

    show_fix = any_fix(risky)
    if show_fix:
        lines += [
            "| # | Package | Version | Type | Risk | Key finding | Fix |",
            "|--:|---------|---------|------|------|-------------|-----|",
        ]
    else:
        lines += [
            "| # | Package | Version | Type | Risk | Key finding |",
            "|--:|---------|---------|------|------|-------------|",
        ]
    for rank, package in enumerate(risky[:limit], start=1):
        label = _LABEL[classify(package.risk.overall)]
        kind = "direct" if package.signals.is_direct else "transitive"
        finding = key_finding(package).replace("|", "\\|")
        row = (
            f"| {rank} | {package.signals.name} | {package.signals.version} | {kind} "
            f"| **{label}** {package.risk.overall:.2f} | {finding} |"
        )
        if show_fix:
            row += f" {fix_hint(package) or '—'} |"
        lines.append(row)
    lines.append("")
    if len(risky) > limit:
        lines.append(f"_… and {len(risky) - limit} more risky package(s) not shown._")
    low = total - len(risky)
    if low:
        lines.append(f"_{low} package(s) look low-risk._")
    return "\n".join(lines).rstrip() + "\n"
