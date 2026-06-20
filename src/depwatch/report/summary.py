"""Format-agnostic helpers shared by the terminal, Markdown and HTML reports.

Each output format differs only in how it draws things; what counts as risky, what
the headline finding is, and which dimension dominates are decided once here.
"""

from __future__ import annotations

from depwatch.core.models import ScoredPackage
from depwatch.scoring.bands import RiskBand, classify

_HIGH_BANDS = (RiskBand.HIGH, RiskBand.CRITICAL)


def select_risky(packages: list[ScoredPackage]) -> list[ScoredPackage]:
    """The packages worth showing — anything above the low band."""
    return [p for p in packages if classify(p.risk.overall) != RiskBand.LOW]


def high_risk_count(packages: list[ScoredPackage]) -> int:
    """How many packages land in the high or critical band."""
    return sum(1 for p in packages if classify(p.risk.overall) in _HIGH_BANDS)


def key_finding(package: ScoredPackage) -> str:
    """The reason from the dimension driving this package's risk."""
    top = max(package.risk.dimensions, key=lambda d: d.score)
    return top.reason if top.score > 0 else "—"


def dominant_driver(packages: list[ScoredPackage]) -> str | None:
    """The dimension contributing the most risk across the whole scan."""
    totals: dict[str, float] = {}
    for package in packages:
        for dimension in package.risk.dimensions:
            totals[dimension.name] = totals.get(dimension.name, 0.0) + dimension.score
    if not totals:
        return None
    name, total = max(totals.items(), key=lambda item: item[1])
    return name if total > 0 else None


def worst_band(packages: list[ScoredPackage]) -> RiskBand:
    """The band of the riskiest package, used by the CI gate."""
    return classify(max((p.risk.overall for p in packages), default=0.0))
