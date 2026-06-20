"""Combine the per-dimension scores into one weighted overall risk score."""

from __future__ import annotations

from depwatch.core.models import PackageSignals, RiskScore
from depwatch.scoring.bands import CRITICAL_RISK_FLOOR, HIGH_RISK_FLOOR
from depwatch.scoring.dimensions import (
    score_adoption,
    score_bus_factor,
    score_license,
    score_maintenance,
    score_vulnerabilities,
)

# How much each dimension contributes to the overall score. Tunable in one place.
DEFAULT_WEIGHTS: dict[str, float] = {
    "vulnerabilities": 0.35,
    "maintenance": 0.20,
    "bus_factor": 0.15,
    "adoption": 0.15,
    "license": 0.15,
}

# CVSS base-score boundaries for the qualitative "high" and "critical" bands.
_HIGH_CVSS = 7.0
_CRITICAL_CVSS = 9.0


def score_package(signals: PackageSignals, weights: dict[str, float] | None = None) -> RiskScore:
    weights = weights or DEFAULT_WEIGHTS
    dimensions = [
        score_vulnerabilities(signals),
        score_maintenance(signals),
        score_bus_factor(signals),
        score_adoption(signals),
        score_license(signals),
    ]
    total_weight = sum(weights[d.name] for d in dimensions)
    overall = sum(weights[d.name] * d.score for d in dimensions) / total_weight
    return RiskScore(overall=max(overall, _severity_floor(signals)), dimensions=dimensions)


def _severity_floor(signals: PackageSignals) -> float:
    """A known high/critical vulnerability can't be diluted below that band by good health."""
    if signals.vulnerability_count == 0 or signals.highest_severity is None:
        return 0.0
    if signals.highest_severity >= _CRITICAL_CVSS:
        return CRITICAL_RISK_FLOOR
    if signals.highest_severity >= _HIGH_CVSS:
        return HIGH_RISK_FLOOR
    return 0.0
