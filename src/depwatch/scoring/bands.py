"""Turn a numeric risk score into a named band.

One shared vocabulary so everything agrees on what "high risk" means: the report
colours packages by band, and the stored scan summary counts the high-risk ones
using the same floor.
"""

from __future__ import annotations

from enum import StrEnum

# Lower bound of each band on the 0 (safe) to 1 (risky) scale.
_MODERATE_FLOOR = 0.15
_HIGH_FLOOR = 0.30
_CRITICAL_FLOOR = 0.50

# At or above this overall score, a package is "high risk" (high or critical).
HIGH_RISK_FLOOR = _HIGH_FLOOR


class RiskBand(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


# Bands from safest to riskiest, so thresholds can be compared by position.
_SEVERITY = (RiskBand.LOW, RiskBand.MODERATE, RiskBand.HIGH, RiskBand.CRITICAL)


class FailOn(StrEnum):
    """The risk gate: fail the scan once the worst band reaches this level."""

    OFF = "off"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


def classify(score: float) -> RiskBand:
    """Map an overall risk score to its band."""
    if score >= _CRITICAL_FLOOR:
        return RiskBand.CRITICAL
    if score >= _HIGH_FLOOR:
        return RiskBand.HIGH
    if score >= _MODERATE_FLOOR:
        return RiskBand.MODERATE
    return RiskBand.LOW


def should_fail(worst: RiskBand, threshold: FailOn) -> bool:
    """Whether a scan whose riskiest package is ``worst`` trips the ``threshold`` gate."""
    if threshold is FailOn.OFF:
        return False
    return _SEVERITY.index(worst) >= _SEVERITY.index(RiskBand(threshold.value))
