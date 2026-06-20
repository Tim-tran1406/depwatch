from datetime import datetime
from typing import Any

from depwatch.core.models import PackageSignals, ScoredPackage
from depwatch.report.summary import (
    dominant_driver,
    high_risk_count,
    key_finding,
    select_risky,
    worst_band,
)
from depwatch.scoring.bands import RiskBand
from depwatch.scoring.score import score_package

DATE = datetime(2026, 6, 20, 12, 0, 0)


def _scored(name: str, **kwargs: Any) -> ScoredPackage:
    signals = PackageSignals(name=name, version="1.0", is_direct=True, **kwargs)
    return ScoredPackage(signals=signals, risk=score_package(signals))


VULNERABLE = _scored("urllib3", vulnerability_count=11)
HEALTHY = _scored(
    "werkzeug",
    vulnerability_count=0,
    days_since_last_release=20,
    contributor_count=80,
    monthly_downloads=200_000_000,
    license="BSD-3-Clause",
)


def test_select_risky_drops_low_risk_packages() -> None:
    risky = select_risky([VULNERABLE, HEALTHY])
    assert [p.signals.name for p in risky] == ["urllib3"]


def test_high_risk_count_counts_high_and_critical() -> None:
    assert high_risk_count([VULNERABLE, HEALTHY]) == 1
    assert high_risk_count([HEALTHY]) == 0


def test_key_finding_is_the_dominant_dimension_reason() -> None:
    assert "11 known vulnerabilities" in key_finding(VULNERABLE)
    assert key_finding(HEALTHY) == "—"


def test_dominant_driver_picks_the_hottest_dimension() -> None:
    assert dominant_driver([VULNERABLE]) == "vulnerabilities"
    assert dominant_driver([HEALTHY]) is None
    assert dominant_driver([]) is None


def test_worst_band_reflects_the_riskiest_package() -> None:
    assert worst_band([HEALTHY]) is RiskBand.LOW
    assert worst_band([VULNERABLE, HEALTHY]) is not RiskBand.LOW
    assert worst_band([]) is RiskBand.LOW
