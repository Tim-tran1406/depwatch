from typing import Any

from depwatch.core.models import PackageSignals
from depwatch.scoring.score import DEFAULT_WEIGHTS, score_package


def _signals(**kwargs: Any) -> PackageSignals:
    return PackageSignals(name="x", version="1.0", is_direct=True, **kwargs)


def test_healthy_package_scores_low() -> None:
    signals = _signals(
        vulnerability_count=0,
        days_since_last_release=20,
        contributor_count=10,
        monthly_downloads=50_000_000,
        license="MIT",
    )
    assert score_package(signals).overall < 0.1


def test_risky_package_scores_high() -> None:
    signals = _signals(
        vulnerability_count=5,
        highest_severity=9.5,
        days_since_last_release=1500,
        contributor_count=1,
        monthly_downloads=10,
        license=None,
    )
    assert score_package(signals).overall > 0.8


def test_overall_is_the_weighted_average_of_dimensions() -> None:
    signals = _signals(vulnerability_count=2, days_since_last_release=400, monthly_downloads=1000)
    risk = score_package(signals)
    expected = sum(DEFAULT_WEIGHTS[d.name] * d.score for d in risk.dimensions) / sum(
        DEFAULT_WEIGHTS.values()
    )
    assert abs(risk.overall - expected) < 1e-9


def test_reports_all_five_dimensions() -> None:
    risk = score_package(_signals())
    assert {d.name for d in risk.dimensions} == {
        "vulnerabilities",
        "maintenance",
        "bus_factor",
        "adoption",
        "license",
    }
