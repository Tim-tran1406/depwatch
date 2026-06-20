from collections.abc import Callable
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from depwatch.core.models import DimensionScore, PackageSignals
from depwatch.scoring.dimensions import (
    score_adoption,
    score_bus_factor,
    score_license,
    score_maintenance,
    score_vulnerabilities,
)


def _signals(**kwargs: Any) -> PackageSignals:
    return PackageSignals(name="x", version="1.0", is_direct=True, **kwargs)


# --- vulnerabilities ---


def test_no_vulnerabilities_is_zero() -> None:
    assert score_vulnerabilities(_signals(vulnerability_count=0)).score == 0.0


def test_single_critical_vulnerability_is_high() -> None:
    assert score_vulnerabilities(_signals(vulnerability_count=1, highest_severity=9.8)).score >= 0.9


def test_unknown_severity_assumed_medium() -> None:
    score = score_vulnerabilities(_signals(vulnerability_count=1, highest_severity=None)).score
    assert 0.4 <= score <= 0.6


# --- maintenance ---


def test_recent_release_is_safe() -> None:
    assert score_maintenance(_signals(days_since_last_release=30)).score == 0.0


def test_two_year_old_release_is_max() -> None:
    assert score_maintenance(_signals(days_since_last_release=730)).score == 1.0


def test_unknown_release_date_is_moderate() -> None:
    assert score_maintenance(_signals(days_since_last_release=None)).score == 0.5


# --- bus factor ---


def test_many_contributors_is_safe() -> None:
    assert score_bus_factor(_signals(contributor_count=10)).score == 0.0


def test_single_contributor_is_risky() -> None:
    assert score_bus_factor(_signals(contributor_count=1)).score == 1.0


def test_unknown_contributors_is_moderate() -> None:
    assert score_bus_factor(_signals(contributor_count=None)).score == 0.5


# --- adoption ---


def test_huge_adoption_is_safe() -> None:
    assert score_adoption(_signals(monthly_downloads=10_000_000)).score == 0.0


def test_zero_adoption_is_max() -> None:
    assert score_adoption(_signals(monthly_downloads=0)).score == 1.0


def test_unknown_adoption_is_moderate() -> None:
    # Missing download stats are unknown, not zero — neutral, not max risk.
    assert score_adoption(_signals(monthly_downloads=None)).score == 0.5


# --- license ---


def test_permissive_licenses_are_safe() -> None:
    assert score_license(_signals(license="Apache 2.0")).score == 0.0
    assert score_license(_signals(license="MIT")).score == 0.0
    assert score_license(_signals(license="BSD-3-Clause")).score == 0.0


def test_copyleft_license_is_moderate() -> None:
    assert score_license(_signals(license="GPL-3.0")).score == 0.4
    assert score_license(_signals(license="AGPL-3.0")).score == 0.4
    # Spelled-out names contain no "gpl" abbreviation but are still copyleft.
    assert score_license(_signals(license="GNU General Public License v3")).score == 0.4


def test_missing_license_is_risky() -> None:
    assert score_license(_signals(license=None)).score == 0.7
    assert score_license(_signals(license="UNKNOWN")).score == 0.7
    assert score_license(_signals(license="")).score == 0.7


def test_uncommon_license_is_low_moderate() -> None:
    assert score_license(_signals(license="WeirdLicense-1.0")).score == 0.3


# --- property-based invariants ---

_DIMENSIONS: list[Callable[[PackageSignals], DimensionScore]] = [
    score_vulnerabilities,
    score_maintenance,
    score_bus_factor,
    score_adoption,
    score_license,
]

_signal_strategy = st.builds(
    PackageSignals,
    name=st.just("x"),
    version=st.just("1.0"),
    is_direct=st.booleans(),
    vulnerability_count=st.integers(min_value=0, max_value=50),
    highest_severity=st.one_of(st.none(), st.floats(min_value=0, max_value=10)),
    days_since_last_release=st.one_of(st.none(), st.integers(min_value=0, max_value=5000)),
    monthly_downloads=st.one_of(st.none(), st.integers(min_value=0, max_value=2_000_000_000)),
    contributor_count=st.one_of(st.none(), st.integers(min_value=1, max_value=500)),
    license=st.one_of(st.none(), st.sampled_from(["MIT", "Apache-2.0", "GPL-3.0", "", "Custom"])),
)


@given(_signal_strategy)
def test_every_dimension_score_stays_in_unit_interval(signals: PackageSignals) -> None:
    for scorer in _DIMENSIONS:
        assert 0.0 <= scorer(signals).score <= 1.0


@given(
    base=st.integers(min_value=0, max_value=20),
    extra=st.integers(min_value=0, max_value=20),
    severity=st.floats(min_value=0, max_value=10),
)
def test_more_vulnerabilities_never_lowers_risk(base: int, extra: int, severity: float) -> None:
    low = score_vulnerabilities(_signals(vulnerability_count=base, highest_severity=severity)).score
    high = score_vulnerabilities(
        _signals(vulnerability_count=base + extra, highest_severity=severity)
    ).score
    assert high >= low


@given(a=st.integers(min_value=0, max_value=5000), b=st.integers(min_value=0, max_value=5000))
def test_older_release_never_lowers_maintenance_risk(a: int, b: int) -> None:
    younger, older = sorted((a, b))
    assert (
        score_maintenance(_signals(days_since_last_release=older)).score
        >= score_maintenance(_signals(days_since_last_release=younger)).score
    )


@given(
    a=st.integers(min_value=0, max_value=2_000_000_000),
    b=st.integers(min_value=0, max_value=2_000_000_000),
)
def test_more_downloads_never_raises_adoption_risk(a: int, b: int) -> None:
    fewer, more = sorted((a, b))
    assert (
        score_adoption(_signals(monthly_downloads=more)).score
        <= score_adoption(_signals(monthly_downloads=fewer)).score
    )


@given(a=st.integers(min_value=1, max_value=500), b=st.integers(min_value=1, max_value=500))
def test_more_contributors_never_raises_bus_factor_risk(a: int, b: int) -> None:
    fewer, more = sorted((a, b))
    assert (
        score_bus_factor(_signals(contributor_count=more)).score
        <= score_bus_factor(_signals(contributor_count=fewer)).score
    )
