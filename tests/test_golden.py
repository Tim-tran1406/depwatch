"""Golden tests against real package signals.

These signals were captured from the live APIs (June 2026) and frozen here, so the
test is deterministic but the inputs are real. They assert the engine ranks real
packages the way a human reviewer would, rather than checking exact numbers.
"""

from depwatch.core.models import PackageSignals
from depwatch.scoring.score import score_package

# urllib3 1.26.5 — an old pin carrying many known advisories.
URLLIB3_OLD = PackageSignals(
    name="urllib3",
    version="1.26.5",
    is_direct=True,
    vulnerability_count=11,
    highest_severity=8.1,
    vulnerability_ids=["CVE-2024-37891"],
    contributor_count=100,
    days_since_last_release=43,
    monthly_downloads=1_645_798_007,
    license="MIT",
)

# werkzeug 3.1.8 — current, popular, well-staffed, no known vulnerabilities.
WERKZEUG_HEALTHY = PackageSignals(
    name="werkzeug",
    version="3.1.8",
    is_direct=False,
    vulnerability_count=0,
    contributor_count=100,
    days_since_last_release=78,
    monthly_downloads=242_061_810,
    license="BSD-3-Clause",
)

# itsdangerous 2.2.0 — fine to use, but not released in over two years.
ITSDANGEROUS_STALE = PackageSignals(
    name="itsdangerous",
    version="2.2.0",
    is_direct=False,
    vulnerability_count=0,
    contributor_count=44,
    days_since_last_release=794,
    monthly_downloads=195_788_196,
    license="BSD-3-Clause",
)


def test_vulnerable_old_package_outranks_healthy_one() -> None:
    assert score_package(URLLIB3_OLD).overall > score_package(WERKZEUG_HEALTHY).overall


def test_stale_package_outranks_fresh_one() -> None:
    assert score_package(ITSDANGEROUS_STALE).overall > score_package(WERKZEUG_HEALTHY).overall


def test_healthy_popular_package_is_low_risk() -> None:
    assert score_package(WERKZEUG_HEALTHY).overall < 0.1


def test_known_vulnerable_pin_is_clearly_flagged() -> None:
    assert score_package(URLLIB3_OLD).overall > 0.25
