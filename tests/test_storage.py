from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from depwatch.core.models import PackageSignals, ScoredPackage
from depwatch.scoring.score import score_package
from depwatch.storage.store import HIGH_RISK_THRESHOLD, ScanStore

T0 = datetime(2026, 6, 20, 12, 0, 0)
T1 = datetime(2026, 6, 21, 9, 30, 0)


def _scored(name: str, **kwargs: Any) -> ScoredPackage:
    """Build a ScoredPackage by running real signals through the real scorer."""
    signals = PackageSignals(
        name=name,
        version=kwargs.pop("version", "1.0"),
        is_direct=kwargs.pop("is_direct", True),
        **kwargs,
    )
    return ScoredPackage(signals=signals, risk=score_package(signals))


# A clearly risky package and a clearly healthy one, scored for real.
RISKY = _scored(
    "urllib3",
    version="1.26.5",
    vulnerability_count=11,
    days_since_last_release=1500,
    contributor_count=1,
    monthly_downloads=10,
    license=None,
)
HEALTHY = _scored(
    "werkzeug",
    version="3.1.8",
    is_direct=False,
    vulnerability_count=0,
    days_since_last_release=40,
    contributor_count=80,
    monthly_downloads=200_000_000,
    license="BSD-3-Clause",
)


def test_save_returns_incrementing_ids() -> None:
    with ScanStore() as store:
        first = store.save_scan("req.txt", [HEALTHY], created_at=T0)
        second = store.save_scan("req.txt", [HEALTHY], created_at=T1)
        assert (first, second) == (1, 2)


def test_get_packages_is_ranked_riskiest_first() -> None:
    with ScanStore() as store:
        scan_id = store.save_scan("req.txt", [HEALTHY, RISKY], created_at=T0)
        packages = store.get_packages(scan_id)

        assert [p.name for p in packages] == ["urllib3", "werkzeug"]
        assert packages[0].overall_risk > packages[1].overall_risk


def test_stored_package_round_trips_signals_and_dimensions() -> None:
    with ScanStore() as store:
        scan_id = store.save_scan("req.txt", [RISKY], created_at=T0)
        package = store.get_packages(scan_id)[0]

        assert package.version == "1.26.5"
        assert package.is_direct is True
        assert package.vulnerability_count == 11
        assert package.contributor_count == 1
        assert package.monthly_downloads == 10
        assert package.license is None
        # All five dimensions are stored, hottest first.
        assert {d.name for d in package.dimensions} == {
            "vulnerabilities",
            "maintenance",
            "bus_factor",
            "adoption",
            "license",
        }
        scores = [d.score for d in package.dimensions]
        assert scores == sorted(scores, reverse=True)


def test_nullable_signals_round_trip_as_none() -> None:
    with ScanStore() as store:
        scan_id = store.save_scan(
            "req.txt",
            [
                _scored(
                    "mystery", contributor_count=None, days_since_last_release=None, license=None
                )
            ],
            created_at=T0,
        )
        package = store.get_packages(scan_id)[0]
        assert package.contributor_count is None
        assert package.days_since_last_release is None
        assert package.highest_severity is None
        assert package.license is None


def test_scan_summary_computes_aggregates() -> None:
    with ScanStore() as store:
        scan_id = store.save_scan("req.txt", [RISKY, HEALTHY], created_at=T0)
        summary = store.scan_summary(scan_id)

        assert summary is not None
        assert summary.package_count == 2
        assert summary.source == "req.txt"
        assert summary.created_at == T0
        assert summary.max_risk == max(RISKY.risk.overall, HEALTHY.risk.overall)
        # Only the risky package clears the high-risk threshold.
        assert RISKY.risk.overall >= HIGH_RISK_THRESHOLD > HEALTHY.risk.overall
        assert summary.high_risk_count == 1


def test_scan_summary_is_none_for_unknown_scan() -> None:
    with ScanStore() as store:
        assert store.scan_summary(999) is None


def test_empty_scan_has_safe_aggregates() -> None:
    with ScanStore() as store:
        scan_id = store.save_scan("empty.txt", [], created_at=T0)
        summary = store.scan_summary(scan_id)

        assert summary is not None
        assert summary.package_count == 0
        assert summary.max_risk == 0.0
        assert summary.high_risk_count == 0
        assert store.get_packages(scan_id) == []


def test_list_scans_is_newest_first() -> None:
    with ScanStore() as store:
        store.save_scan("old.txt", [HEALTHY], created_at=T0)
        store.save_scan("new.txt", [RISKY], created_at=T1)

        scans = store.list_scans()
        assert [s.source for s in scans] == ["new.txt", "old.txt"]


def test_latest_scan_for_finds_the_newest_for_a_source() -> None:
    with ScanStore() as store:
        first = store.save_scan("req.txt", [HEALTHY], created_at=T0)
        second = store.save_scan("req.txt", [HEALTHY], created_at=T1)
        store.save_scan("other.txt", [HEALTHY], created_at=T1)

        assert store.latest_scan_for("req.txt") == second
        assert store.latest_scan_for("req.txt", before=second) == first
        assert store.latest_scan_for("missing.txt") is None


def test_dimension_averages_are_grouped_and_ordered() -> None:
    with ScanStore() as store:
        scan_id = store.save_scan("req.txt", [RISKY, HEALTHY], created_at=T0)
        averages = store.dimension_averages(scan_id)

        assert {a.dimension for a in averages} == {
            "vulnerabilities",
            "maintenance",
            "bus_factor",
            "adoption",
            "license",
        }
        values = [a.average for a in averages]
        assert values == sorted(values, reverse=True)
        # Each average is the mean of the two packages' scores on that dimension.
        by_name = {a.dimension: a.average for a in averages}
        risky_vuln = next(d.score for d in RISKY.risk.dimensions if d.name == "vulnerabilities")
        healthy_vuln = next(d.score for d in HEALTHY.risk.dimensions if d.name == "vulnerabilities")
        assert abs(by_name["vulnerabilities"] - (risky_vuln + healthy_vuln) / 2) < 1e-9


def test_persists_across_connections(tmp_path: Path) -> None:
    db_path = tmp_path / "nested" / "depwatch.duckdb"
    with ScanStore(db_path) as store:
        scan_id = store.save_scan("req.txt", [RISKY], created_at=T0)

    # Reopen the same file in a fresh connection: the data is on disk.
    with ScanStore(db_path) as store:
        assert store.scan_summary(scan_id) is not None
        assert store.get_packages(scan_id)[0].name == "urllib3"


def test_normalises_tz_aware_created_at() -> None:
    aware = datetime(2026, 6, 20, 12, 0, 0, tzinfo=UTC)
    with ScanStore() as store:
        scan_id = store.save_scan("req.txt", [HEALTHY], created_at=aware)
        summary = store.scan_summary(scan_id)
        assert summary is not None
        # Stored and read back as the same instant, naive UTC.
        assert summary.created_at == datetime(2026, 6, 20, 12, 0, 0)
