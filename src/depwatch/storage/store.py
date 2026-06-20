"""Persist scored scans in DuckDB and query them back.

This is the SQL/analytics layer. Scans are written once and read many ways: the
ranked packages for a scan, a summary with computed aggregates, the history of
scans, and the average risk per dimension. Aggregates live in SQL rather than in
stored columns, so there is nothing to keep in sync.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType

import duckdb

from depwatch.core.models import ScoredPackage
from depwatch.storage.models import (
    DimensionAverage,
    ScanSummary,
    StoredDimension,
    StoredPackage,
)
from depwatch.storage.schema import apply_schema

# Risk at or above this counts as "high" in the summary; tunable in one place.
HIGH_RISK_THRESHOLD = 0.5

_MEMORY = ":memory:"


def _to_utc_naive(value: datetime) -> datetime:
    """Normalise to naive UTC so the TIMESTAMP column round-trips consistently.

    DuckDB's TIMESTAMP is timezone-naive; handing it a tz-aware value silently
    shifts it into local time. We convert aware values to UTC and drop the
    tzinfo, and leave naive values (assumed already UTC) untouched.
    """
    if value.tzinfo is not None:
        value = value.astimezone(UTC)
    return value.replace(tzinfo=None)


# A constant SQL fragment, never built from user input. Selects each scan with
# the aggregates computed over its packages; the optional WHERE narrows to one.
_SUMMARY_SQL = """
    SELECT s.scan_id,
           s.created_at,
           s.source,
           COUNT(p.name) AS package_count,
           COALESCE(MAX(p.overall_risk), 0.0) AS max_risk,
           COUNT(*) FILTER (WHERE p.overall_risk >= ?) AS high_risk_count
    FROM scans s
    LEFT JOIN scored_packages p USING (scan_id)
    {where}
    GROUP BY s.scan_id, s.created_at, s.source
    ORDER BY s.created_at DESC, s.scan_id DESC
"""


class ScanStore:
    """A DuckDB-backed store for scan results.

    Pass a file path to persist, or ``":memory:"`` for a throwaway database
    (used by the tests). Usable as a context manager.
    """

    def __init__(self, db_path: str | Path = _MEMORY) -> None:
        if str(db_path) != _MEMORY:
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._con = duckdb.connect(str(db_path))
        apply_schema(self._con)

    def __enter__(self) -> ScanStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._con.close()

    def save_scan(self, source: str, scored: list[ScoredPackage], created_at: datetime) -> int:
        """Write one scan and its packages atomically; return the new scan id."""
        self._con.execute("BEGIN TRANSACTION")
        try:
            row = self._con.execute(
                "INSERT INTO scans (created_at, source) VALUES (?, ?) RETURNING scan_id",
                [_to_utc_naive(created_at), source],
            ).fetchone()
            assert row is not None  # RETURNING always yields the inserted row
            scan_id = int(row[0])
            self._insert_packages(scan_id, scored)
            self._insert_dimensions(scan_id, scored)
            self._con.execute("COMMIT")
        except Exception:
            self._con.execute("ROLLBACK")
            raise
        return scan_id

    def _insert_packages(self, scan_id: int, scored: list[ScoredPackage]) -> None:
        rows = [
            [
                scan_id,
                sp.signals.name,
                sp.signals.version,
                sp.signals.is_direct,
                sp.risk.overall,
                sp.signals.vulnerability_count,
                sp.signals.highest_severity,
                sp.signals.days_since_last_release,
                sp.signals.monthly_downloads,
                sp.signals.contributor_count,
                sp.signals.license,
            ]
            for sp in scored
        ]
        if rows:
            self._con.executemany(
                """
                INSERT INTO scored_packages
                    (scan_id, name, version, is_direct, overall_risk, vulnerability_count,
                     highest_severity, days_since_last_release, monthly_downloads,
                     contributor_count, license)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    def _insert_dimensions(self, scan_id: int, scored: list[ScoredPackage]) -> None:
        rows = [
            [scan_id, sp.signals.name, dim.name, dim.score, dim.reason]
            for sp in scored
            for dim in sp.risk.dimensions
        ]
        if rows:
            self._con.executemany(
                "INSERT INTO dimension_scores (scan_id, name, dimension, score, reason) "
                "VALUES (?, ?, ?, ?, ?)",
                rows,
            )

    def list_scans(self) -> list[ScanSummary]:
        """Every scan, newest first, each with its computed aggregates."""
        rows = self._con.execute(_SUMMARY_SQL.format(where=""), [HIGH_RISK_THRESHOLD]).fetchall()
        return [self._to_summary(row) for row in rows]

    def scan_summary(self, scan_id: int) -> ScanSummary | None:
        """The summary for one scan, or ``None`` if it does not exist."""
        rows = self._con.execute(
            _SUMMARY_SQL.format(where="WHERE s.scan_id = ?"),
            [HIGH_RISK_THRESHOLD, scan_id],
        ).fetchall()
        return self._to_summary(rows[0]) if rows else None

    def get_packages(self, scan_id: int) -> list[StoredPackage]:
        """A scan's packages, riskiest first, each with its dimension breakdown."""
        dims = self._dimensions_by_package(scan_id)
        rows = self._con.execute(
            """
            SELECT name, version, is_direct, overall_risk, vulnerability_count,
                   highest_severity, days_since_last_release, monthly_downloads,
                   contributor_count, license
            FROM scored_packages
            WHERE scan_id = ?
            ORDER BY overall_risk DESC, name
            """,
            [scan_id],
        ).fetchall()
        return [
            StoredPackage(
                name=row[0],
                version=row[1],
                is_direct=row[2],
                overall_risk=row[3],
                vulnerability_count=row[4],
                highest_severity=row[5],
                days_since_last_release=row[6],
                monthly_downloads=row[7],
                contributor_count=row[8],
                license=row[9],
                dimensions=dims.get(row[0], []),
            )
            for row in rows
        ]

    def dimension_averages(self, scan_id: int) -> list[DimensionAverage]:
        """Mean score per dimension across a scan, hottest dimension first."""
        rows = self._con.execute(
            """
            SELECT dimension, AVG(score) AS average
            FROM dimension_scores
            WHERE scan_id = ?
            GROUP BY dimension
            ORDER BY average DESC, dimension
            """,
            [scan_id],
        ).fetchall()
        return [DimensionAverage(dimension=row[0], average=row[1]) for row in rows]

    def _dimensions_by_package(self, scan_id: int) -> dict[str, list[StoredDimension]]:
        rows = self._con.execute(
            """
            SELECT name, dimension, score, reason
            FROM dimension_scores
            WHERE scan_id = ?
            ORDER BY name, score DESC, dimension
            """,
            [scan_id],
        ).fetchall()
        by_package: dict[str, list[StoredDimension]] = {}
        for name, dimension, score, reason in rows:
            by_package.setdefault(name, []).append(
                StoredDimension(name=dimension, score=score, reason=reason)
            )
        return by_package

    @staticmethod
    def _to_summary(row: tuple[int, datetime, str, int, float, int]) -> ScanSummary:
        return ScanSummary(
            scan_id=row[0],
            created_at=row[1],
            source=row[2],
            package_count=row[3],
            max_risk=row[4],
            high_risk_count=row[5],
        )
