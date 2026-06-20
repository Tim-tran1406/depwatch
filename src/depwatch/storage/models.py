"""Read models returned by the storage layer.

These mirror what comes back out of SQL, which is not quite the same shape as the
domain models that go in: a stored package carries its overall risk and its
dimension breakdown together, and a scan summary carries computed aggregates.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class StoredDimension(BaseModel):
    """One dimension's score for a stored package."""

    name: str
    score: float
    reason: str


class StoredPackage(BaseModel):
    """A package as read back from a scan, with its dimension breakdown attached."""

    name: str
    version: str
    is_direct: bool
    overall_risk: float
    vulnerability_count: int
    highest_severity: float | None
    days_since_last_release: int | None
    monthly_downloads: int | None
    contributor_count: int | None
    license: str | None
    dimensions: list[StoredDimension]


class ScanSummary(BaseModel):
    """A scan and the aggregates computed over its packages."""

    scan_id: int
    created_at: datetime
    source: str
    package_count: int
    max_risk: float
    high_risk_count: int


class DimensionAverage(BaseModel):
    """The mean score for one dimension across a scan's packages."""

    dimension: str
    average: float
