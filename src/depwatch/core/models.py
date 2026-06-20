"""Core domain models that flow through depwatch."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class Requirement(BaseModel):
    """A single line from a requirements file: a package and an optional pinned version."""

    name: str
    version: str | None


class ResolvedPackage(BaseModel):
    """A package in the fully resolved dependency set, and how it was pulled in."""

    name: str
    version: str
    is_direct: bool


class PackageSignals(BaseModel):
    """Raw signals gathered for one package, before scoring."""

    name: str
    version: str
    is_direct: bool
    vulnerability_count: int = 0
    highest_severity: float | None = None  # 0-10, CVSS-style, when known
    vulnerability_ids: list[str] = []  # advisory ids, most severe first (CVE when available)
    days_since_last_release: int | None = None
    monthly_downloads: int = 0
    contributor_count: int | None = None  # number of repo contributors (capped), bus-factor signal
    license: str | None = None


class DimensionScore(BaseModel):
    """One package's risk on a single dimension: 0 is safe, 1 is risky."""

    name: str
    score: float
    reason: str


class RiskScore(BaseModel):
    """A package's overall risk (0 safe, 1 risky) and the per-dimension breakdown."""

    overall: float
    dimensions: list[DimensionScore]


class ScoredPackage(BaseModel):
    signals: PackageSignals
    risk: RiskScore


class ScanResult(BaseModel):
    """The outcome of one scan: the scored packages plus where and when it ran."""

    source: str
    created_at: datetime
    packages: list[ScoredPackage]
    scan_id: int | None = None  # set once the scan has been saved
