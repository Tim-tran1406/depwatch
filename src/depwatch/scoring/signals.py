"""Gather the raw signals for a package by fanning out to the data clients.

The flaky or optional sources (download stats, contributor count) degrade to a
safe default instead of failing, so a missing signal never sinks a whole package.
Severity weighting per vulnerability is a planned refinement; for now a package's
vulnerabilities are treated as medium severity and the count drives the score.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import UTC, datetime

from depwatch.core.models import PackageSignals, ResolvedPackage
from depwatch.ingest.depsdev import DepsDevClient, DepsDevVersion
from depwatch.ingest.github import GitHubClient
from depwatch.ingest.osv import OSVClient, OSVVulnerability
from depwatch.ingest.pypi import PyPIClient
from depwatch.ingest.pypistats import PyPIStatsClient
from depwatch.scoring.severity import best_severity

logger = logging.getLogger(__name__)

_GITHUB_REPO = re.compile(r"github\.com[/:]+([^/]+)/([^/#?]+?)(?:\.git)?/?$")


class SignalCollector:
    def __init__(
        self,
        depsdev: DepsDevClient,
        osv: OSVClient,
        pypi: PyPIClient,
        pypistats: PyPIStatsClient,
        github: GitHubClient,
    ) -> None:
        self._depsdev = depsdev
        self._osv = osv
        self._pypi = pypi
        self._pypistats = pypistats
        self._github = github

    async def collect(self, package: ResolvedPackage) -> PackageSignals:
        vulns, pkg, version, downloads = await asyncio.gather(
            self._osv.query(package.name, package.version),
            self._pypi.get_package(package.name),
            self._depsdev.get_version(package.name, package.version),
            self._monthly_downloads(package.name),
        )
        contributors = await self._contributor_count(version.source_repo_url or pkg.source_url)
        count, highest_severity, vulnerability_ids = _vulnerability_signals(vulns)
        return PackageSignals(
            name=package.name,
            version=package.version,
            is_direct=package.is_direct,
            vulnerability_count=count,
            highest_severity=highest_severity,
            vulnerability_ids=vulnerability_ids,
            days_since_last_release=_days_since(pkg.last_release_at),
            monthly_downloads=downloads,
            contributor_count=contributors,
            license=pkg.license or _first_license(version),
        )

    async def _monthly_downloads(self, name: str) -> int:
        try:
            return (await self._pypistats.recent_downloads(name)).last_month
        except Exception as exc:
            logger.warning("no download stats for %s: %s", name, exc)
            return 0

    async def _contributor_count(self, source_url: str | None) -> int | None:
        owner_repo = _github_owner_repo(source_url)
        if owner_repo is None:
            return None
        try:
            return await self._github.get_contributor_count(*owner_repo)
        except Exception as exc:
            logger.warning("no contributor data for %s: %s", source_url, exc)
            return None


def _vulnerability_signals(vulns: list[OSVVulnerability]) -> tuple[int, float | None, list[str]]:
    """Collapse duplicate advisories, then count, rank and pick the worst severity.

    OSV often returns the same vulnerability from several databases (a GHSA and a
    PYSEC entry for one CVE), so we key by the display id to avoid double counting.
    """
    severities: dict[str, float | None] = {}
    for vuln in vulns:
        key = _vuln_id(vuln)
        severity = best_severity(vuln.cvss_vectors(), vuln.severity_label)
        if key not in severities or _is_higher(severity, severities[key]):
            severities[key] = severity
    known = [severity for severity in severities.values() if severity is not None]
    highest = max(known) if known else None
    ordered = sorted(
        severities.items(),
        key=lambda item: item[1] if item[1] is not None else -1.0,
        reverse=True,
    )
    return len(severities), highest, [key for key, _ in ordered]


def _is_higher(candidate: float | None, current: float | None) -> bool:
    if candidate is None:
        return False
    return current is None or candidate > current


def _vuln_id(vuln: OSVVulnerability) -> str:
    """Prefer the CVE alias for display; fall back to the OSV id (e.g. a GHSA)."""
    for alias in vuln.aliases:
        if alias.startswith("CVE-"):
            return alias
    return vuln.id


def _github_owner_repo(source_url: str | None) -> tuple[str, str] | None:
    if not source_url:
        return None
    match = _GITHUB_REPO.search(source_url)
    if match is None:
        return None
    return match.group(1), match.group(2)


def _days_since(moment: datetime | None) -> int | None:
    if moment is None:
        return None
    return (datetime.now(UTC) - moment).days


def _first_license(version: DepsDevVersion) -> str | None:
    return version.licenses[0] if version.licenses else None
