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
from depwatch.ingest.osv import OSVClient
from depwatch.ingest.pypi import PyPIClient
from depwatch.ingest.pypistats import PyPIStatsClient

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
        return PackageSignals(
            name=package.name,
            version=package.version,
            is_direct=package.is_direct,
            vulnerability_count=len(vulns),
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
