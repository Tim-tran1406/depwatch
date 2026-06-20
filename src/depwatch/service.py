"""Application service: run a full scan end to end and optionally store it.

This is the one place that wires the layers together — parse the requirements,
resolve the dependency set, score every package, and (by default) save the run to
the local database. The CLI and any other front end call this and nothing else.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

from depwatch.config import Settings
from depwatch.core.models import ScanResult, ScoredPackage
from depwatch.core.requirements import parse_requirements_file
from depwatch.core.resolve import DependencyResolver
from depwatch.ingest.depsdev import DepsDevClient
from depwatch.ingest.github import GitHubClient
from depwatch.ingest.http import AsyncFetcher
from depwatch.ingest.osv import OSVClient
from depwatch.ingest.pypi import PyPIClient
from depwatch.ingest.pypistats import PyPIStatsClient
from depwatch.scoring.engine import ScoringEngine
from depwatch.scoring.signals import SignalCollector
from depwatch.storage.store import ScanStore


async def _score(requirements: Path, settings: Settings) -> list[ScoredPackage]:
    parsed = parse_requirements_file(requirements)
    async with AsyncFetcher(settings) as fetcher:
        depsdev = DepsDevClient(fetcher, settings)
        pypi = PyPIClient(fetcher, settings)
        resolved = await DependencyResolver(depsdev, pypi).resolve(parsed)
        collector = SignalCollector(
            depsdev,
            OSVClient(fetcher, settings),
            pypi,
            PyPIStatsClient(fetcher, settings),
            GitHubClient(fetcher, settings),
        )
        return await ScoringEngine(collector).score_all(resolved)


def run_scan(
    requirements: Path,
    settings: Settings,
    *,
    save: bool = True,
    created_at: datetime | None = None,
) -> ScanResult:
    """Parse, resolve, score, optionally persist, and return the result riskiest-first."""
    moment = created_at or datetime.now(UTC)
    packages = asyncio.run(_score(requirements, settings))
    packages.sort(key=lambda p: p.risk.overall, reverse=True)
    scan_id: int | None = None
    if save:
        with ScanStore(settings.db_path) as store:
            scan_id = store.save_scan(str(requirements), packages, created_at=moment)
    return ScanResult(
        source=str(requirements), created_at=moment, packages=packages, scan_id=scan_id
    )
