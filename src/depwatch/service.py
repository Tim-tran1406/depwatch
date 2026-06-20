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
from depwatch.core.models import ScanDiff, ScanResult, ScoredPackage
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
from depwatch.trends import compute_diff


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


def diff_against_previous(result: ScanResult, settings: Settings) -> ScanDiff | None:
    """Compare a result against the previous stored scan of the same source.

    Returns None when there is no earlier scan to compare against.
    """
    with ScanStore(settings.db_path) as store:
        previous_id = store.latest_scan_for(result.source, before=result.scan_id)
        if previous_id is None:
            return None
        previous = store.get_packages(previous_id)
    return compute_diff(result, previous, previous_id)
