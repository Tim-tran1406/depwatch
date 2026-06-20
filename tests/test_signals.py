import asyncio
from pathlib import Path

from pytest_httpx import HTTPXMock

from depwatch.config import Settings
from depwatch.core.models import PackageSignals, ResolvedPackage
from depwatch.ingest.depsdev import DepsDevClient
from depwatch.ingest.github import GitHubClient
from depwatch.ingest.http import AsyncFetcher
from depwatch.ingest.osv import OSVClient
from depwatch.ingest.pypi import PyPIClient
from depwatch.ingest.pypistats import PyPIStatsClient
from depwatch.scoring.signals import SignalCollector


def _collect(settings: Settings, package: ResolvedPackage) -> PackageSignals:
    async def run() -> PackageSignals:
        async with AsyncFetcher(settings) as fetcher:
            collector = SignalCollector(
                DepsDevClient(fetcher, settings),
                OSVClient(fetcher, settings),
                PyPIClient(fetcher, settings),
                PyPIStatsClient(fetcher, settings),
                GitHubClient(fetcher, settings),
            )
            return await collector.collect(package)

    return asyncio.run(run())


def test_collect_assembles_all_signals(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/query",
        json={"vulns": [{"id": "V1", "summary": "x", "aliases": [], "severity": []}]},
    )
    httpx_mock.add_response(
        url="https://pypi.org/pypi/flask/json",
        json={
            "info": {"version": "2.0.1", "license": "BSD-3-Clause", "project_urls": {}},
            "releases": {"2.0.1": [{"upload_time_iso_8601": "2026-06-01T00:00:00Z"}]},
        },
    )
    httpx_mock.add_response(
        url="https://api.deps.dev/v3/systems/pypi/packages/flask/versions/2.0.1",
        json={
            "licenses": ["BSD-3-Clause"],
            "advisoryKeys": [],
            "links": [{"label": "SOURCE_REPO", "url": "https://github.com/pallets/flask"}],
        },
    )
    httpx_mock.add_response(
        url="https://pypistats.org/api/packages/flask/recent",
        json={"data": {"last_day": 1, "last_week": 2, "last_month": 1000}},
    )
    httpx_mock.add_response(
        url="https://api.github.com/repos/pallets/flask/contributors?per_page=100&anon=true",
        json=[{"id": i} for i in range(40)],
    )
    settings = Settings(cache_dir=tmp_path)

    signals = _collect(settings, ResolvedPackage(name="flask", version="2.0.1", is_direct=True))

    assert signals.vulnerability_count == 1
    assert signals.contributor_count == 40
    assert signals.monthly_downloads == 1000
    assert signals.license == "BSD-3-Clause"
    assert signals.days_since_last_release is not None


def test_collect_degrades_when_optional_sources_fail(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    httpx_mock.add_response(url="https://api.osv.dev/v1/query", json={"vulns": []})
    httpx_mock.add_response(
        url="https://pypi.org/pypi/lonely/json",
        json={
            "info": {"version": "1.0", "license": "MIT", "project_urls": {}},
            "releases": {"1.0": [{"upload_time_iso_8601": "2026-06-01T00:00:00Z"}]},
        },
    )
    httpx_mock.add_response(
        url="https://api.deps.dev/v3/systems/pypi/packages/lonely/versions/1.0",
        json={"licenses": ["MIT"], "advisoryKeys": [], "links": []},
    )
    httpx_mock.add_response(url="https://pypistats.org/api/packages/lonely/recent", status_code=404)
    settings = Settings(cache_dir=tmp_path)

    signals = _collect(settings, ResolvedPackage(name="lonely", version="1.0", is_direct=False))

    assert signals.monthly_downloads == 0  # pypistats 404 -> safe default
    assert signals.contributor_count is None  # no source repo -> no GitHub lookup
    assert signals.vulnerability_count == 0
    assert signals.license == "MIT"
