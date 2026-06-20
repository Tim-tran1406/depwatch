import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path

from pytest_httpx import HTTPXMock

from depwatch.config import Settings
from depwatch.ingest.depsdev import DepsDevClient
from depwatch.ingest.github import GitHubClient
from depwatch.ingest.http import AsyncFetcher
from depwatch.ingest.osv import OSVClient
from depwatch.ingest.pypi import PyPIClient
from depwatch.ingest.pypistats import PyPIStatsClient


def _run[T](settings: Settings, call: Callable[[AsyncFetcher], Awaitable[T]]) -> T:
    async def runner() -> T:
        async with AsyncFetcher(settings) as fetcher:
            return await call(fetcher)

    return asyncio.run(runner())


def test_depsdev_get_version(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    httpx_mock.add_response(
        json={
            "publishedAt": "2023-05-22T15:12:42Z",
            "licenses": ["Apache-2.0"],
            "advisoryKeys": [{"id": "GHSA-9hjg-9r4m-mvj7"}],
            "links": [{"label": "SOURCE_REPO", "url": "https://github.com/psf/requests"}],
        }
    )
    settings = Settings(cache_dir=tmp_path)
    version = _run(settings, lambda f: DepsDevClient(f, settings).get_version("requests", "2.31.0"))
    assert version.licenses == ["Apache-2.0"]
    assert version.advisory_ids == ["GHSA-9hjg-9r4m-mvj7"]
    assert version.source_repo_url == "https://github.com/psf/requests"


def test_depsdev_get_project_scorecard(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    httpx_mock.add_response(
        json={
            "starsCount": 54045,
            "forksCount": 9978,
            "openIssuesCount": 229,
            "scorecard": {
                "overallScore": 7.5,
                "checks": [
                    {"name": "Maintained", "score": 10},
                    {"name": "Code-Review", "score": 8},
                ],
            },
        }
    )
    settings = Settings(cache_dir=tmp_path)
    project = _run(
        settings, lambda f: DepsDevClient(f, settings).get_project("github.com/psf/requests")
    )
    assert project.stars == 54045
    assert project.scorecard_overall == 7.5
    assert project.scorecard_checks["Maintained"] == 10


def test_osv_query(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    httpx_mock.add_response(
        json={"vulns": [{"id": "GHSA-x", "summary": "bad", "aliases": ["CVE-1"], "severity": []}]}
    )
    settings = Settings(cache_dir=tmp_path)
    vulns = _run(settings, lambda f: OSVClient(f, settings).query("requests", "2.31.0"))
    assert len(vulns) == 1
    assert vulns[0].id == "GHSA-x"
    assert vulns[0].aliases == ["CVE-1"]


def test_pypi_get_package_uses_latest_release(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    httpx_mock.add_response(
        json={
            "info": {
                "version": "2.31.0",
                "requires_python": ">=3.7",
                "author": "Kenneth Reitz",
                "maintainer": "",
                "license": "Apache 2.0",
                "project_urls": {"Source": "https://github.com/psf/requests"},
            },
            "releases": {
                "2.30.0": [{"upload_time_iso_8601": "2023-05-03T00:00:00Z"}],
                "2.31.0": [{"upload_time_iso_8601": "2023-05-22T15:12:42Z"}],
            },
        }
    )
    settings = Settings(cache_dir=tmp_path)
    package = _run(settings, lambda f: PyPIClient(f, settings).get_package("requests"))
    assert package.latest_version == "2.31.0"
    assert package.source_url == "https://github.com/psf/requests"
    assert package.last_release_at is not None
    assert package.last_release_at.day == 22  # most recent upload across all releases


def test_pypistats_recent_downloads(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    httpx_mock.add_response(
        json={"data": {"last_day": 1, "last_week": 2, "last_month": 3}, "package": "requests"}
    )
    settings = Settings(cache_dir=tmp_path)
    downloads = _run(settings, lambda f: PyPIStatsClient(f, settings).recent_downloads("requests"))
    assert (downloads.last_day, downloads.last_week, downloads.last_month) == (1, 2, 3)


def test_github_get_repo_sends_token(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    httpx_mock.add_response(
        json={
            "pushed_at": "2026-06-15T18:12:30Z",
            "stargazers_count": 54044,
            "subscribers_count": 1293,
            "open_issues_count": 229,
            "archived": False,
        }
    )
    settings = Settings(cache_dir=tmp_path, github_token="secrettoken")
    repo = _run(settings, lambda f: GitHubClient(f, settings).get_repo("psf", "requests"))
    assert repo.stars == 54044
    assert repo.archived is False
    assert httpx_mock.get_requests()[0].headers["Authorization"] == "Bearer secrettoken"
