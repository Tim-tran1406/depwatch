import asyncio
from pathlib import Path

from pytest_httpx import HTTPXMock

from depwatch.config import Settings
from depwatch.core.models import PackageSignals, ResolvedPackage
from depwatch.ingest.depsdev import DepsDevClient
from depwatch.ingest.github import GitHubClient
from depwatch.ingest.http import AsyncFetcher
from depwatch.ingest.osv import OSVClient, OSVVulnerability
from depwatch.ingest.pypi import PyPIClient
from depwatch.ingest.pypistats import PyPIStatsClient
from depwatch.scoring.signals import SignalCollector, _vulnerability_signals

_CVSS_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _vuln(vuln_id: str, aliases: list[str], label: str | None = None) -> OSVVulnerability:
    return OSVVulnerability(
        id=vuln_id, summary=None, aliases=aliases, severity=[], severity_label=label
    )


def test_same_cve_from_two_databases_counts_once() -> None:
    # A GHSA and a PYSEC entry that both describe CVE-2020-14343.
    vulns = [
        _vuln("GHSA-x", ["CVE-2020-14343", "PYSEC-2021-142"], label="CRITICAL"),
        _vuln("PYSEC-2021-142", ["CVE-2020-14343", "GHSA-x"], label=None),
    ]
    count, highest, ids = _vulnerability_signals(vulns)
    assert count == 1
    assert ids == ["CVE-2020-14343"]
    assert highest == 9.5  # the CRITICAL label wins over the unlabelled duplicate


def test_vulnerabilities_are_ordered_worst_first() -> None:
    vulns = [_vuln("a", ["CVE-A"], label="LOW"), _vuln("b", ["CVE-B"], label="CRITICAL")]
    count, highest, ids = _vulnerability_signals(vulns)
    assert (count, ids, highest) == (2, ["CVE-B", "CVE-A"], 9.5)


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
        json={
            "vulns": [
                {
                    "id": "GHSA-1",
                    "summary": "x",
                    "aliases": ["CVE-2024-1"],
                    "severity": [{"type": "CVSS_V3", "score": _CVSS_CRITICAL}],
                    "database_specific": {"severity": "CRITICAL"},
                }
            ]
        },
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
    assert signals.highest_severity is not None and signals.highest_severity > 9.0
    assert signals.vulnerability_ids == ["CVE-2024-1"]  # CVE alias preferred over the GHSA id
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

    assert signals.monthly_downloads is None  # pypistats 404 -> unknown, not zero
    assert signals.contributor_count is None  # no source repo -> no GitHub lookup
    assert signals.vulnerability_count == 0
    assert signals.license == "MIT"
