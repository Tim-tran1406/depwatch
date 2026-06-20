"""Client for the deps.dev API.

deps.dev is the backbone: one service gives us a version's licenses and security
advisories plus its source repository, and a project's stars, forks, open issues,
and OpenSSF Scorecard results.
"""

from __future__ import annotations

from datetime import datetime
from urllib.parse import quote

from pydantic import BaseModel

from depwatch.config import Settings
from depwatch.ingest.http import AsyncFetcher
from depwatch.ingest.parsing import parse_datetime


class DepsDevVersion(BaseModel):
    published_at: datetime | None
    licenses: list[str]
    advisory_ids: list[str]
    source_repo_url: str | None


class DepsDevProject(BaseModel):
    stars: int
    forks: int
    open_issues: int
    scorecard_overall: float | None
    scorecard_checks: dict[str, int]


class DepsDevClient:
    def __init__(self, fetcher: AsyncFetcher, settings: Settings) -> None:
        self._fetcher = fetcher
        self._base = settings.depsdev_base_url

    async def get_version(self, name: str, version: str) -> DepsDevVersion:
        url = (
            f"{self._base}/systems/pypi/packages/{quote(name, safe='')}"
            f"/versions/{quote(version, safe='')}"
        )
        data = await self._fetcher.get_json(url)
        source_repo = next(
            (link["url"] for link in data.get("links", []) if link.get("label") == "SOURCE_REPO"),
            None,
        )
        return DepsDevVersion(
            published_at=parse_datetime(data.get("publishedAt")),
            licenses=data.get("licenses", []),
            advisory_ids=[advisory["id"] for advisory in data.get("advisoryKeys", [])],
            source_repo_url=source_repo,
        )

    async def get_project(self, project_key: str) -> DepsDevProject:
        url = f"{self._base}/projects/{quote(project_key, safe='')}"
        data = await self._fetcher.get_json(url)
        scorecard = data.get("scorecard") or {}
        checks = {
            check["name"]: check["score"]
            for check in scorecard.get("checks", [])
            if check.get("score") is not None
        }
        return DepsDevProject(
            stars=data.get("starsCount", 0),
            forks=data.get("forksCount", 0),
            open_issues=data.get("openIssuesCount", 0),
            scorecard_overall=scorecard.get("overallScore"),
            scorecard_checks=checks,
        )
