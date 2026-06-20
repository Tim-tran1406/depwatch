"""Client for the GitHub REST API: repository activity signals.

Used only to fill gaps deps.dev does not cover. A token (read from config) lifts
the rate limit from 60 to 5000 requests/hour but is not required.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from depwatch.config import Settings
from depwatch.ingest.http import AsyncFetcher
from depwatch.ingest.parsing import parse_datetime


class GitHubRepo(BaseModel):
    pushed_at: datetime | None
    stars: int
    subscribers: int
    open_issues: int
    archived: bool


class GitHubClient:
    def __init__(self, fetcher: AsyncFetcher, settings: Settings) -> None:
        self._fetcher = fetcher
        self._base = settings.github_base_url
        self._token = settings.github_token

    async def get_repo(self, owner: str, repo: str) -> GitHubRepo:
        headers = {"Accept": "application/vnd.github+json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        data = await self._fetcher.get_json(f"{self._base}/repos/{owner}/{repo}", headers=headers)
        return GitHubRepo(
            pushed_at=parse_datetime(data.get("pushed_at")),
            stars=data.get("stargazers_count", 0),
            subscribers=data.get("subscribers_count", 0),
            open_issues=data.get("open_issues_count", 0),
            archived=data.get("archived", False),
        )
