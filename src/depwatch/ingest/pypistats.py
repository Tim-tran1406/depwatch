"""Client for pypistats.org: recent download counts, our signal for adoption."""

from __future__ import annotations

from pydantic import BaseModel

from depwatch.config import Settings
from depwatch.ingest.http import AsyncFetcher


class PyPIDownloads(BaseModel):
    last_day: int
    last_week: int
    last_month: int


class PyPIStatsClient:
    def __init__(self, fetcher: AsyncFetcher, settings: Settings) -> None:
        self._fetcher = fetcher
        self._base = settings.pypistats_base_url

    async def recent_downloads(self, name: str) -> PyPIDownloads:
        data = await self._fetcher.get_json(f"{self._base}/packages/{name}/recent")
        recent = data.get("data", {})
        return PyPIDownloads(
            last_day=recent.get("last_day", 0),
            last_week=recent.get("last_week", 0),
            last_month=recent.get("last_month", 0),
        )
