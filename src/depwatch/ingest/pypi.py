"""Client for the PyPI JSON API: release history, maintainers, and the source repo."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel

from depwatch.config import Settings
from depwatch.ingest.http import AsyncFetcher
from depwatch.ingest.parsing import parse_datetime

_SOURCE_URL_LABELS = ("source", "repository", "homepage")


class PyPIPackage(BaseModel):
    latest_version: str
    last_release_at: datetime | None
    requires_python: str | None
    author: str | None
    maintainer: str | None
    license: str | None
    source_url: str | None


class PyPIClient:
    def __init__(self, fetcher: AsyncFetcher, settings: Settings) -> None:
        self._fetcher = fetcher
        self._base = settings.pypi_base_url

    async def get_package(self, name: str) -> PyPIPackage:
        data = await self._fetcher.get_json(f"{self._base}/{name}/json")
        info = data.get("info", {})
        return PyPIPackage(
            latest_version=info.get("version", ""),
            last_release_at=self._latest_upload(data.get("releases", {})),
            requires_python=info.get("requires_python") or None,
            author=info.get("author") or None,
            maintainer=info.get("maintainer") or None,
            license=info.get("license") or None,
            source_url=self._source_url(info.get("project_urls") or {}),
        )

    @staticmethod
    def _latest_upload(releases: dict[str, Any]) -> datetime | None:
        times = []
        for files in releases.values():
            for file in files:
                uploaded = parse_datetime(file.get("upload_time_iso_8601"))
                if uploaded is not None:
                    times.append(uploaded)
        return max(times) if times else None

    @staticmethod
    def _source_url(project_urls: dict[str, Any]) -> str | None:
        for label, url in project_urls.items():
            if label.lower() in _SOURCE_URL_LABELS:
                return str(url)
        return None
