"""Client for the OSV.dev vulnerability database (free, no key, no rate limit)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from depwatch.config import Settings
from depwatch.ingest.http import AsyncFetcher


class OSVVulnerability(BaseModel):
    id: str
    summary: str | None
    aliases: list[str]
    severity: list[dict[str, Any]]


class OSVClient:
    def __init__(self, fetcher: AsyncFetcher, settings: Settings) -> None:
        self._fetcher = fetcher
        self._base = settings.osv_base_url

    async def query(self, name: str, version: str) -> list[OSVVulnerability]:
        body = {"package": {"ecosystem": "PyPI", "name": name}, "version": version}
        data = await self._fetcher.post_json(f"{self._base}/query", body)
        return [
            OSVVulnerability(
                id=vuln["id"],
                summary=vuln.get("summary"),
                aliases=vuln.get("aliases", []),
                severity=vuln.get("severity", []),
            )
            for vuln in data.get("vulns", [])
        ]
