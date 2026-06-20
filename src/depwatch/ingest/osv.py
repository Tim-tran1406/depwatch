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
    severity: list[dict[str, Any]]  # CVSS vectors: [{"type": "CVSS_V3", "score": "CVSS:3.1/..."}]
    severity_label: str | None  # GitHub's qualitative rating, e.g. "HIGH"
    affected: list[dict[str, Any]] = []  # OSV "affected" entries, each with version ranges

    def cvss_vectors(self) -> list[str]:
        return [entry["score"] for entry in self.severity if "score" in entry]

    def pypi_ranges(self) -> list[tuple[str | None, str | None]]:
        """The affected version windows as (introduced, fixed) pairs.

        Only ECOSYSTEM ranges are used (the PyPI version order). ``introduced`` is
        None for "from the beginning"; ``fixed`` is None when the window has no clean
        fix (an open-ended or last-affected range), so we never claim a fix that the
        advisory does not actually state.
        """
        pairs: list[tuple[str | None, str | None]] = []
        for entry in self.affected:
            for rng in entry.get("ranges", []):
                if rng.get("type") != "ECOSYSTEM":
                    continue
                introduced: str | None = None
                open_window = False
                for event in rng.get("events", []):
                    if "introduced" in event:
                        introduced = event["introduced"]
                        open_window = True
                    elif "fixed" in event:
                        pairs.append((introduced, event["fixed"]))
                        open_window = False
                    elif "last_affected" in event or "limit" in event:
                        # an inclusive/limit bound is not a clean fix point
                        pairs.append((introduced, None))
                        open_window = False
                if open_window:
                    pairs.append((introduced, None))
        return pairs


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
                severity_label=vuln.get("database_specific", {}).get("severity"),
                affected=vuln.get("affected", []),
            )
            for vuln in data.get("vulns", [])
        ]
