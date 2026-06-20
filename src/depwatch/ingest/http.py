"""Async HTTP access with retries and response caching.

Every external call goes through AsyncFetcher, so the whole project shares one set
of rules: a timeout, a descriptive user agent, a concurrency limit, automatic
retries with backoff on transient failures, and the on-disk cache.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Self

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from depwatch.config import Settings
from depwatch.ingest.cache import DiskCache

# Responses worth retrying: rate limiting and transient server errors.
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_CACHE_TTL_SECONDS = 24 * 3600


class RetryableHTTPError(Exception):
    """A response whose status code means we should back off and retry."""


_with_retry = retry(
    retry=retry_if_exception_type((httpx.TransportError, RetryableHTTPError)),
    wait=wait_exponential(multiplier=0.5, max=8),
    stop=stop_after_attempt(4),
    reraise=True,
)


class AsyncFetcher:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._cache = DiskCache(settings.cache_dir, ttl_seconds=_CACHE_TTL_SECONDS)
        self._semaphore = asyncio.Semaphore(settings.http_max_concurrency)
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> Self:
        self._client = httpx.AsyncClient(
            timeout=self._settings.http_timeout,
            headers={"User-Agent": self._settings.user_agent},
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get_json(self, url: str, *, headers: dict[str, str] | None = None) -> Any:
        return await self._request("GET", url, headers=headers, body=None)

    async def post_json(self, url: str, body: Any, *, headers: dict[str, str] | None = None) -> Any:
        return await self._request("POST", url, headers=headers, body=body)

    async def _request(
        self, method: str, url: str, *, headers: dict[str, str] | None, body: Any
    ) -> Any:
        cache_key = DiskCache.make_key(
            method, url, json.dumps(body, sort_keys=True) if body else ""
        )
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        data = await self._fetch(method, url, headers=headers, body=body)
        self._cache.set(cache_key, data)
        return data

    @_with_retry
    async def _fetch(
        self, method: str, url: str, *, headers: dict[str, str] | None, body: Any
    ) -> Any:
        if self._client is None:
            raise RuntimeError("AsyncFetcher must be used as an async context manager")
        async with self._semaphore:
            response = await self._client.request(method, url, headers=headers, json=body)
        if response.status_code in _RETRYABLE_STATUS:
            raise RetryableHTTPError(f"{response.status_code} from {url}")
        response.raise_for_status()
        return response.json()
