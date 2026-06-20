"""A small on-disk cache for API responses.

Caching does two jobs: it keeps us well under the GitHub rate limit, and it makes
a scan reproducible and fast to re-run. Each entry is a JSON file keyed by a hash
of the request, with a time-to-live so data does not go stale forever.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any


class DiskCache:
    def __init__(self, root: Path, ttl_seconds: float) -> None:
        self.root = root
        self.ttl_seconds = ttl_seconds
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def make_key(*parts: str) -> str:
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]

    def _path(self, key: str) -> Path:
        return self.root / f"{key}.json"

    def get(self, key: str) -> Any | None:
        path = self._path(key)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        if time.time() - payload["stored_at"] > self.ttl_seconds:
            return None
        return payload["value"]

    def set(self, key: str, value: Any) -> None:
        self._path(key).write_text(json.dumps({"stored_at": time.time(), "value": value}))
