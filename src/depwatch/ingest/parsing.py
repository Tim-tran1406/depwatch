"""Small parsing helpers shared by the ingestion clients."""

from __future__ import annotations

from datetime import datetime


def parse_datetime(value: str | None) -> datetime | None:
    """Parse an ISO 8601 timestamp, tolerating missing or malformed values."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
