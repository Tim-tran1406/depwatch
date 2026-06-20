from pathlib import Path

from depwatch.ingest.cache import DiskCache


def test_set_get_roundtrip(tmp_path: Path) -> None:
    cache = DiskCache(tmp_path, ttl_seconds=3600)
    key = DiskCache.make_key("GET", "https://example.com")
    cache.set(key, {"hello": "world"})
    assert cache.get(key) == {"hello": "world"}


def test_missing_key_returns_none(tmp_path: Path) -> None:
    cache = DiskCache(tmp_path, ttl_seconds=3600)
    assert cache.get("does-not-exist") is None


def test_expired_entry_returns_none(tmp_path: Path) -> None:
    cache = DiskCache(tmp_path, ttl_seconds=-1)
    key = DiskCache.make_key("GET", "https://example.com")
    cache.set(key, {"hello": "world"})
    assert cache.get(key) is None
