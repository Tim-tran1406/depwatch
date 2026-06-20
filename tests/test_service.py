from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from depwatch import service
from depwatch.config import Settings
from depwatch.core.models import PackageSignals, ScoredPackage
from depwatch.scoring.score import score_package
from depwatch.storage.store import ScanStore

T0 = datetime(2026, 6, 20, 12, 0, 0)


def _scored(name: str, **kwargs: Any) -> ScoredPackage:
    signals = PackageSignals(name=name, version="1.0", is_direct=True, **kwargs)
    return ScoredPackage(signals=signals, risk=score_package(signals))


RISKY = _scored("urllib3", vulnerability_count=11, highest_severity=9.0)
HEALTHY = _scored(
    "werkzeug",
    days_since_last_release=10,
    contributor_count=80,
    monthly_downloads=200_000_000,
    license="MIT",
)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(cache_dir=tmp_path / "cache", db_path=tmp_path / "depwatch.duckdb")


def _stub_score(monkeypatch: pytest.MonkeyPatch, packages: Iterable[ScoredPackage]) -> None:
    async def fake(requirements: Path, settings: Settings) -> list[ScoredPackage]:
        return list(packages)

    monkeypatch.setattr(service, "_score", fake)


def test_run_scan_sorts_riskiest_first(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, tmp_path: Path
) -> None:
    _stub_score(monkeypatch, [HEALTHY, RISKY])

    result = service.run_scan(tmp_path / "r.txt", settings, save=False, created_at=T0)

    assert [p.signals.name for p in result.packages] == ["urllib3", "werkzeug"]
    assert result.created_at == T0
    assert result.source == str(tmp_path / "r.txt")


def test_run_scan_saves_by_default(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, tmp_path: Path
) -> None:
    _stub_score(monkeypatch, [RISKY])

    result = service.run_scan(tmp_path / "r.txt", settings, created_at=T0)

    assert result.scan_id is not None
    with ScanStore(settings.db_path) as store:  # the scan is genuinely persisted
        summary = store.scan_summary(result.scan_id)
        assert summary is not None and summary.package_count == 1


def test_run_scan_skips_save_when_disabled(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, tmp_path: Path
) -> None:
    _stub_score(monkeypatch, [RISKY])

    result = service.run_scan(tmp_path / "r.txt", settings, save=False, created_at=T0)

    assert result.scan_id is None
    with ScanStore(settings.db_path) as store:
        assert store.list_scans() == []
