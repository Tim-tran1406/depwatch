import json
from datetime import datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from depwatch import service
from depwatch.cli import app
from depwatch.core.models import PackageSignals, ScanResult, ScoredPackage
from depwatch.scoring.score import score_package

runner = CliRunner()


def _result(source: str, scan_id: int | None) -> ScanResult:
    signals = PackageSignals(
        name="urllib3", version="1.26.5", is_direct=True, vulnerability_count=11
    )
    scored = ScoredPackage(signals=signals, risk=score_package(signals))
    return ScanResult(
        source=source,
        created_at=datetime(2026, 6, 20, 12, 0, 0),
        packages=[scored],
        scan_id=scan_id,
    )


@pytest.fixture
def requirements(tmp_path: Path) -> Path:
    path = tmp_path / "requirements.txt"
    path.write_text("urllib3==1.26.5\n")
    return path


def test_scan_renders_a_table(monkeypatch: pytest.MonkeyPatch, requirements: Path) -> None:
    monkeypatch.setattr(service, "run_scan", lambda *a, **k: _result(str(requirements), 1))

    result = runner.invoke(app, ["scan", str(requirements)])

    assert result.exit_code == 0
    assert "urllib3" in result.stdout
    assert "scan #1" in result.stdout


def test_scan_json_flag_emits_valid_json(
    monkeypatch: pytest.MonkeyPatch, requirements: Path
) -> None:
    monkeypatch.setattr(service, "run_scan", lambda *a, **k: _result(str(requirements), 2))

    result = runner.invoke(app, ["scan", str(requirements), "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["scan_id"] == 2
    assert payload["packages"][0]["signals"]["name"] == "urllib3"


def test_scan_passes_no_save_through(monkeypatch: pytest.MonkeyPatch, requirements: Path) -> None:
    seen: dict[str, object] = {}

    def fake(req: Path, settings: object, *, save: bool = True) -> ScanResult:
        seen["save"] = save
        return _result(str(req), None)

    monkeypatch.setattr(service, "run_scan", fake)

    result = runner.invoke(app, ["scan", str(requirements), "--no-save"])

    assert result.exit_code == 0
    assert seen["save"] is False


def test_scan_rejects_a_missing_file() -> None:
    result = runner.invoke(app, ["scan", "does-not-exist.txt"])
    assert result.exit_code != 0
