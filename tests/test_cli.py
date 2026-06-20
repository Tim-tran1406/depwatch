import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from depwatch import service
from depwatch.cli import app
from depwatch.core.models import PackageChange, PackageSignals, ScanDiff, ScanResult, ScoredPackage
from depwatch.scoring.score import score_package

runner = CliRunner()


def _scored(name: str, **kwargs: Any) -> ScoredPackage:
    signals = PackageSignals(name=name, version="1.0", is_direct=True, **kwargs)
    return ScoredPackage(signals=signals, risk=score_package(signals))


def _result(source: str, scan_id: int | None, **kwargs: Any) -> ScanResult:
    package = _scored("urllib3", **(kwargs or {"vulnerability_count": 11}))
    return ScanResult(
        source=source,
        created_at=datetime(2026, 6, 20, 12, 0, 0),
        packages=[package],
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


def test_scan_json_format_emits_valid_json(
    monkeypatch: pytest.MonkeyPatch, requirements: Path
) -> None:
    monkeypatch.setattr(service, "run_scan", lambda *a, **k: _result(str(requirements), 2))

    result = runner.invoke(app, ["scan", str(requirements), "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["scan_id"] == 2
    assert payload["packages"][0]["signals"]["name"] == "urllib3"


def test_scan_markdown_format(monkeypatch: pytest.MonkeyPatch, requirements: Path) -> None:
    monkeypatch.setattr(service, "run_scan", lambda *a, **k: _result(str(requirements), None))

    result = runner.invoke(app, ["scan", str(requirements), "--format", "markdown"])

    assert result.exit_code == 0
    assert "## depwatch" in result.stdout
    assert "| urllib3 |" in result.stdout


def test_scan_writes_html_to_output_file(
    monkeypatch: pytest.MonkeyPatch, requirements: Path, tmp_path: Path
) -> None:
    monkeypatch.setattr(service, "run_scan", lambda *a, **k: _result(str(requirements), None))
    out = tmp_path / "report.html"

    result = runner.invoke(app, ["scan", str(requirements), "--format", "html", "-o", str(out)])

    assert result.exit_code == 0
    assert out.read_text().startswith("<!doctype html>")
    assert "urllib3" in out.read_text()


def test_fail_on_high_exits_nonzero_for_risky_scan(
    monkeypatch: pytest.MonkeyPatch, requirements: Path
) -> None:
    monkeypatch.setattr(service, "run_scan", lambda *a, **k: _result(str(requirements), None))

    result = runner.invoke(app, ["scan", str(requirements), "--fail-on", "high"])

    assert result.exit_code == 1  # urllib3 with 11 vulns trips the gate
    assert "urllib3" in result.stdout  # the report still prints before the gate fails


def test_fail_on_off_is_the_default(monkeypatch: pytest.MonkeyPatch, requirements: Path) -> None:
    monkeypatch.setattr(service, "run_scan", lambda *a, **k: _result(str(requirements), None))

    result = runner.invoke(app, ["scan", str(requirements)])

    assert result.exit_code == 0


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


def test_since_last_renders_the_diff(monkeypatch: pytest.MonkeyPatch, requirements: Path) -> None:
    monkeypatch.setattr(service, "run_scan", lambda *a, **k: _result(str(requirements), 5))
    diff = ScanDiff(
        source=str(requirements),
        previous_scan_id=4,
        changes=[PackageChange(name="urllib3", status="worsened", detail="8 → 11 vulnerabilities")],
    )
    monkeypatch.setattr(service, "diff_against_previous", lambda *a, **k: diff)

    result = runner.invoke(app, ["scan", str(requirements), "--since-last"])

    assert result.exit_code == 0
    assert "Changes since scan #4" in result.stdout
    assert "urllib3" in result.stdout


def test_since_last_with_no_previous_scan(
    monkeypatch: pytest.MonkeyPatch, requirements: Path
) -> None:
    monkeypatch.setattr(service, "run_scan", lambda *a, **k: _result(str(requirements), 1))
    monkeypatch.setattr(service, "diff_against_previous", lambda *a, **k: None)

    result = runner.invoke(app, ["scan", str(requirements), "--since-last"])

    assert result.exit_code == 0
    assert "No previous scan" in result.stdout
