from datetime import datetime
from typing import Any

from depwatch.core.models import PackageSignals, ScanResult, ScoredPackage
from depwatch.report.html import scan_to_html
from depwatch.scoring.score import score_package

DATE = datetime(2026, 6, 20, 12, 0, 0)


def _scored(name: str, **kwargs: Any) -> ScoredPackage:
    signals = PackageSignals(name=name, version="1.0", is_direct=True, **kwargs)
    return ScoredPackage(signals=signals, risk=score_package(signals))


VULNERABLE = _scored("urllib3", vulnerability_count=11)
HEALTHY = _scored(
    "werkzeug",
    vulnerability_count=0,
    days_since_last_release=20,
    contributor_count=80,
    monthly_downloads=200_000_000,
    license="BSD-3-Clause",
)


def _result(packages: list[ScoredPackage]) -> ScanResult:
    return ScanResult(source="requirements.txt", created_at=DATE, packages=packages, scan_id=None)


def test_html_is_a_self_contained_document() -> None:
    out = scan_to_html(_result([VULNERABLE, HEALTHY]))

    assert out.startswith("<!doctype html>")
    assert "<style>" in out  # styles are inlined, no external assets
    assert "<table>" in out
    assert "urllib3" in out
    assert 'class="badge high"' in out or 'class="badge critical"' in out


def test_html_escapes_dynamic_text() -> None:
    sneaky = _scored("<script>", vulnerability_count=11)
    out = scan_to_html(_result([sneaky]))
    assert "<script>" not in out  # the package name is escaped, not injected
    assert "&lt;script&gt;" in out


def test_html_when_all_healthy() -> None:
    out = scan_to_html(_result([HEALTHY]))
    assert "look low-risk" in out
    assert "<table>" not in out
