from datetime import datetime
from typing import Any

from depwatch.core.models import PackageSignals, ScanResult, ScoredPackage
from depwatch.report.markdown import scan_to_markdown
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


def _result(packages: list[ScoredPackage], scan_id: int | None = None) -> ScanResult:
    return ScanResult(
        source="requirements.txt", created_at=DATE, packages=packages, scan_id=scan_id
    )


def test_markdown_has_a_heading_and_a_table_of_risky_packages() -> None:
    out = scan_to_markdown(_result([VULNERABLE, HEALTHY], scan_id=3))

    assert out.startswith("## depwatch")
    assert "| urllib3 |" in out
    assert "11 known vulnerabilities" in out
    assert "scan #3" in out
    assert "werkzeug" not in out  # low-risk, summarised not listed
    assert "1 package(s) look low-risk" in out


def test_markdown_when_all_healthy() -> None:
    out = scan_to_markdown(_result([HEALTHY]))
    assert "look low-risk" in out
    assert "|" not in out  # no table rendered


def test_markdown_notes_incomplete_scans() -> None:
    result = ScanResult(
        source="requirements.txt", created_at=DATE, packages=[VULNERABLE], scan_id=None, skipped=2
    )
    out = scan_to_markdown(result)
    assert "2 package(s) could not be scanned" in out


def test_markdown_when_empty() -> None:
    out = scan_to_markdown(_result([]))
    assert "No packages to scan" in out
