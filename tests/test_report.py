import json
from datetime import datetime
from typing import Any

from rich.console import Console

from depwatch.core.models import PackageSignals, ScanResult, ScoredPackage
from depwatch.report.render import render_scan, scan_to_json
from depwatch.scoring.score import score_package

T0 = datetime(2026, 6, 20, 12, 0, 0)


def _scored(name: str, **kwargs: Any) -> ScoredPackage:
    signals = PackageSignals(
        name=name,
        version=kwargs.pop("version", "1.0"),
        is_direct=kwargs.pop("is_direct", True),
        **kwargs,
    )
    return ScoredPackage(signals=signals, risk=score_package(signals))


VULNERABLE = _scored("urllib3", version="1.26.5", vulnerability_count=11)
STALE = _scored("itsdangerous", version="2.2.0", days_since_last_release=794)
HEALTHY = _scored(
    "werkzeug",
    is_direct=False,
    vulnerability_count=0,
    days_since_last_release=30,
    contributor_count=80,
    monthly_downloads=200_000_000,
    license="BSD-3-Clause",
)


def _render(result: ScanResult, *, limit: int = 10) -> str:
    console = Console(width=120, force_terminal=False)
    with console.capture() as capture:
        render_scan(console, result, limit=limit)
    return capture.get()


def test_report_lists_risky_packages_with_their_findings() -> None:
    result = ScanResult(
        source="requirements.txt",
        created_at=T0,
        packages=[VULNERABLE, STALE, HEALTHY],
        scan_id=1,
    )
    out = _render(result)

    assert "urllib3" in out
    assert "11 known vulnerabilities" in out  # the finding, not just the score
    assert "scan #1" in out


def test_report_hides_healthy_packages_but_counts_them() -> None:
    result = ScanResult(
        source="requirements.txt", created_at=T0, packages=[VULNERABLE, HEALTHY], scan_id=None
    )
    out = _render(result)

    assert "werkzeug" not in out  # low-risk, not listed
    assert "1 package(s) look low-risk" in out


def test_report_warns_about_skipped_packages() -> None:
    result = ScanResult(
        source="requirements.txt", created_at=T0, packages=[VULNERABLE], scan_id=None, skipped=3
    )
    out = _render(result)
    assert "3 package(s) could not be scanned" in out


def test_report_when_everything_is_healthy() -> None:
    result = ScanResult(source="requirements.txt", created_at=T0, packages=[HEALTHY], scan_id=None)
    out = _render(result)
    assert "All 1 packages look low-risk" in out


def test_report_limit_truncates_and_notes_the_remainder() -> None:
    many = [_scored(f"pkg{i}", vulnerability_count=11) for i in range(5)]
    result = ScanResult(source="requirements.txt", created_at=T0, packages=many, scan_id=None)
    out = _render(result, limit=2)
    assert "3 more risky package(s) not shown" in out


def test_json_output_is_valid_and_complete() -> None:
    result = ScanResult(
        source="requirements.txt", created_at=T0, packages=[VULNERABLE, HEALTHY], scan_id=7
    )
    payload = json.loads(scan_to_json(result))

    assert payload["scan_id"] == 7
    assert payload["source"] == "requirements.txt"
    names = {p["signals"]["name"] for p in payload["packages"]}
    assert names == {"urllib3", "werkzeug"}
