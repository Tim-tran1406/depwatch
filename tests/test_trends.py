from datetime import datetime

from rich.console import Console

from depwatch.core.models import PackageSignals, RiskScore, ScanResult, ScoredPackage
from depwatch.report.render import render_diff
from depwatch.storage.models import StoredPackage
from depwatch.trends import compute_diff

T0 = datetime(2026, 6, 20, 12, 0, 0)


def _stored(name: str, overall_risk: float, vulns: int = 0, version: str = "1.0") -> StoredPackage:
    return StoredPackage(
        name=name,
        version=version,
        is_direct=True,
        overall_risk=overall_risk,
        vulnerability_count=vulns,
        highest_severity=None,
        days_since_last_release=None,
        monthly_downloads=None,
        contributor_count=None,
        license=None,
        dimensions=[],
    )


def _current(name: str, overall_risk: float, vulns: int = 0, version: str = "1.0") -> ScoredPackage:
    signals = PackageSignals(name=name, version=version, is_direct=True, vulnerability_count=vulns)
    return ScoredPackage(signals=signals, risk=RiskScore(overall=overall_risk, dimensions=[]))


def _result(*packages: ScoredPackage) -> ScanResult:
    return ScanResult(source="requirements.txt", created_at=T0, packages=list(packages), scan_id=2)


def _diff(previous: list[StoredPackage], result: ScanResult) -> dict[str, str]:
    diff = compute_diff(result, previous, previous_scan_id=1)
    return {c.name: c.status for c in diff.changes}


def test_new_risky_package_is_added() -> None:
    changes = _diff([], _result(_current("pyyaml", 0.5)))
    assert changes == {"pyyaml": "added"}


def test_new_low_risk_package_is_not_flagged() -> None:
    assert _diff([], _result(_current("typing-extensions", 0.02))) == {}


def test_dropped_package_is_removed() -> None:
    changes = _diff([_stored("olddep", 0.4)], _result())
    assert changes == {"olddep": "removed"}


def test_more_vulnerabilities_is_worsened() -> None:
    diff = compute_diff(
        _result(_current("urllib3", 0.35, vulns=11)),
        [_stored("urllib3", 0.35, vulns=8)],
        previous_scan_id=1,
    )
    assert diff.changes[0].status == "worsened"
    assert "8 → 11 vulnerabilities" in diff.changes[0].detail


def test_rising_band_is_worsened_with_detail() -> None:
    diff = compute_diff(
        _result(_current("flask", 0.5)),
        [_stored("flask", 0.2)],
        previous_scan_id=1,
    )
    assert diff.changes[0].status == "worsened"
    assert "moderate → critical" in diff.changes[0].detail


def test_resolved_package_is_improved() -> None:
    diff = compute_diff(
        _result(_current("urllib3", 0.05, vulns=0, version="2.0.0")),
        [_stored("urllib3", 0.5, vulns=11, version="1.26.5")],
        previous_scan_id=1,
    )
    assert diff.changes[0].status == "improved"
    assert "11 → 0 vulnerabilities" in diff.changes[0].detail
    assert "1.26.5 → 2.0.0" in diff.changes[0].detail


def test_unchanged_package_is_omitted() -> None:
    assert (
        _diff([_stored("requests", 0.27, vulns=3)], _result(_current("requests", 0.27, vulns=3)))
        == {}
    )


def test_render_diff_lists_changes() -> None:
    diff = compute_diff(
        _result(_current("urllib3", 0.35, vulns=11)),
        [_stored("urllib3", 0.35, vulns=8)],
        previous_scan_id=4,
    )
    console = Console(width=100, force_terminal=False)
    with console.capture() as capture:
        render_diff(console, diff)
    out = capture.get()
    assert "Changes since scan #4" in out
    assert "urllib3" in out


def test_render_diff_when_nothing_changed() -> None:
    diff = compute_diff(_result(), [], previous_scan_id=4)
    console = Console(force_terminal=False)
    with console.capture() as capture:
        render_diff(console, diff)
    assert "No changes since scan #4" in capture.get()
