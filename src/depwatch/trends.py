"""Compare a fresh scan against the previously stored one and describe what changed.

The comparison is keyed by package name. A package can be newly added, removed,
worsened (its band rose or it gained vulnerabilities), or improved. Packages that
did not change are left out, so the result is only the news.
"""

from __future__ import annotations

from depwatch.core.models import PackageChange, ScanDiff, ScanResult, ScoredPackage
from depwatch.scoring.bands import RiskBand, classify
from depwatch.storage.models import StoredPackage

_SEVERITY_ORDER = [RiskBand.LOW, RiskBand.MODERATE, RiskBand.HIGH, RiskBand.CRITICAL]


def compute_diff(
    result: ScanResult, previous: list[StoredPackage], previous_scan_id: int
) -> ScanDiff:
    previous_by_name = {package.name: package for package in previous}
    current_by_name = {package.signals.name: package for package in result.packages}
    changes: list[PackageChange] = []
    for name in sorted(previous_by_name.keys() | current_by_name.keys()):
        change = _classify(name, previous_by_name.get(name), current_by_name.get(name))
        if change is not None:
            changes.append(change)
    return ScanDiff(source=result.source, previous_scan_id=previous_scan_id, changes=changes)


def _classify(
    name: str, previous: StoredPackage | None, current: ScoredPackage | None
) -> PackageChange | None:
    if previous is None and current is not None:
        band = classify(current.risk.overall)
        if band is RiskBand.LOW:
            return None  # a new low-risk dependency is not worth flagging
        return PackageChange(name=name, status="added", detail=f"new dependency, {band.value} risk")
    if current is None and previous is not None:
        return PackageChange(name=name, status="removed", detail="no longer in the project")

    assert previous is not None and current is not None
    previous_band = classify(previous.overall_risk)
    current_band = classify(current.risk.overall)
    band_delta = _SEVERITY_ORDER.index(current_band) - _SEVERITY_ORDER.index(previous_band)
    vuln_delta = current.signals.vulnerability_count - previous.vulnerability_count
    if band_delta == 0 and vuln_delta == 0:
        return None  # unchanged (a bare version bump with no risk impact is not news)

    detail = _detail(previous, current, previous_band, current_band)
    worsened = band_delta > 0 or vuln_delta > 0
    return PackageChange(name=name, status="worsened" if worsened else "improved", detail=detail)


def _detail(
    previous: StoredPackage,
    current: ScoredPackage,
    previous_band: RiskBand,
    current_band: RiskBand,
) -> str:
    bits: list[str] = []
    if previous_band is not current_band:
        bits.append(f"{previous_band.value} → {current_band.value}")
    prev_vulns = previous.vulnerability_count
    curr_vulns = current.signals.vulnerability_count
    if prev_vulns != curr_vulns:
        bits.append(f"{prev_vulns} → {curr_vulns} vulnerabilities")
    if previous.version != current.signals.version:
        bits.append(f"{previous.version} → {current.signals.version}")
    return ", ".join(bits)
