"""Work out the smallest version upgrade that clears a package's vulnerabilities.

Each OSV advisory describes the version windows it affects. A version is safe, as
far as known advisories go, when it falls outside every one of those windows. So
the minimal safe upgrade is the lowest released version, above the current one,
that sits in none of the affected windows. When no such version exists yet — some
advisory has no fix, or every higher version re-enters another window — we fall
back to the version that clears the most, and say how many remain.

This is pure: it takes the advisories already fetched for the package and does only
version arithmetic, so it is easy to test exhaustively.
"""

from __future__ import annotations

from packaging.version import InvalidVersion, Version

from depwatch.core.models import Remediation
from depwatch.ingest.osv import OSVVulnerability

# An affected window as comparable versions: (introduced, fixed), either may be None.
_Window = tuple[Version | None, Version | None]


def safe_upgrade(current_version: str, vulns: list[OSVVulnerability]) -> Remediation | None:
    """The minimal upgrade that clears the most vulnerabilities, or None if none helps."""
    try:
        current = Version(current_version)
    except InvalidVersion:
        return None

    # Group windows by display id so advisories that share a CVE (a GHSA and a PYSEC
    # entry for one flaw) count once — matching the deduped headline vulnerability count.
    by_id: dict[str, list[_Window]] = {}
    for vuln in vulns:
        windows = _windows(vuln)
        if windows:
            by_id.setdefault(_display_id(vuln), []).extend(windows)
    applicable = {vid: windows for vid, windows in by_id.items() if _affected(current, windows)}
    if not applicable:
        return None
    total = len(applicable)

    candidates = sorted(
        {
            fixed
            for windows in applicable.values()
            for _, fixed in windows
            if fixed is not None and fixed > current and not fixed.is_prerelease
        }
    )

    best: tuple[int, Version] | None = None
    for candidate in candidates:
        cleared = sum(1 for windows in applicable.values() if not _affected(candidate, windows))
        if cleared == total:
            return Remediation(target_version=str(candidate), clears=cleared, total=total)
        if best is None or cleared > best[0]:
            best = (cleared, candidate)

    if best is None or best[0] == 0:
        return None  # nothing upgradeable actually reduces the risk
    unfixed = sorted(vid for vid, windows in applicable.items() if not _has_fix(windows))
    return Remediation(
        target_version=str(best[1]), clears=best[0], total=total, unfixed_ids=unfixed
    )


def _windows(vuln: OSVVulnerability) -> list[_Window]:
    """The advisory's affected ranges as comparable (introduced, fixed) versions."""
    windows: list[_Window] = []
    for introduced, fixed in vuln.pypi_ranges():
        windows.append((_parse(introduced), _parse(fixed)))
    return windows


def _affected(version: Version, windows: list[_Window]) -> bool:
    """True when the version sits inside any affected window [introduced, fixed)."""
    for introduced, fixed in windows:
        if (introduced is None or version >= introduced) and (fixed is None or version < fixed):
            return True
    return False


def _has_fix(windows: list[_Window]) -> bool:
    return any(fixed is not None for _, fixed in windows)


def _parse(raw: str | None) -> Version | None:
    """Parse a version boundary; '0' and unparseable values become None (open-ended)."""
    if raw is None or raw == "0":
        return None
    try:
        return Version(raw)
    except InvalidVersion:
        return None


def _display_id(vuln: OSVVulnerability) -> str:
    """Prefer the CVE alias, mirroring how findings are labelled elsewhere."""
    for alias in vuln.aliases:
        if alias.startswith("CVE-"):
            return alias
    return vuln.id
