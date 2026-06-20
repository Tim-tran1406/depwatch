"""Pure functions that score one package on each risk dimension.

Each returns a DimensionScore between 0 (safe) and 1 (risky) plus a short reason.
They take already-gathered signals and never touch the network, which is what makes
them easy to test exhaustively.
"""

from __future__ import annotations

import math

from depwatch.core.models import DimensionScore, PackageSignals

# Maintenance: no concern under ~6 months since release; fully stale after ~2 years.
_FRESH_DAYS = 180
_STALE_DAYS = 730

# License buckets, matched as substrings of the declared license text.
_PERMISSIVE = ("mit", "apache", "bsd", "isc", "python", "psf", "zlib", "unlicense")
_COPYLEFT = ("gpl", "agpl", "lgpl", "mpl", "epl", "cddl")


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def score_vulnerabilities(s: PackageSignals) -> DimensionScore:
    if s.vulnerability_count == 0:
        return DimensionScore(name="vulnerabilities", score=0.0, reason="no known vulnerabilities")
    severity = s.highest_severity if s.highest_severity is not None else 5.0
    score = _clamp(severity / 10.0 + 0.1 * (s.vulnerability_count - 1))
    suffix = "y" if s.vulnerability_count == 1 else "ies"
    named = _name_advisories(s.vulnerability_ids, s.vulnerability_count)
    return DimensionScore(
        name="vulnerabilities",
        score=score,
        reason=f"{s.vulnerability_count} known vulnerabilit{suffix}{named}, "
        f"highest severity {severity:g}",
    )


def _name_advisories(ids: list[str], count: int) -> str:
    """A short '(CVE-… +N more)' note for the reason, or empty when no ids are known."""
    if not ids:
        return ""
    if count > 1:
        return f" ({ids[0]} +{count - 1} more)"
    return f" ({ids[0]})"


def score_maintenance(s: PackageSignals) -> DimensionScore:
    if s.days_since_last_release is None:
        return DimensionScore(name="maintenance", score=0.5, reason="last release date unknown")
    score = _clamp((s.days_since_last_release - _FRESH_DAYS) / (_STALE_DAYS - _FRESH_DAYS))
    return DimensionScore(
        name="maintenance",
        score=score,
        reason=f"last released {s.days_since_last_release} days ago",
    )


def score_bus_factor(s: PackageSignals) -> DimensionScore:
    if s.contributor_count is None:
        return DimensionScore(name="bus_factor", score=0.5, reason="contributor data unavailable")
    # A single maintainer is the riskiest; ~10+ contributors spreads the bus factor.
    score = _clamp((10 - s.contributor_count) / 9)
    return DimensionScore(
        name="bus_factor", score=score, reason=f"{s.contributor_count} contributor(s)"
    )


def score_adoption(s: PackageSignals) -> DimensionScore:
    # Log scale: ~10M downloads/month is effectively zero risk; zero downloads is full risk.
    score = _clamp(1.0 - math.log10(s.monthly_downloads + 1) / 7.0)
    return DimensionScore(
        name="adoption", score=score, reason=f"{s.monthly_downloads:,} downloads last month"
    )


def score_license(s: PackageSignals) -> DimensionScore:
    if not s.license or s.license.strip().lower() in ("", "unknown"):
        return DimensionScore(name="license", score=0.7, reason="no license declared")
    text = s.license.lower()
    if any(key in text for key in _PERMISSIVE):
        return DimensionScore(name="license", score=0.0, reason=f"permissive license ({s.license})")
    if any(key in text for key in _COPYLEFT):
        return DimensionScore(name="license", score=0.4, reason=f"copyleft license ({s.license})")
    return DimensionScore(name="license", score=0.3, reason=f"uncommon license ({s.license})")
