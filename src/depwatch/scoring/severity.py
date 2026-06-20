"""Turn an advisory's severity into a single 0-10 number.

OSV gives severity two ways: a precise CVSS vector (v3 or v4) and, for
GitHub-reviewed advisories, a coarse label ("HIGH", "MODERATE", ...). We prefer
the CVSS base score and fall back to the label, so an advisory with either still
gets a real number instead of a flat guess.
"""

from __future__ import annotations

from cvss import CVSS3, CVSS4

# Representative midpoint of each qualitative CVSS band, for advisories that only
# carry a label. "moderate" is GitHub's name for what CVSS calls "medium".
_LABEL_SCORE: dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "moderate": 5.0,
    "medium": 5.0,
    "low": 2.0,
}


def cvss_base_score(vector: str) -> float | None:
    """Parse a CVSS v3 or v4 vector string into its base score, or None if unparseable."""
    try:
        if vector.startswith("CVSS:4"):
            return float(CVSS4(vector).base_score)
        if vector.startswith("CVSS:3"):
            return float(CVSS3(vector).base_score)
    except Exception:
        return None
    return None


def label_score(label: str | None) -> float | None:
    """Map a qualitative severity label to a representative number, or None if unknown."""
    if label is None:
        return None
    return _LABEL_SCORE.get(label.strip().lower())


def best_severity(vectors: list[str], label: str | None) -> float | None:
    """The most precise severity available: the highest CVSS base score, else the label."""
    scores = [score for vector in vectors if (score := cvss_base_score(vector)) is not None]
    if scores:
        return max(scores)
    return label_score(label)
