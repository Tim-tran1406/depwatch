"""Tests for the minimal-safe-upgrade computation."""

from __future__ import annotations

from depwatch.ingest.osv import OSVVulnerability
from depwatch.scoring.remediation import safe_upgrade


def _vuln(
    id_: str, *windows: tuple[str, str | None], aliases: tuple[str, ...] = ()
) -> OSVVulnerability:
    """Build an advisory whose affected ranges are the given (introduced, fixed) windows."""
    events: list[dict[str, str]] = []
    for introduced, fixed in windows:
        events.append({"introduced": introduced})
        if fixed is not None:
            events.append({"fixed": fixed})
    return OSVVulnerability(
        id=id_,
        summary=None,
        aliases=list(aliases),
        severity=[],
        severity_label=None,
        affected=[{"ranges": [{"type": "ECOSYSTEM", "events": events}]}],
    )


def test_picks_smallest_fully_safe_version() -> None:
    vulns = [_vuln("V1", ("0", "1.1.0")), _vuln("V2", ("0", "1.2.0"))]
    result = safe_upgrade("1.0.0", vulns)
    assert result is not None
    assert result.target_version == "1.2.0"
    assert result.clears == 2
    assert result.total == 2
    assert result.unfixed_ids == []


def test_skips_versions_that_re_enter_another_window() -> None:
    # Affected in the 1.x line (fixed 1.26.19) and again in 2.0–2.2.2, plus a wide
    # window fixed at 2.6.0. Only 2.6.0 sits outside every window.
    vulns = [
        _vuln("V", ("0", "1.26.19"), ("2.0.0", "2.2.2")),
        _vuln("W", ("1.0", "2.6.0")),
    ]
    result = safe_upgrade("1.26.5", vulns)
    assert result is not None
    assert result.target_version == "2.6.0"
    assert result.clears == 2


def test_partial_upgrade_when_an_advisory_has_no_fix() -> None:
    vulns = [
        _vuln("V1", ("0", "1.1.0")),
        _vuln("OPEN", ("0", None), aliases=("CVE-2026-9999",)),
    ]
    result = safe_upgrade("1.0.0", vulns)
    assert result is not None
    assert result.target_version == "1.1.0"
    assert result.clears == 1
    assert result.total == 2
    assert result.unfixed_ids == ["CVE-2026-9999"]


def test_no_vulnerabilities_means_no_suggestion() -> None:
    assert safe_upgrade("1.0.0", []) is None


def test_advisory_not_affecting_current_version_is_ignored() -> None:
    # Current 2.0.0 is past the only affected window, so there is nothing to fix.
    assert safe_upgrade("2.0.0", [_vuln("V", ("0", "1.5.0"))]) is None


def test_unfixable_only_yields_no_suggestion() -> None:
    assert safe_upgrade("1.0.0", [_vuln("V", ("0", None))]) is None


def test_prerelease_fix_is_not_recommended() -> None:
    assert safe_upgrade("1.0.0", [_vuln("V", ("0", "2.0.0rc1"))]) is None


def test_invalid_current_version_is_handled() -> None:
    assert safe_upgrade("not-a-version", [_vuln("V", ("0", "1.1.0"))]) is None


def test_pypi_ranges_only_reads_ecosystem_ranges() -> None:
    vuln = OSVVulnerability(
        id="V",
        summary=None,
        aliases=[],
        severity=[],
        severity_label=None,
        affected=[
            {"ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc"}]}]},
            {
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.5"}]}
                ]
            },
        ],
    )
    assert vuln.pypi_ranges() == [("1.0", "1.5")]


def test_last_affected_is_treated_as_no_clean_fix() -> None:
    vuln = OSVVulnerability(
        id="V",
        summary=None,
        aliases=[],
        severity=[],
        severity_label=None,
        affected=[
            {
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "1.5"}]}
                ]
            }
        ],
    )
    assert vuln.pypi_ranges() == [("0", None)]
