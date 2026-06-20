import json
from datetime import datetime
from pathlib import Path
from typing import Any

from depwatch.core.models import PackageSignals, ScanResult, ScoredPackage
from depwatch.report.sarif import scan_to_sarif
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


CRITICAL = _scored("pyyaml", version="5.3.1", vulnerability_count=1, highest_severity=9.8)
HEALTHY = _scored(
    "werkzeug",
    vulnerability_count=0,
    days_since_last_release=10,
    contributor_count=80,
    monthly_downloads=200_000_000,
    license="BSD-3-Clause",
)


def _result(*packages: ScoredPackage, source: str = "requirements.txt") -> ScanResult:
    return ScanResult(source=source, created_at=T0, packages=list(packages), scan_id=None)


def test_sarif_is_valid_210_with_tool_and_rules() -> None:
    doc = json.loads(scan_to_sarif(_result(CRITICAL)))
    assert doc["version"] == "2.1.0"
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "depwatch"
    rule_ids = {r["id"] for r in driver["rules"]}
    assert "depwatch/vulnerabilities" in rule_ids


def test_critical_package_is_an_error_result() -> None:
    doc = json.loads(scan_to_sarif(_result(CRITICAL)))
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    result = results[0]
    assert result["level"] == "error"
    assert result["ruleId"] == "depwatch/vulnerabilities"
    assert "pyyaml" in result["message"]["text"]
    assert "highest severity 9.8" in result["message"]["text"]


def test_healthy_packages_produce_no_results() -> None:
    doc = json.loads(scan_to_sarif(_result(HEALTHY)))
    assert doc["runs"][0]["results"] == []


def test_result_points_at_the_declaring_line(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("# comment\nwerkzeug==3.0.0\npyyaml==5.3.1\n")

    doc = json.loads(scan_to_sarif(_result(CRITICAL), requirements_path=req))
    location = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == str(req)
    assert location["region"]["startLine"] == 3  # pyyaml is on line 3


def test_unmapped_package_falls_back_to_line_one(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("flask==2.0.1\n")  # pyyaml is transitive, not in the file

    doc = json.loads(scan_to_sarif(_result(CRITICAL), requirements_path=req))
    region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 1
