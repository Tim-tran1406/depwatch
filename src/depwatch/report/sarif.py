"""Render a scan result as SARIF, so findings show up in GitHub code scanning.

GitHub ingests SARIF 2.1.0 and turns each result into an inline annotation on the
pull request and an entry in the Security tab. Every risky package becomes one
result, categorised by the dimension driving its risk and located, where possible,
at the line in the requirements file that declares it.
"""

from __future__ import annotations

import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from packaging.requirements import InvalidRequirement
from packaging.requirements import Requirement as PackagingRequirement
from packaging.utils import canonicalize_name

from depwatch.core.models import ScanResult, ScoredPackage
from depwatch.report.summary import key_finding, select_risky
from depwatch.scoring.bands import RiskBand, classify

_INFORMATION_URI = "https://github.com/Tim-tran1406/depwatch"

# The dimensions, as SARIF rules so findings group sensibly in the Security tab.
_RULES: dict[str, str] = {
    "vulnerabilities": "Known security vulnerabilities",
    "maintenance": "Stale or unmaintained release history",
    "bus_factor": "Maintained by very few people",
    "adoption": "Low adoption",
    "license": "Risky or missing license",
}

# SARIF severity level per risk band (only risky packages are emitted).
_LEVEL: dict[RiskBand, str] = {
    RiskBand.CRITICAL: "error",
    RiskBand.HIGH: "error",
    RiskBand.MODERATE: "warning",
    RiskBand.LOW: "note",
}


def scan_to_sarif(result: ScanResult, requirements_path: str | Path | None = None) -> str:
    """The risky packages as a SARIF 2.1.0 document."""
    uri = str(requirements_path) if requirements_path is not None else result.source
    line_of = _line_numbers(requirements_path)
    risky = select_risky(result.packages)
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "depwatch",
                        "informationUri": _INFORMATION_URI,
                        "version": _tool_version(),
                        "rules": [_rule(dim, desc) for dim, desc in _RULES.items()],
                    }
                },
                "results": [_result_for(package, uri, line_of) for package in risky],
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _rule(dimension: str, description: str) -> dict[str, object]:
    return {
        "id": f"depwatch/{dimension}",
        "name": dimension,
        "shortDescription": {"text": description},
        "helpUri": _INFORMATION_URI,
    }


def _result_for(package: ScoredPackage, uri: str, line_of: dict[str, int]) -> dict[str, object]:
    band = classify(package.risk.overall)
    driver = max(package.risk.dimensions, key=lambda d: d.score)
    name, version_ = package.signals.name, package.signals.version
    return {
        "ruleId": f"depwatch/{driver.name}",
        "level": _LEVEL[band],
        "message": {
            "text": f"{name} {version_}: {key_finding(package)} "
            f"(risk {package.risk.overall:.2f}, {band.value})"
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line_of.get(name, 1)},
                }
            }
        ],
        "partialFingerprints": {"depwatch/v1": f"{name}@{version_}"},
        "properties": {"risk": round(package.risk.overall, 4), "band": band.value},
    }


def _line_numbers(requirements_path: str | Path | None) -> dict[str, int]:
    """Map each declared package name to its 1-based line, for inline annotations."""
    if requirements_path is None:
        return {}
    try:
        text = Path(requirements_path).read_text(encoding="utf-8")
    except OSError:
        return {}
    mapping: dict[str, int] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith(("#", "-")):
            continue
        try:
            name = canonicalize_name(PackagingRequirement(line).name)
        except InvalidRequirement:
            continue
        mapping.setdefault(name, number)
    return mapping


def _tool_version() -> str:
    try:
        return version("depwatch")
    except PackageNotFoundError:  # pragma: no cover - only when not installed
        return "0"
