"""Read a requirements.txt file into a clean list of requirements.

We only need the package name and, when present, the pinned version. Anything we
cannot interpret as a simple named requirement (option lines, URLs, local paths)
is skipped rather than guessed at.
"""

from __future__ import annotations

from pathlib import Path

from packaging.requirements import InvalidRequirement
from packaging.requirements import Requirement as PackagingRequirement
from packaging.utils import canonicalize_name

from depwatch.core.models import Requirement


def parse_requirements_file(path: Path) -> list[Requirement]:
    return parse_requirements(path.read_text().splitlines())


def parse_requirements(lines: list[str]) -> list[Requirement]:
    requirements: list[Requirement] = []
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue  # comments, blanks, and option lines (-r, -e, --hash, ...)
        try:
            parsed = PackagingRequirement(line)
        except InvalidRequirement:
            continue  # URLs, local paths, anything not a plain named requirement
        requirements.append(
            Requirement(name=canonicalize_name(parsed.name), version=_pinned_version(parsed))
        )
    return requirements


def _pinned_version(parsed: PackagingRequirement) -> str | None:
    for spec in parsed.specifier:
        if spec.operator in ("==", "==="):
            return spec.version
    return None
