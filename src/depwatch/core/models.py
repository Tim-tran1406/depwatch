"""Core domain models that flow through depwatch."""

from __future__ import annotations

from pydantic import BaseModel


class Requirement(BaseModel):
    """A single line from a requirements file: a package and an optional pinned version."""

    name: str
    version: str | None


class ResolvedPackage(BaseModel):
    """A package in the fully resolved dependency set, and how it was pulled in."""

    name: str
    version: str
    is_direct: bool
