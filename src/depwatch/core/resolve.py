"""Resolve a project's full dependency set from its top-level requirements.

For each requirement we ask deps.dev for the resolved dependency graph (the exact
versions that would be installed, direct and transitive), then merge them into one
deduplicated set. A package is "direct" if it is named in the requirements file.
"""

from __future__ import annotations

import asyncio
import logging

from packaging.utils import canonicalize_name

from depwatch.core.models import Requirement, ResolvedPackage
from depwatch.ingest.depsdev import DepsDevClient, DepsDevDependencyNode
from depwatch.ingest.pypi import PyPIClient

logger = logging.getLogger(__name__)


class DependencyResolver:
    def __init__(self, depsdev: DepsDevClient, pypi: PyPIClient) -> None:
        self._depsdev = depsdev
        self._pypi = pypi

    async def resolve(self, requirements: list[Requirement]) -> list[ResolvedPackage]:
        direct_names = {req.name for req in requirements}
        graphs = await asyncio.gather(*(self._resolve_one(req) for req in requirements))
        resolved: dict[str, ResolvedPackage] = {}
        for nodes in graphs:
            for node in nodes:
                name = canonicalize_name(node.name)
                if node.relation == "SELF":
                    # The package the user listed: its pinned version is authoritative,
                    # so a SELF node always wins over the same name seen transitively.
                    resolved[name] = ResolvedPackage(
                        name=name, version=node.version, is_direct=True
                    )
                elif name not in resolved:
                    resolved[name] = ResolvedPackage(
                        name=name, version=node.version, is_direct=name in direct_names
                    )
        return list(resolved.values())

    async def _resolve_one(self, req: Requirement) -> list[DepsDevDependencyNode]:
        try:
            version = req.version or (await self._pypi.get_package(req.name)).latest_version
            return await self._depsdev.get_dependencies(req.name, version)
        except Exception as exc:  # one unresolvable package should not fail the whole scan
            logger.warning("could not resolve %s: %s", req.name, exc)
            return []
