import asyncio
from pathlib import Path

from pytest_httpx import HTTPXMock

from depwatch.config import Settings
from depwatch.core.models import Requirement, ResolvedPackage
from depwatch.core.resolve import DependencyResolver
from depwatch.ingest.depsdev import DepsDevClient, DepsDevDependencyNode
from depwatch.ingest.http import AsyncFetcher
from depwatch.ingest.pypi import PyPIClient

_FLASK_DEPS = {
    "nodes": [
        {"relation": "SELF", "versionKey": {"name": "flask", "version": "2.0.1"}},
        {"relation": "DIRECT", "versionKey": {"name": "click", "version": "8.4.1"}},
        {"relation": "INDIRECT", "versionKey": {"name": "markupsafe", "version": "3.0.3"}},
    ],
    "edges": [],
    "error": "",
}


def test_get_dependencies_parses_nodes(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    httpx_mock.add_response(json=_FLASK_DEPS)
    settings = Settings(cache_dir=tmp_path)

    async def run() -> list[DepsDevDependencyNode]:
        async with AsyncFetcher(settings) as fetcher:
            return await DepsDevClient(fetcher, settings).get_dependencies("flask", "2.0.1")

    nodes = asyncio.run(run())
    assert [n.name for n in nodes] == ["flask", "click", "markupsafe"]
    assert nodes[0].relation == "SELF"


def test_resolve_marks_direct_vs_transitive(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    httpx_mock.add_response(json=_FLASK_DEPS)
    settings = Settings(cache_dir=tmp_path)

    async def run() -> list[ResolvedPackage]:
        async with AsyncFetcher(settings) as fetcher:
            resolver = DependencyResolver(
                DepsDevClient(fetcher, settings), PyPIClient(fetcher, settings)
            )
            return await resolver.resolve([Requirement(name="flask", version="2.0.1")])

    packages = asyncio.run(run())
    by_name = {p.name: p for p in packages}
    assert by_name["flask"].is_direct is True
    assert by_name["click"].is_direct is False
    assert by_name["markupsafe"].version == "3.0.3"


def test_resolve_prefers_direct_pin_over_transitive(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    base = "https://api.deps.dev/v3/systems/pypi/packages"
    httpx_mock.add_response(
        url=f"{base}/alpha/versions/1.0:dependencies",
        json={
            "nodes": [
                {"relation": "SELF", "versionKey": {"name": "alpha", "version": "1.0"}},
                {"relation": "DIRECT", "versionKey": {"name": "shared", "version": "2.0"}},
            ]
        },
    )
    httpx_mock.add_response(
        url=f"{base}/shared/versions/9.9:dependencies",
        json={"nodes": [{"relation": "SELF", "versionKey": {"name": "shared", "version": "9.9"}}]},
    )
    settings = Settings(cache_dir=tmp_path)

    async def run() -> list[ResolvedPackage]:
        async with AsyncFetcher(settings) as fetcher:
            resolver = DependencyResolver(
                DepsDevClient(fetcher, settings), PyPIClient(fetcher, settings)
            )
            return await resolver.resolve(
                [
                    Requirement(name="alpha", version="1.0"),
                    Requirement(name="shared", version="9.9"),
                ]
            )

    packages = asyncio.run(run())
    shared = [p for p in packages if p.name == "shared"]
    assert len(shared) == 1
    assert shared[0].version == "9.9"  # direct pin wins over the 2.0 that alpha pulled in
    assert shared[0].is_direct is True
