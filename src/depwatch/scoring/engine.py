"""Score every resolved package by gathering its signals and combining them."""

from __future__ import annotations

import asyncio
import logging

from depwatch.core.models import ResolvedPackage, ScoredPackage
from depwatch.scoring.score import score_package
from depwatch.scoring.signals import SignalCollector

logger = logging.getLogger(__name__)


class ScoringEngine:
    def __init__(self, collector: SignalCollector) -> None:
        self._collector = collector

    async def score_all(self, packages: list[ResolvedPackage]) -> list[ScoredPackage]:
        results = await asyncio.gather(
            *(self._score_one(p) for p in packages), return_exceptions=True
        )
        scored: list[ScoredPackage] = []
        for package, result in zip(packages, results, strict=True):
            if isinstance(result, BaseException):
                logger.warning("could not score %s: %s", package.name, result)
                continue
            scored.append(result)
        return scored

    async def _score_one(self, package: ResolvedPackage) -> ScoredPackage:
        signals = await self._collector.collect(package)
        return ScoredPackage(signals=signals, risk=score_package(signals))
