"""Stage ``engine.fingerprint`` (WP7). Skeleton stub: replace the body, keep the @register arguments."""
from __future__ import annotations

from ..context import AnalysisContext
from ..models import StageResult
from ..registry import register

NAME = 'engine.fingerprint'


@register(name='engine.fingerprint', requires=('inventory',), after=('macho', 'meta'))
class EngineFingerprintStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        return StageResult.skipped(NAME, "not implemented")
