"""Stage ``engine.unity`` (WP5). Skeleton stub: replace the body, keep the @register arguments."""
from __future__ import annotations

from ..context import AnalysisContext
from ..models import StageResult
from ..registry import register

NAME = 'engine.unity'


@register(name='engine.unity', requires=('engine.detect', 'inventory'), after=('macho', 'meta'))
class EngineUnityStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        return StageResult.skipped(NAME, "not implemented")
