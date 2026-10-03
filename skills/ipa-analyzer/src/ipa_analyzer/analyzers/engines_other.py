"""Stage ``engine.other`` (WP7b). Skeleton stub: replace the body, keep the @register arguments."""
from __future__ import annotations

from ..context import AnalysisContext
from ..models import StageResult
from ..registry import register

NAME = 'engine.other'


@register(name='engine.other', requires=('engine.detect',))
class EngineOtherStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        return StageResult.skipped(NAME, "not implemented")
