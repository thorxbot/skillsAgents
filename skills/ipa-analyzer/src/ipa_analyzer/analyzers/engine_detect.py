"""Stage ``engine.detect`` (WP7). Skeleton stub: replace the body, keep the @register arguments."""
from __future__ import annotations

from ..context import AnalysisContext
from ..models import StageResult
from ..registry import register

NAME = 'engine.detect'


@register(name='engine.detect', requires=('inventory',), after=('macho', 'meta', 'engine.fingerprint'))
class EngineDetectStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        return StageResult.skipped(NAME, "not implemented")
