"""Stage ``engine.unity.hotfix`` (WP5b). Skeleton stub: replace the body, keep the @register arguments."""
from __future__ import annotations

from ..context import AnalysisContext
from ..models import StageResult
from ..registry import register

NAME = 'engine.unity.hotfix'


@register(name='engine.unity.hotfix', requires=('engine.unity',), after=('inventory', 'macho'))
class EngineUnityHotfixStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        return StageResult.skipped(NAME, "not implemented")
