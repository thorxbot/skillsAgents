"""Stage ``protect`` (WP4). Skeleton stub: replace the body, keep the @register arguments."""
from __future__ import annotations

from ..context import AnalysisContext
from ..models import StageResult
from ..registry import register

NAME = 'protect'


@register(name='protect', requires=('inventory',), after=('macho', 'engine.unity', 'engine.unity.hotfix', 'engine.other', 'libs'))
class ProtectStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        return StageResult.skipped(NAME, "not implemented")
