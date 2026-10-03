"""Stage ``macho`` (WP3). Skeleton stub: replace the body, keep the @register arguments."""
from __future__ import annotations

from ..context import AnalysisContext
from ..models import StageResult
from ..registry import register

NAME = 'macho'


@register(name='macho', requires=('inventory',))
class MachoStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        return StageResult.skipped(NAME, "not implemented")
