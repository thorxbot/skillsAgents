"""Stage ``libs`` (WP4). Skeleton stub: replace the body, keep the @register arguments."""
from __future__ import annotations

from ..context import AnalysisContext
from ..models import StageResult
from ..registry import register

NAME = 'libs'


@register(name='libs', requires=('inventory',), after=('macho', 'engine.fingerprint', 'engine.unity', 'engine.unity.hotfix', 'engine.other'))
class LibsStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        return StageResult.skipped(NAME, "not implemented")
