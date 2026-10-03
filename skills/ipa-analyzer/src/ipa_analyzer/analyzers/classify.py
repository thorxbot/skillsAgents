"""Stage ``classify`` (WP4). Skeleton stub: replace the body, keep the @register arguments."""
from __future__ import annotations

from ..context import AnalysisContext
from ..models import StageResult
from ..registry import register

NAME = 'classify'


@register(name='classify', after=('meta', 'engine.detect', 'engine.fingerprint', 'libs'))
class ClassifyStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        return StageResult.skipped(NAME, "not implemented")
