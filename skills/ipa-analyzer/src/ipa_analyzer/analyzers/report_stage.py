"""Stage ``report`` (WP8). Skeleton stub: replace the body, keep the @register arguments."""
from __future__ import annotations

from ..context import AnalysisContext
from ..models import StageResult
from ..registry import register

NAME = 'report'


@register(name='report', after=('ingest', 'inventory', 'meta', 'macho', 'engine.fingerprint', 'engine.detect', 'engine.other', 'engine.unity', 'engine.unity.hotfix', 'libs', 'protect', 'classify'), always_run=True)
class ReportStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        return StageResult.skipped(NAME, "not implemented")
