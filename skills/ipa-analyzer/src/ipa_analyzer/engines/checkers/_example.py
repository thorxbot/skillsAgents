"""Example engine checker (template for WP7b). ``applies()`` is always False so it never runs.

To add a checker: create ``engines/checkers/<name>.py`` with a class that has ``applies`` and ``run``
and decorate it with ``@register_checker("<engine_id>")``; no other file needs to change.
"""
from __future__ import annotations

from ...context import AnalysisContext
from ...models import Evidence, Finding, Verdict
from ..api import CheckerResult, DetectResult, register_checker


@register_checker("example")
class ExampleChecker:
    engine_id = "example"

    def applies(self, ctx: AnalysisContext, detect: DetectResult) -> bool:
        return False   # a real checker would test e.g. detect.has("cocos2dx_lua")

    def run(self, ctx: AnalysisContext, detect: DetectResult) -> CheckerResult:
        finding = Finding(
            id="engine.script.encrypted", verdict=Verdict.UNKNOWN, confidence=0.0,
            title="Example checker did not inspect anything",
            evidence=[Evidence(kind="heuristic", ref="example", detail="template only")],
            tags=["engine:example"])
        return CheckerResult(findings=[finding], data={"note": "template"})
