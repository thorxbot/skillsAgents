"""Stage ``engine.other`` (WP7b): run the engine checkers that match ``engine.detect`` and merge their results.

Every registered ``EngineChecker`` (``engines/checkers/*.py``, auto-discovered) is asked ``applies(ctx, detect)``;
the ones that say yes are run in ``engine_id`` order, each isolated: an exception in one checker is recorded in
``_checkers`` and the others still run (stage ``partial``).  Result shape (CONTRACT-FREEZE section 4.7)::

    ctx.results["engine.other"] = {"<engine_id>": <CheckerResult.data>, ...,
                                   "_checkers": {"<engine_id>": {status, reason, error, duration_s}}}

Checkers that declare ``fallback = True`` (generic ``lua`` / ``generic_scripts``) are only run when no dedicated
checker applies.  No checker applies -> stage ``skipped``.  Checkers only inspect and report; nothing is decrypted or executed.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List

from ..context import AnalysisContext
from ..engines.api import CheckerResult, DetectResult, EngineChecker, checker_import_failures, get_checkers
from ..models import Finding, StageResult, Status
from ..registry import register

log = logging.getLogger(__name__)

NAME = 'engine.other'


def _applicable(ctx: AnalysisContext, detect: DetectResult, checkers: List[EngineChecker],
                meta: Dict[str, Dict[str, Any]], warnings: List[str]) -> List[EngineChecker]:
    chosen: List[EngineChecker] = []
    for c in checkers:
        try:
            if c.applies(ctx, detect):
                chosen.append(c)
        except Exception as exc:  # noqa: BLE001 - one broken applies() must not stop the others
            log.warning("engine checker %s: applies() failed", c.engine_id, exc_info=True)
            meta[c.engine_id] = {"status": Status.FAILED.value, "reason": None,
                                 "error": "applies: %s: %s" % (type(exc).__name__, exc), "duration_s": 0.0}
            warnings.append("checker %s: applies() raised %s" % (c.engine_id, type(exc).__name__))
    return chosen


@register(name='engine.other', requires=('engine.detect',))
class EngineOtherStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        raw = ctx.results.get("engine.detect")
        if raw is None:
            return StageResult.skipped(NAME, "engine.detect produced no result")
        detect = raw if isinstance(raw, DetectResult) else DetectResult.from_dict(raw)
        warnings: List[str] = []
        meta: Dict[str, Dict[str, Any]] = {}
        for mod, err in sorted(checker_import_failures().items()):
            warnings.append("engine checker module %s failed to import: %s" % (mod, err))
        chosen = _applicable(ctx, detect, get_checkers(), meta, warnings)
        dedicated = [c for c in chosen if not getattr(c, "fallback", False)]
        if dedicated:
            for c in chosen:
                if getattr(c, "fallback", False):
                    meta[c.engine_id] = {"status": Status.SKIPPED.value, "error": None, "duration_s": 0.0,
                                         "reason": "superseded by dedicated checker(s): %s" % ", ".join(
                                             d.engine_id for d in dedicated)}
            chosen = dedicated
        if not chosen and not meta:
            return StageResult.skipped(NAME, "no engine checker applies to the detected engine(s)")
        data: Dict[str, Any] = {}
        findings: List[Finding] = []
        degraded = any(m.get("status") == Status.FAILED.value for m in meta.values())
        for c in chosen:
            t0 = time.monotonic()
            try:
                res: CheckerResult = c.run(ctx, detect)
            except Exception as exc:  # noqa: BLE001 - isolate
                log.warning("engine checker %s failed", c.engine_id, exc_info=True)
                meta[c.engine_id] = {"status": Status.FAILED.value, "reason": None,
                                     "error": "%s: %s" % (type(exc).__name__, exc),
                                     "duration_s": round(time.monotonic() - t0, 3)}
                warnings.append("checker %s failed: %s" % (c.engine_id, type(exc).__name__))
                degraded = True
                continue
            status = res.status if isinstance(res.status, Status) else Status(str(res.status))
            meta[c.engine_id] = {"status": status.value, "reason": res.reason, "error": None,
                                 "duration_s": round(time.monotonic() - t0, 3)}
            warnings.extend("%s: %s" % (c.engine_id, w) if not w.startswith(c.engine_id) else w for w in res.warnings)
            if status in (Status.PARTIAL, Status.FAILED):
                degraded = True
            if status != Status.SKIPPED:
                data[c.engine_id] = res.data
                findings.extend(res.findings)
        data["_checkers"] = dict(sorted(meta.items()))
        if not any(k != "_checkers" for k in data):
            if degraded:
                return StageResult.partial(NAME, data, findings, warnings, reason="every applicable checker failed")
            return StageResult.skipped(NAME, "applicable engine checkers had nothing to report")
        if degraded:
            return StageResult.partial(NAME, data, findings, warnings,
                                       reason="one or more engine checkers failed or reported partial results")
        return StageResult.ok(NAME, data, findings, warnings)
