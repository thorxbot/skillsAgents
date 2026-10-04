"""Stage ``classify`` (WP4): project type (game / media / lifestyle / ...) from store metadata, engine, fingerprint,
libraries, system frameworks, permissions and package composition. No hard dependency: missing upstream data only
lowers the stage to ``partial``."""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from ..classify import CATEGORY_LABELS, ClassifyInput, classify, load_rules
from ..context import AnalysisContext
from ..models import Evidence, Finding, StageResult, Verdict
from ..registry import register

log = logging.getLogger(__name__)

NAME = "classify"
_UPSTREAM = ("meta", "engine.detect", "engine.fingerprint", "libs")


def _gather(ctx: AnalysisContext) -> ClassifyInput:
    r = ctx.results
    meta = r.get("meta") or {}
    itunes = meta.get("itunes") if isinstance(meta.get("itunes"), dict) else {}
    ident = meta.get("identity") if isinstance(meta.get("identity"), dict) else {}
    extra = ident.get("extra") if isinstance(ident.get("extra"), dict) else {}
    inp = ClassifyInput(
        genre_id=str(itunes["genre_id"]) if itunes.get("genre_id") not in (None, "") else None,
        genre_name=itunes.get("genre") if isinstance(itunes.get("genre"), str) else None,
        genres=list(itunes.get("genres") or []) if isinstance(itunes.get("genres"), list) else [],
        subgenres=list(itunes.get("subgenres") or []) if isinstance(itunes.get("subgenres"), list) else [],
        ls_category=ident.get("category") or extra.get("category") or meta.get("LSApplicationCategoryType"),
        permission_keys=[p.get("key") for p in meta.get("permissions") or [] if isinstance(p, dict) and p.get("key")])
    det = r.get("engine.detect") or {}
    prim = det.get("primary") if isinstance(det.get("primary"), dict) else None
    if prim:
        inp.engine_primary = prim.get("id")
        inp.engine_confirmed = bool(prim.get("confirmed"))
        inp.engine_confidence = float(prim.get("confidence") or 0.0)
    inp.engine_is_game = bool(det.get("is_game_engine"))
    inp.engine_candidates = [c for c in det.get("candidates") or [] if isinstance(c, dict)]
    custom = det.get("custom") if isinstance(det.get("custom"), dict) else {}
    inp.custom_verdict = custom.get("verdict")
    inp.fingerprint = r.get("engine.fingerprint") or {}
    libs = r.get("libs") or {}
    items = [i for i in libs.get("items") or [] if isinstance(i, dict)]
    inp.lib_ids = [i["id"] for i in items if i.get("kind") != "system" and i.get("id")]
    cats: Dict[str, int] = {}
    for i in items:
        if i.get("kind") != "system":
            cats[i.get("category", "other")] = cats.get(i.get("category", "other"), 0) + 1
    inp.lib_categories = cats
    inp.lib_tags_ads = [i["id"] for i in items if "ads" in (i.get("tags") or []) and i.get("kind") != "system"]
    inp.system_frameworks = [i["name"] for i in items if i.get("kind") == "system" and i.get("name")]
    inp.inventory_by_category = [c for c in (r.get("inventory") or {}).get("by_category") or [] if isinstance(c, dict)]
    return inp


@register(name='classify', after=('meta', 'engine.detect', 'engine.fingerprint', 'libs'))
class ClassifyStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        rules = load_rules()
        warnings: List[str] = []
        if not rules:
            warnings.append("classify.json unavailable: store-metadata and heuristic rules disabled")
        missing = [n for n in _UPSTREAM if n not in ctx.results]
        res = classify(_gather(ctx), rules)
        cat = res["category"]
        zh, en = CATEGORY_LABELS.get(cat, CATEGORY_LABELS["unknown"])
        conf = float(res["confidence"])
        if cat == "unknown":
            verdict = Verdict.UNKNOWN
        elif conf >= 0.6:
            verdict = Verdict.YES
        else:
            verdict = Verdict.SUSPECTED
        runner = res.get("runner_up")
        params = {"category": cat, "category_zh": zh, "category_en": en, "subcategory": res.get("subcategory") or "-",
                  "confidence": conf, "runner_up": ("%s (%.2f)" % (runner["category"], runner["score"])) if runner else "-",
                  "missing": ", ".join(missing) or "-"}
        text = "Project type: %s%s (confidence %.2f)." % (en, " / %s" % res["subcategory"] if res.get("subcategory") else "", conf)
        if runner:
            text += " Runner-up: %s." % params["runner_up"]
        if missing:
            text += " Missing upstream data: %s." % params["missing"]
        finding = Finding("classify.category", verdict, conf if cat != "unknown" else 0.2, "Project type", text, params,
                          [Evidence(e["kind"], e["ref"], e["detail"]) for e in res["evidence"][:12]], "", tags=["classify"])
        data = {"category": cat, "subcategory": res.get("subcategory"), "confidence": conf, "scores": res["scores"],
                "evidence": res["evidence"][:20], "runner_up": runner}
        if missing:
            return StageResult.partial(NAME, data, [finding], warnings, reason="missing upstream data: %s" % ", ".join(missing))
        return StageResult.ok(NAME, data, [finding], warnings)
