"""Explainable project-type scorer.

Signals are grouped (store metadata, engine, fingerprint, libraries, system frameworks, inventory, permissions);
inside a group contributions add up to a per-group cap, groups combine as a noisy-OR so independent evidence
raises a category's score without ever exceeding 1. Store metadata (iTunes genre / LSApplicationCategoryType)
is decisive; everything else is a weighted heuristic (``data/classify.json``, UNVERIFIED against ground truth).
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..util import paths as _paths

log = logging.getLogger(__name__)

CATEGORY_LABELS: Dict[str, Tuple[str, str]] = {
    "game": ("游戏", "Games"), "media": ("影音", "Media"), "lifestyle": ("生活", "Lifestyle"), "social": ("社交", "Social"),
    "utility": ("工具 / 效率", "Utilities / productivity"), "finance": ("金融", "Finance"), "education": ("教育", "Education"),
    "health_fitness": ("健康健身", "Health & fitness"), "shopping": ("购物", "Shopping"), "travel": ("出行", "Travel"),
    "news_reading": ("新闻 / 阅读", "News & reading"), "other": ("其他", "Other"), "unknown": ("未知", "Unknown")}
_SCRIPT_VM_IGNORE = frozenset({"jsc", "hermes", "mono", "il2cpp"})
_MIN_SCORE_DEFAULT = 0.2


@dataclass
class ClassifyInput:
    """Plain-data inputs (any may be empty / None when the upstream stage did not run)."""
    genre_id: Optional[str] = None
    genre_name: Optional[str] = None
    genres: List[Any] = field(default_factory=list)
    subgenres: List[Any] = field(default_factory=list)
    ls_category: Optional[str] = None
    permission_keys: List[str] = field(default_factory=list)
    engine_primary: Optional[str] = None
    engine_confirmed: bool = False
    engine_confidence: float = 0.0
    engine_is_game: bool = False
    engine_candidates: List[Dict[str, Any]] = field(default_factory=list)
    custom_verdict: Optional[str] = None
    fingerprint: Dict[str, Any] = field(default_factory=dict)
    lib_ids: List[str] = field(default_factory=list)
    lib_categories: Dict[str, int] = field(default_factory=dict)
    lib_tags_ads: List[str] = field(default_factory=list)
    system_frameworks: List[str] = field(default_factory=list)
    inventory_by_category: List[Dict[str, Any]] = field(default_factory=list)


def load_rules(data_dir: Optional[Path] = None) -> Dict[str, Any]:
    path = (Path(data_dir) if data_dir else _paths.resource_dir("data")) / "classify.json"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        if isinstance(doc, dict):
            return doc
    except (OSError, ValueError) as exc:
        log.warning("classify.json unreadable (%s): store-metadata and heuristic rules disabled", exc)
    return {}


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


class _Scores:
    def __init__(self) -> None:
        self.groups: Dict[str, Dict[str, float]] = {}
        self.evidence: List[Dict[str, str]] = []

    def add(self, group: str, cat: str, value: float, ev: Optional[Dict[str, str]] = None, *, cap: float = 1.0) -> None:
        g = self.groups.setdefault(group, {})
        before = g.get(cat, 0.0)
        g[cat] = min(cap, before + value)
        if ev is not None and g[cat] > before:
            self.evidence.append(ev)

    def best(self, group: str, cat: str, value: float, ev: Dict[str, str]) -> None:
        g = self.groups.setdefault(group, {})
        if value > g.get(cat, 0.0):
            g[cat] = value
            self.evidence.append(ev)

    def totals(self) -> Dict[str, float]:
        cats = {c for g in self.groups.values() for c in g}
        out: Dict[str, float] = {}
        for c in cats:
            miss = 1.0
            for g in self.groups.values():
                miss *= 1.0 - min(1.0, g.get(c, 0.0))
            out[c] = round(1.0 - miss, 4)
        return out


def _genre_lookup(rules: Dict[str, Any], inp: ClassifyInput) -> Tuple[Optional[str], Optional[str], bool]:
    """``(apple_genre_id, internal_category, by_id)`` from the iTunes genre fields."""
    gmap = rules.get("genre_id_map") or {}
    gid = str(inp.genre_id).strip() if inp.genre_id not in (None, "") else None
    if gid and gid in gmap:
        return gid, gmap[gid], True
    names = rules.get("genre_names") or {}
    wanted = (inp.genre_name or "").strip().lower()
    if wanted:
        for k, v in names.items():
            if k in gmap and wanted in {str(x).lower() for x in v.values()}:
                return k, gmap[k], False
    return None, None, False


def _game_subcategory(rules: Dict[str, Any], inp: ClassifyInput) -> Optional[str]:
    sub_ids = rules.get("game_subgenre_ids") or {}
    names = rules.get("genre_names") or {}
    for entry in list(inp.subgenres) + list(inp.genres):
        gid = None
        label = None
        if isinstance(entry, dict):
            gid = str(entry.get("genreId") or entry.get("genre_id") or "")
            label = entry.get("name")
        elif isinstance(entry, (str, int)):
            label = str(entry)
            gid = label if str(entry).isdigit() else None
        if gid and gid in sub_ids:
            return sub_ids[gid]
        if isinstance(label, str):
            for k, slug in sub_ids.items():
                if label.strip().lower() in {str(x).lower() for x in (names.get(k) or {}).values()}:
                    return slug
    return None


def classify(inp: ClassifyInput, rules: Dict[str, Any]) -> Dict[str, Any]:
    """Score ``inp`` and return ``{category, subcategory, confidence, scores, evidence, runner_up}``."""
    w = rules.get("weights") or {}
    sc = _Scores()
    subcategory: Optional[str] = None
    direct_cats: List[str] = []

    # 1. store metadata ---------------------------------------------------------------------
    gid, gcat, by_id = _genre_lookup(rules, inp)
    if gcat:
        sc.best("store", gcat, float(w.get("itunes_genre" if by_id else "itunes_genre_name_only", 0.9)),
                {"kind": "plist_key", "ref": "iTunesMetadata.plist:genre", "detail": "genre %s (%s) -> %s" % (
                    gid, ((rules.get("genre_names") or {}).get(gid) or {}).get("en", "?"), gcat)})
        direct_cats.append(gcat)
        if gcat != "game":
            en = ((rules.get("genre_names") or {}).get(gid) or {}).get("en")
            if en and _slug(en) != gcat:
                subcategory = _slug(en)
    ls = (inp.ls_category or "").strip().lower()
    ls_cat = None
    if ls:
        ls_cat = (rules.get("ls_category_map") or {}).get(ls)
        game_sub = None
        if ls_cat is None and ls.startswith("public.app-category.") and ls.endswith("-games"):
            ls_cat = "game"
            game_sub = (rules.get("ls_game_subcategories") or {}).get(ls[len("public.app-category."):])
        if ls_cat:
            sc.best("store_ls", ls_cat, float(w.get("ls_category", 0.9)),
                    {"kind": "plist_key", "ref": "Info.plist:LSApplicationCategoryType", "detail": "%s -> %s" % (ls, ls_cat)})
            direct_cats.append(ls_cat)
            if ls_cat == "game" and game_sub:
                subcategory = subcategory or game_sub
    if gcat and ls_cat and gcat == ls_cat:
        sc.add("store_agree", gcat, float(w.get("agreement_bonus", 0.03)))
    if "game" in direct_cats:
        subcategory = _game_subcategory(rules, inp) or subcategory

    # 2. engine -------------------------------------------------------------------------------
    exclusive = set(rules.get("exclusive_game_engines") or [])
    non_excl = set(rules.get("non_exclusive_engines") or [])
    engine_only_nonexclusive = False
    prim = inp.engine_primary
    cands = [c for c in inp.engine_candidates if isinstance(c, dict) and c.get("id")]
    best_game_engine: Optional[Tuple[str, float, bool]] = None
    for eid, conf, confirmed in ([(prim, inp.engine_confidence, inp.engine_confirmed)] if prim else []) + [
            (str(c["id"]), float(c.get("confidence") or 0.0), bool(c.get("confirmed"))) for c in cands]:
        if eid in exclusive:
            val = float(w.get("engine_exclusive_game", 0.75))
        elif eid in non_excl:
            val = float(w.get("engine_game", 0.6)) if eid == "unity" else 0.0
        elif eid == prim and inp.engine_is_game:
            val = float(w.get("engine_game", 0.6))
        else:
            val = 0.0
        if val <= 0:
            continue
        val *= 1.0 if confirmed else max(0.5, min(1.0, conf))
        if best_game_engine is None or val > best_game_engine[1]:
            best_game_engine = (eid, val, eid in non_excl)
    if best_game_engine:
        sc.best("engine", "game", best_game_engine[1], {"kind": "heuristic", "ref": "engine.detect",
                "detail": "game engine %s%s" % (best_game_engine[0], " (also used for non-game apps)" if best_game_engine[2] else "")})
        engine_only_nonexclusive = best_game_engine[2]
    cv = inp.custom_verdict
    if cv in ("yes", "suspected"):
        sc.best("engine_custom", "game", float(w.get("engine_custom_yes" if cv == "yes" else "engine_custom_suspected", 0.3)),
                {"kind": "heuristic", "ref": "engine.detect:custom", "detail": "custom native engine (%s) with game signals" % cv})

    # 3. fingerprint --------------------------------------------------------------------------
    fp = inp.fingerprint or {}
    cap = float(w.get("fingerprint_cap", 0.3))
    if fp.get("render"):
        sc.add("fingerprint", "game", float(w.get("fingerprint_render", 0.1)), {"kind": "heuristic", "ref": "engine.fingerprint",
               "detail": "rendering API: %s" % ", ".join(sorted(fp["render"]))}, cap=cap)
    pha = [h.get("id") for dim in ("physics", "animation", "audio") for h in fp.get(dim) or [] if isinstance(h, dict)]
    if pha:
        sc.add("fingerprint", "game", float(w.get("fingerprint_physics_anim_audio", 0.15)), {"kind": "heuristic",
               "ref": "engine.fingerprint", "detail": "physics/animation/audio middleware: %s" % ", ".join(sorted(map(str, pha))[:6])}, cap=cap)
    vms = [h.get("id") for h in fp.get("script_vms") or [] if isinstance(h, dict) and h.get("id") not in _SCRIPT_VM_IGNORE]
    if vms:
        sc.add("fingerprint", "game", float(w.get("fingerprint_script_vm", 0.05)), {"kind": "heuristic", "ref": "engine.fingerprint",
               "detail": "embedded script VM: %s" % ", ".join(sorted(map(str, vms))[:4])}, cap=cap)

    # 4. libraries ----------------------------------------------------------------------------
    id_sig = rules.get("lib_id_signals") or {}
    cat_sig = rules.get("lib_category_signals") or {}
    for lid in sorted(set(inp.lib_ids)):
        for cat, val in (id_sig.get(lid) or {}).items():
            sc.add("libs", cat, float(val), {"kind": "heuristic", "ref": "libs", "detail": "library %s suggests %s" % (lid, cat)}, cap=0.4)
    for lcat, n in sorted(inp.lib_categories.items()):
        for cat, val in (cat_sig.get(lcat) or {}).items():
            sc.add("libs", cat, float(val), {"kind": "heuristic", "ref": "libs", "detail": "%d %s librar%s" % (n, lcat, "y" if n == 1 else "ies")}, cap=0.4)
    if inp.lib_tags_ads:
        sc.add("libs_ads", "game", float(w.get("lib_ads_game", 0.1)) * len(inp.lib_tags_ads),
               {"kind": "heuristic", "ref": "libs", "detail": "%d ad SDK(s) (common in games)" % len(inp.lib_tags_ads)},
               cap=float(w.get("lib_ads_cap", 0.2)))

    # 5. system frameworks / permissions ----------------------------------------------------
    sys_sig = rules.get("system_framework_signals") or {}
    scap = float(w.get("system_signal_cap", 0.45))
    for fw in sorted(set(inp.system_frameworks)):
        for cat, val in (sys_sig.get(fw) or {}).items():
            sc.add("system", cat, float(val), {"kind": "macho", "ref": "libs", "detail": "links %s" % fw}, cap=scap)
    pcap = float(w.get("permission_cap", 0.25))
    psig = rules.get("permission_signals") or {}
    for key in sorted(set(inp.permission_keys)):
        for cat, val in (psig.get(key) or {}).items():
            sc.add("permission", cat, float(val), {"kind": "plist_key", "ref": "Info.plist:" + key, "detail": "permission %s" % key}, cap=pcap)

    # 6. inventory ------------------------------------------------------------------------------
    inv = rules.get("inventory_signals") or {}
    shares = {str(r.get("category")): float(r.get("percent") or 0.0) / 100.0 for r in inp.inventory_by_category if isinstance(r, dict)}
    icap = float(w.get("inventory_cap", 0.4))
    if shares.get("video", 0.0) >= float(inv.get("video_share_media", 0.3)):
        sc.add("inventory", "media", float(inv.get("video_share_media_weight", 0.35)), {"kind": "heuristic", "ref": "inventory",
               "detail": "video files are %.0f%% of the package" % (shares["video"] * 100)}, cap=icap)
    if shares.get("audio", 0.0) >= float(inv.get("audio_share_media", 0.3)):
        sc.add("inventory", "media", float(inv.get("audio_share_media_weight", 0.2)), {"kind": "heuristic", "ref": "inventory",
               "detail": "audio files are %.0f%% of the package" % (shares["audio"] * 100)}, cap=icap)
    gshare = sum(shares.get(c, 0.0) for c in inv.get("game_asset_categories") or [])
    if gshare >= float(inv.get("game_asset_share", 0.4)):
        sc.add("inventory", "game", float(inv.get("game_asset_weight", 0.2)), {"kind": "heuristic", "ref": "inventory",
               "detail": "3D / shader / engine-data / bundle files are %.0f%% of the package" % (gshare * 100)}, cap=icap)

    # 7. decision -------------------------------------------------------------------------------
    totals = sc.totals()
    ranked = sorted(totals.items(), key=lambda kv: (-kv[1], kv[0]))
    min_score = float(w.get("min_score", _MIN_SCORE_DEFAULT))
    if not ranked or ranked[0][1] < min_score:
        return {"category": "unknown", "subcategory": None, "confidence": 0.0, "scores": {k: round(v, 3) for k, v in ranked},
                "evidence": sc.evidence, "runner_up": ({"category": ranked[0][0], "score": round(ranked[0][1], 3)} if ranked else None)}
    top_cat, top = ranked[0]
    second = ranked[1] if len(ranked) > 1 else None
    conf = min(float(w.get("max_confidence", 0.98)), top)
    runner = {"category": second[0], "score": round(second[1], 3)} if second else None
    if second and top - second[1] < float(w.get("close_gap", 0.15)):
        conf *= float(w.get("close_gap_penalty", 0.75))
    elif runner is None and engine_only_nonexclusive and top_cat == "game" and not direct_cats:
        runner = {"category": "other", "score": float(w.get("non_exclusive_engine_runner_up", 0.2))}
    return {"category": top_cat, "subcategory": subcategory if top_cat in ("game",) or subcategory else None,
            "confidence": round(conf, 3), "scores": {k: round(v, 3) for k, v in ranked}, "evidence": sc.evidence,
            "runner_up": runner}
