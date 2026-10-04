from __future__ import annotations

import json

import pytest

from ipa_analyzer.analyzers.classify import ClassifyStage
from ipa_analyzer.classify import CATEGORY_LABELS, ClassifyInput, classify, load_rules
from ipa_analyzer.models import Status, Verdict
from ipa_analyzer.util.paths import resource_dir

RULES = load_rules()


def run(**kw):
    return classify(ClassifyInput(**kw), RULES)


def test_rules_file_is_complete():
    cats = set(RULES["categories"])
    assert set(RULES["genre_id_map"].values()) <= cats and set(RULES["ls_category_map"].values()) <= cats
    assert RULES["genre_id_map"]["6014"] == "game"
    assert set(RULES["genre_id_map"]) <= set(RULES["genre_names"]) and set(RULES["game_subgenre_ids"]) <= set(RULES["genre_names"])
    assert RULES["genre_names"]["6014"]["zh-Hans"] == "游戏"
    for sig in RULES["system_framework_signals"].values():
        assert set(sig) <= cats
    assert set(CATEGORY_LABELS) >= cats | {"unknown"}


def test_itunes_games_genre_id_is_decisive():
    r = run(genre_id="6014", genre_name="Games", subgenres=[{"genreId": 7012, "name": "Puzzle"}])
    assert r["category"] == "game" and r["confidence"] >= 0.9 and r["subcategory"] == "puzzle"
    assert any(e["ref"] == "iTunesMetadata.plist:genre" for e in r["evidence"])


def test_genre_given_as_localized_name_only_is_lower_confidence():
    r = run(genre_name="游戏")
    assert r["category"] == "game" and 0.8 <= r["confidence"] < 0.95
    r2 = run(genre_name="社交")
    assert r2["category"] == "social"


def test_non_game_genre_ids_map_and_subcategory():
    assert run(genre_id=6011)["category"] == "media" and run(genre_id="6011")["subcategory"] == "music"
    assert run(genre_id="6013")["category"] == "health_fitness" and run(genre_id="6015")["category"] == "finance"
    assert run(genre_id="999999")["category"] == "unknown"


def test_ls_category_and_agreement():
    r = run(ls_category="public.app-category.puzzle-games")
    assert r["category"] == "game" and r["confidence"] >= 0.9 and r["subcategory"] == "puzzle"
    both = run(genre_id="6014", ls_category="public.app-category.games")
    assert both["confidence"] >= run(genre_id="6014")["confidence"]
    assert run(ls_category="public.app-category.photography")["category"] == "media"


def test_unity_only_is_game_with_lower_confidence_and_competitor():
    r = run(engine_primary="unity", engine_confirmed=True, engine_confidence=0.95, engine_is_game=True)
    assert r["category"] == "game" and r["confidence"] < 0.8
    assert r["runner_up"] is not None and any("non-game" in e["detail"] for e in r["evidence"])


def test_unity_with_gamekit_is_more_confident():
    base = run(engine_primary="unity", engine_confirmed=True, engine_is_game=True)
    kit = run(engine_primary="unity", engine_confirmed=True, engine_is_game=True, system_frameworks=["GameKit", "GameController"])
    assert kit["confidence"] > base["confidence"]


def test_exclusive_engine_beats_unity_level_confidence():
    r = run(engine_primary="cocos", engine_confirmed=True, engine_is_game=True)
    assert r["category"] == "game" and r["confidence"] >= 0.75


def test_custom_engine_with_metal_and_physics_is_game_but_below_known_engine():
    fp = {"render": {"metal": {}}, "physics": [{"id": "box2d"}], "script_vms": [{"id": "lua"}]}
    custom = run(custom_verdict="yes", fingerprint=fp)
    known = run(engine_primary="cocos", engine_confirmed=True, engine_is_game=True, fingerprint=fp)
    assert custom["category"] == "game" and custom["confidence"] < known["confidence"]
    assert run(custom_verdict="suspected", fingerprint=fp)["confidence"] < custom["confidence"]


def test_native_media_app_with_ffmpeg_and_video_is_media():
    r = run(system_frameworks=["AVFoundation", "AVKit"], lib_ids=["ffmpegkit"], lib_categories={"media": 1},
            inventory_by_category=[{"category": "video", "percent": 62.0}, {"category": "image", "percent": 10.0}])
    assert r["category"] == "media" and r["confidence"] >= 0.6


def test_close_scores_lower_confidence_and_report_runner_up():
    a = run(system_frameworks=["HealthKit"], lib_categories={"social": 3})                       # health 0.5 vs social
    # build two nearly equal groups
    r = run(system_frameworks=["MapKit"], inventory_by_category=[{"category": "video", "percent": 40.0}])
    assert r["runner_up"] is not None
    gap = r["scores"][r["category"]] - r["runner_up"]["score"]
    assert gap < 0.15 or r["confidence"] >= r["scores"][r["category"]] * 0.75
    assert a["category"] in ("health_fitness", "social")


def test_noisy_or_independent_evidence_raises_score():
    one = run(system_frameworks=["HealthKit"])["scores"]["health_fitness"]
    two = run(system_frameworks=["HealthKit"], permission_keys=["NSHealthShareUsageDescription"])["scores"]["health_fitness"]
    assert two > one and two < 1.0


def test_ads_sdks_nudge_towards_game_only_slightly():
    r = run(lib_tags_ads=["admob", "applovin", "unity_ads"])
    assert r["category"] == "unknown" or r["scores"].get("game", 0) <= 0.2


def test_nothing_known_is_unknown_not_a_guess():
    r = run()
    assert r["category"] == "unknown" and r["confidence"] == 0.0 and r["subcategory"] is None


def test_no_rules_file_degrades_to_unknown():
    r = classify(ClassifyInput(genre_id="6014"), {})
    assert r["category"] == "unknown"


# ---- stage -----------------------------------------------------------------------------
STAGES = ("ingest", "inventory", "classify")


def test_stage_partial_when_upstream_missing(run_stages):
    ctx = run_stages({"x.txt": b"x"}, stages=STAGES)
    st = ctx.stage_results["classify"]
    assert st.status == Status.PARTIAL and "meta" in (st.reason or "")
    assert ctx.results["classify"]["category"] == "unknown"
    assert st.findings[0].id == "classify.category" and st.findings[0].verdict == Verdict.UNKNOWN


def test_stage_with_injected_results_games(run_stages):
    inject = {"meta": {"itunes": {"genre": "Games", "genre_id": 6014, "genres": ["Games", "Puzzle"],
                                   "subgenres": [{"genreId": 7012, "name": "Puzzle"}]},
                       "identity": {"extra": {"category": "public.app-category.games"}}, "permissions": []},
              "engine.detect": {"primary": {"id": "unity", "confidence": 0.9, "confirmed": True}, "candidates": [], "is_game_engine": True,
                                "custom": {"verdict": "no"}},
              "engine.fingerprint": {}, "libs": {"items": []}}
    ctx = run_stages({"x.txt": b"x"}, stages=STAGES, inject=inject)
    st = ClassifyStage().run(ctx)
    assert st.status == Status.OK
    d = st.data
    assert d["category"] == "game" and d["confidence"] >= 0.9 and d["subcategory"] == "puzzle"
    f = st.findings[0]
    assert f.verdict == Verdict.YES and f.params["category_zh"] == "游戏"
    json.dumps(st.data)                                                       # JSON-serialisable


def test_stage_reads_libs_items_and_inventory(run_stages):
    inject = {"meta": {}, "engine.detect": {}, "engine.fingerprint": {},
              "libs": {"items": [{"id": "ffmpegkit", "kind": "framework", "category": "media", "tags": []},
                                 {"id": "system.AVKit", "name": "AVKit", "kind": "system", "category": "system", "tags": []}]},
              "inventory": {"by_category": [{"category": "video", "percent": 70.0}]}}
    ctx = run_stages({"x.txt": b"x"}, stages=STAGES, inject=inject)
    st = ClassifyStage().run(ctx)
    assert st.data["category"] == "media" and st.status == Status.OK
