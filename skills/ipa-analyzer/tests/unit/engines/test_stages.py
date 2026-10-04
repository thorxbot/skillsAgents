from __future__ import annotations

import json
from pathlib import Path

import pytest

from fixtures.engine_builder import (SynthApp, custom_engine_app, detect, native_map_app, pak_with_zlib_blocks,
                                     random_blob, run_stages, synth_for_engine, write_app)
from ipa_analyzer import pipeline
from ipa_analyzer.analyzers.engine_detect import EngineDetectStage
from ipa_analyzer.analyzers.engine_fingerprint import EngineFingerprintStage
from ipa_analyzer.config import Config
from ipa_analyzer.context import AnalysisContext
from ipa_analyzer.models import Status
from ipa_analyzer.util.paths import resource_dir

ENGINE_DIR = Path(resource_dir("data")) / "engines"
ENGINES = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted(ENGINE_DIR.glob("*.json"))}


def confirmed_ids(ctx):
    return [c["id"] for c in detect(ctx)["candidates"] if c["confirmed"]]


# --- registration --------------------------------------------------------------------------------------------------------
def test_stage_registration_is_unchanged():
    reg = pipeline.ensure_analyzers_loaded()
    fp, det = reg.get("engine.fingerprint"), reg.get("engine.detect")
    assert fp.requires == ("inventory",) and fp.after == ("macho", "meta") and not fp.always_run
    assert det.requires == ("inventory",) and det.after == ("macho", "meta", "engine.fingerprint")


# --- every built-in engine has a positive fixture -----------------------------------------------------------------------------
@pytest.mark.parametrize("engine_id", sorted(ENGINES))
def test_positive_fixture_for_each_engine(tmp_path, engine_id):
    e = ENGINES[engine_id]
    app = synth_for_engine(e)
    ctx = run_stages(tmp_path, app)
    assert ctx.stage_status("engine.detect") in (Status.OK, Status.PARTIAL)
    d = detect(ctx)
    cand = {c["id"]: c for c in d["candidates"]}
    assert engine_id in cand and cand[engine_id]["confirmed"], (engine_id, cand.get(engine_id), d["primary"] and d["primary"]["id"])
    kind = e["kind"]
    if kind in ("game_engine", "cross_platform_ui", "web_hybrid") and e.get("role") != "family":
        assert d["primary"]["id"] == engine_id, [(c["id"], c["confidence"]) for c in d["candidates"]]
        assert d["primary"]["confidence"] >= 0.7 and d["primary"]["evidence"]
    assert d["is_game_engine"] == (d["primary"] is not None and d["primary"]["kind"] == "game_engine")


# --- Cocos variants -----------------------------------------------------------------------------------------------------------
COCOS = {"cocos2dx_cpp": "cocos2dx_cpp", "cocos2dx_lua": "cocos2dx_lua", "cocos2dx_js": "cocos2dx_js",
         "cocos_creator_2x": "cocos_creator_2x", "cocos_creator_3x": "cocos_creator_3x", "cocos2d_iphone": "cocos2d_iphone"}


@pytest.mark.parametrize("variant", sorted(COCOS))
def test_cocos_variants_are_told_apart(tmp_path, variant):
    ctx = run_stages(tmp_path, synth_for_engine(ENGINES[variant]))
    d = detect(ctx)
    assert d["primary"]["id"] == variant and d["primary"]["family"] == "cocos"
    others = [c for c in d["candidates"] if c["family"] == "cocos" and c["id"] != variant]
    assert all(not c["confirmed"] for c in others), others


def test_cocos_lua_with_cpp_core_symbols_is_lua_not_cpp(tmp_path):
    app = synth_for_engine(ENGINES["cocos2dx_lua"])
    app.symbols += ["__ZN7cocos2d8Director11getInstanceEv", "__ZN7cocos2d4Node4initEv"]
    app.strings.append("cocos2d-x 3.17.2")
    d = detect(run_stages(tmp_path, app))
    assert d["primary"]["id"] == "cocos2dx_lua"
    cpp = next(c for c in d["candidates"] if c["id"] == "cocos2dx_cpp")
    assert cpp["extra"].get("suppressed_by") == "cocos2dx_lua" and cpp["confirmed"] is False
    assert d["primary"]["extra"].get("version_hint") == "3.17.2"


def test_ccz_only_means_cocos_family_with_undetermined_variant(tmp_path):
    app = SynthApp(files={"HD/sprites/%d.ccz" % i: b"CCZp\x00\x01\x00\x00" + bytes(40) for i in range(60)})
    app.files["Audio/a.caf"] = b"caff" + bytes(20)
    d = detect(run_stages(tmp_path, app))
    assert d["primary"]["id"] == "cocos_family" and d["primary"]["family"] == "cocos"
    assert all(not c["confirmed"] for c in d["candidates"] if c["id"] != "cocos_family")
    assert d["custom"]["verdict"] in ("no", "unknown")


def test_creator_3x_layout_of_the_real_sample_family(tmp_path):
    files = {p: b"x" * 30 for p in ("application.js", "src/system.bundle.js", "src/cocos-js/cc.js", "src/chunks/bundle.js",
                                    "src/import-map.json", "src/settings.json", "jsb-adapter/engine-adapter.js",
                                    "jsb-adapter/web-adapter.js", "assets/main/index.js", "assets/resources/index.js",
                                    "assets/internal/index.js")}
    d = detect(run_stages(tmp_path, SynthApp(files=files)))
    assert d["primary"]["id"] == "cocos_creator_3x" and d["primary"]["confidence"] >= 0.95
    assert "jsb-adapter" not in [c["id"] for c in d["candidates"] if c["confirmed"]]


# --- in-house engine -----------------------------------------------------------------------------------------------------------
def test_custom_engine_fixture_is_flagged_and_profiled(tmp_path):
    ctx = run_stages(tmp_path, custom_engine_app())
    d = detect(ctx)
    assert d["primary"] is None and confirmed_ids(ctx) == [], [(c["id"], c["confidence"]) for c in d["candidates"]]
    c = d["custom"]
    assert c["verdict"] in ("yes", "suspected") and 0.5 <= c["confidence"] <= 0.8
    cond = c["conditions"]
    assert cond["render_api"] and cond["script_vm"] and cond["custom_container"] and cond["physics_lib"]
    assert cond["known_engine_confirmed"] is False and c["profile_ref"] == "engine.fingerprint"
    assert [s["key"] for s in c["next_steps"]][:1] == ["engines.next.container"]
    assert any(s["key"] == "engines.next.script_vm" and s["params"]["vm"] == "lua" for s in c["next_steps"])
    assert all(s["text"] for s in c["next_steps"]) and c["evidence"]
    fp = ctx.results["engine.fingerprint"]
    assert "metal" in fp["render"] and [h["id"] for h in fp["script_vms"]][:1] == ["lua"]
    assert any(h["id"] == "box2d" for h in fp["physics"])
    conts = {h["id"].rsplit("/", 1)[-1]: h["extra"] for h in fp["containers"]}
    assert conts["data.pak"]["verdict"] == "custom_format" and conts["data.pak"]["compression"] == "zlib"
    assert conts["blob.dat"]["verdict"] == "encrypted_suspected"
    assert fp["summary_text"].startswith(("Native C++ code", "Thin UIKit shell")) and "Metal" in fp["summary_text"] and "Lua" in fp["summary_text"]
    assert "Box2D" in fp["summary_text"] and "custom container" in fp["summary_text"]
    f = {x.id: x for x in ctx.findings}
    assert f["engine.custom"].verdict.value in ("yes", "suspected") and f["engine.container.unknown"].verdict.value == "suspected"
    assert f["engine.fingerprint"].verdict.value == "yes" and f["engine.primary"].verdict.value == "unknown"


def test_custom_verdict_needs_more_than_render_and_one_signal(tmp_path):
    app = native_map_app()
    d = detect(run_stages(tmp_path, app))
    assert d["custom"]["verdict"] == "no" and d["custom"]["conditions"]["render_api"] is True
    app2 = SynthApp()
    app2.dylibs = ["/System/Library/Frameworks/Metal.framework/Metal"]
    app2.imports = ["_MTLCreateSystemDefaultDevice"]
    app2.symbols = ["_luaL_newstate", "_luaL_openlibs", "_lua_pcallk"]
    d2 = detect(run_stages(tmp_path / "b", app2))
    assert d2["custom"]["verdict"] == "no"            # Metal + Lua but no game signal / second structural trait


# --- counter-examples ---------------------------------------------------------------------------------------------------------
def test_native_map_app_is_neither_custom_nor_a_game_engine(tmp_path):
    ctx = run_stages(tmp_path, native_map_app())
    d = detect(ctx)
    assert d["custom"]["verdict"] == "no" and d["is_game_engine"] is False
    assert d["primary"] is None or d["primary"]["kind"] == "native"
    assert not {"unity", "unreal", "godot"} & set(confirmed_ids(ctx))


def test_unity_named_image_is_not_unity(tmp_path):
    app = SynthApp(files={"unity.png": b"\x89PNG\r\n\x1a\n" + bytes(50), "Unity.jpg": b"\xff\xd8\xff" + bytes(20),
                          "UnityFramework.png": b"\x89PNG\r\n\x1a\n" + bytes(10)})
    ctx = run_stages(tmp_path, app)
    assert "unity" not in confirmed_ids(ctx)
    assert all(c["confidence"] < 0.5 for c in detect(ctx)["candidates"] if c["id"] == "unity")


def test_flutter_word_without_framework_is_not_flutter(tmp_path):
    app = SynthApp(strings=["Flutter", "Welcome to Flutter!", "flutter_assets"], files={"flutter.png": b"\x89PNG\r\n\x1a\n" + bytes(9)})
    ctx = run_stages(tmp_path, app)
    assert "flutter" not in confirmed_ids(ctx)


def test_cocos_plist_resources_in_a_native_app_do_not_make_cocos(tmp_path):
    app = native_map_app()
    app.files.update({"Particles/fire.plist": b"bplist00" + bytes(40), "sprites.plist": b"<?xml version='1.0'?><plist/>",
                      "sprites.png": b"\x89PNG\r\n\x1a\n" + bytes(30)})
    ctx = run_stages(tmp_path, app)
    assert not [c for c in detect(ctx)["candidates"] if c["family"] == "cocos" and c["confirmed"]]


# --- mixed ----------------------------------------------------------------------------------------------------------------------
def test_unity_embedded_in_cordova_shell_is_a_wrapper(tmp_path):
    app = synth_for_engine(ENGINES["cordova_capacitor"]).merge(synth_for_engine(ENGINES["unity"]))
    ctx = run_stages(tmp_path, app)
    d = detect(ctx)
    w = d["wrapper"]
    assert w and w["host"]["id"] == "cordova_capacitor" and [e["id"] for e in w["embedded"]] == ["unity"]
    assert {"unity", "cordova_capacitor"} <= set(confirmed_ids(ctx))
    f = {x.id: x for x in ctx.findings}
    assert f["engine.wrapper"].verdict.value == "yes"


def test_cordova_plus_native_shell_without_other_engine_has_no_wrapper(tmp_path):
    d = detect(run_stages(tmp_path, synth_for_engine(ENGINES["cordova_capacitor"])))
    assert d["primary"]["id"] == "cordova_capacitor" and d["wrapper"] is None


def test_modified_cocos_code_present_but_standard_layout_missing(tmp_path):
    app = SynthApp(symbols=["__ZN7cocos2d9LuaEngine11getInstanceEv", "__ZN7cocos2d8LuaStack4initEv"],
                   files={"data/blob.pak": random_blob(30_000, 3), "readme.txt": b"hello"})
    ctx = run_stages(tmp_path, app)
    c = detect(ctx)["custom"]
    assert c["verdict"] == "suspected" and c.get("kind") == "modified_open_source"
    assert c["open_source_base"] == ["cocos2d-x"] and c["deviations"] and "standard layout" in c["deviations"][0]
    assert 0.3 <= c["confidence"] <= 0.6 and c["next_steps"]
    assert detect(ctx)["primary"]["id"] == "cocos2dx_lua"          # still reported as the engine it resembles


def test_standard_cocos_cpp_is_not_called_modified(tmp_path):
    app = SynthApp(symbols=["__ZN7cocos2d8Director11getInstanceEv"], strings=["cocos2d-x 3.17.2"])
    c = detect(run_stages(tmp_path, app))["custom"]
    assert c["verdict"] == "no" and c.get("kind") is None


# --- FairPlay-encrypted binaries ------------------------------------------------------------------------------------------------
def test_encrypted_binary_ignores_ciphertext_strings_and_reports_limits(tmp_path):
    app = SynthApp(strings=["UnityAppController", "il2cpp_init", "luaL_newstate", "cocos2d-x 3.17.2", "Godot Engine v4.2.1", "bad argument #%d to '%s' (%s)"],
                   objc_classes=["UnityAppController", "RCTBridge"], dylibs=["/System/Library/Frameworks/Metal.framework/Metal"],
                   imports=["_MTLCreateSystemDefaultDevice"], files={"res/a.pak": pak_with_zlib_blocks()})
    ctx = run_stages(tmp_path, app, encrypted=True)
    assert ctx.stage_status("engine.detect") == Status.PARTIAL and ctx.stage_status("engine.fingerprint") == Status.PARTIAL
    d = detect(ctx)
    assert confirmed_ids(ctx) == [] and d["primary"] is None, [(c["id"], c["confidence"]) for c in d["candidates"]]
    assert not [c for c in d["candidates"] if c["id"] in ("unity", "godot", "react_native", "cocos2dx_cpp")]
    vis = d["extra"]["visibility"]
    assert vis["limited"] is True and vis["main_encrypted"] is True and vis["strings_available"] is False
    fp = ctx.results["engine.fingerprint"]
    assert fp["script_vms"] == [] and "metal" in fp["render"]                      # the dylib list is not encrypted
    assert "binary FairPlay-encrypted" in fp["summary_text"]
    assert any("encrypted" in w for w in ctx.warnings)
    f = {x.id: x for x in ctx.findings}
    assert "decrypted IPA" in f["engine.primary"].remediation and "decrypted IPA" in f["engine.fingerprint"].remediation
    assert d["custom"]["verdict"] in ("unknown", "no")
    assert any(s["key"] == "engines.next.decrypted_ipa" for s in d["custom"]["next_steps"]) or d["custom"]["verdict"] == "no"


def test_same_app_unencrypted_does_detect_from_strings(tmp_path):
    app = SynthApp(strings=["UnityAppController", "2021.3.16f1"], objc_classes=["UnityAppController"], symbols=["_il2cpp_init"])
    ctx = run_stages(tmp_path, app)
    d = detect(ctx)
    assert d["primary"]["id"] == "unity" and d["primary"]["extra"]["version_hint"] == "2021.3.16f1"
    assert ctx.stage_status("engine.detect") == Status.OK and d["extra"]["visibility"]["limited"] is False


def test_encrypted_file_level_evidence_still_identifies_the_engine(tmp_path):
    app = synth_for_engine(ENGINES["cocos_creator_3x"])
    ctx = run_stages(tmp_path, app, encrypted=True)
    d = detect(ctx)
    assert d["primary"]["id"] == "cocos_creator_3x" and ctx.stage_status("engine.detect") == Status.PARTIAL
    assert "decrypted IPA" in {x.id: x for x in ctx.findings}["engine.primary"].remediation


# --- upstream gaps ----------------------------------------------------------------------------------------------------------------
def test_missing_inventory_skips_both_stages(tmp_path):
    ctx = AnalysisContext(Config(output_dir=tmp_path / "out"), tmp_path / "x.ipa")
    ipa = write_app(tmp_path / "x.ipa", SynthApp())
    from ipa_analyzer.ingest import open_source
    ctx = AnalysisContext(Config(output_dir=tmp_path / "out"), ipa, source=open_source(ipa), app_root="Payload/Test.app/")
    ctx.bind_input("ab" * 32, "x")
    for stage in (EngineFingerprintStage(), EngineDetectStage()):
        r = stage.run(ctx)
        assert r.status == Status.SKIPPED and r.reason
    ctx.close()


def test_missing_macho_stage_is_partial_but_still_works(tmp_path):
    app = SynthApp(strings=["UnityAppController"], symbols=["_il2cpp_init"], objc_classes=["UnityAppController"])
    ctx = run_stages(tmp_path, app, stages=("engine.fingerprint", "engine.detect"))
    assert ctx.stage_status("macho") != Status.OK
    assert ctx.stage_status("engine.detect") == Status.PARTIAL and "macho unavailable" in ctx.stage_results["engine.detect"].reason
    assert detect(ctx)["primary"]["id"] == "unity"


def test_detect_runs_without_the_fingerprint_stage(tmp_path):
    ctx = run_stages(tmp_path, custom_engine_app(), stages=("macho", "engine.detect"))
    assert ctx.stage_status("engine.fingerprint") is None or ctx.stage_status("engine.fingerprint") == Status.SKIPPED
    assert detect(ctx)["custom"]["verdict"] in ("yes", "suspected") and detect(ctx)["extra"]["profile_source"] == "computed"


# --- user signatures ----------------------------------------------------------------------------------------------------------------
def test_user_engine_json_is_picked_up_by_the_stage(tmp_path):
    user = tmp_path / "userengines"
    user.mkdir()
    (user / "mine.json").write_text(json.dumps({
        "id": "my_inhouse", "name": "My In-house Engine", "kind": "game_engine", "confirm_threshold": 0.7,
        "signals": [{"type": "file", "pattern": "/data/zz.pkg", "weight": 0.9, "strong": True, "note": "user verified"}],
        "sources": ["analyst note"]}), encoding="utf-8")
    app = SynthApp(files={"data/zz.pkg": b"ZZPK" + bytes(60)})
    ctx = run_stages(tmp_path, app, engines_user_dir=user)
    d = detect(ctx)
    assert d["primary"]["id"] == "my_inhouse" and d["extra"]["user_signatures"] == ["my_inhouse"]
    ctx2 = run_stages(tmp_path / "again", app)
    assert detect(ctx2)["primary"] is None


def test_broken_user_json_only_warns(tmp_path):
    user = tmp_path / "ue"
    user.mkdir()
    (user / "bad.json").write_text("[1,", encoding="utf-8")
    ctx = run_stages(tmp_path, SynthApp(), engines_user_dir=user)
    assert ctx.stage_status("engine.detect") in (Status.OK, Status.PARTIAL)
    assert any("bad.json" in w for w in ctx.warnings)


# --- contract / output hygiene --------------------------------------------------------------------------------------------------------
def test_outputs_are_json_serialisable_and_deterministic(tmp_path):
    a = run_stages(tmp_path / "a", custom_engine_app())
    b = run_stages(tmp_path / "b", custom_engine_app())
    for key in ("engine.fingerprint", "engine.detect"):
        assert json.dumps(a.results[key], sort_keys=True) == json.dumps(b.results[key], sort_keys=True)
    d = detect(a)
    assert set(d) >= {"primary", "candidates", "wrapper", "custom", "languages", "is_game_engine", "extra"}
    assert set(d["custom"]) >= {"verdict", "confidence", "evidence", "profile_ref", "conditions", "next_steps", "deviations", "open_source_base"}
    fp = a.results["engine.fingerprint"]
    assert set(fp) >= {"render", "shader_formats", "script_vms", "physics", "audio", "animation", "network", "asset_formats", "containers", "host", "summary_text"}
    assert set(fp["host"]) >= {"thin_uikit_shell", "cpp_ratio", "objc_swift_ratio", "main_loop_hints"}


def test_finding_ids_have_zh_and_en_text():
    base = Path(resource_dir("data")) / "i18n"
    ids = ["engine.primary", "engine.language", "engine.custom", "engine.wrapper", "engine.fingerprint", "engine.container.unknown"]
    for lang in ("zh", "en"):
        tab = json.loads((base / lang / "engines.json").read_text(encoding="utf-8"))
        for i in ids:
            assert tab[i]["title"] and tab[i].get("summary", "x")
        for k in tab:
            assert k in ids or k.startswith("engines.")
    zh = json.loads((base / "zh" / "engines.json").read_text(encoding="utf-8"))
    en = json.loads((base / "en" / "engines.json").read_text(encoding="utf-8"))
    assert set(zh) == set(en)


def test_next_step_keys_are_localised():
    base = Path(resource_dir("data")) / "i18n"
    zh = json.loads((base / "zh" / "engines.json").read_text(encoding="utf-8"))
    ctx_keys = {"engines.next.container", "engines.next.header_cluster", "engines.next.script_vm", "engines.next.python_opcodes",
                "engines.next.shader", "engines.next.decrypted_ipa", "engines.next.record_signature"}
    assert ctx_keys <= set(zh)


def test_full_pipeline_report_validates_against_the_schema(tmp_path, check_report):
    ipa = write_app(tmp_path / "t.ipa", custom_engine_app())
    ctx = AnalysisContext(Config(output_dir=tmp_path / "out", formats=("json", "md"),
                                 stages=("macho", "engine.fingerprint", "engine.detect")), ipa)
    pipeline.run(ctx)
    report = json.loads((ctx.out_dir / "report.json").read_text(encoding="utf-8"))
    assert check_report(report) == []
    ed = report["engine_details"]
    assert ed["detect"]["custom"]["verdict"] in ("yes", "suspected") and ed["fingerprint"]["summary_text"]
    md = (ctx.out_dir / "report.md").read_text(encoding="utf-8")
    assert "疑似" in md or "自研" in md
    ctx.close()
