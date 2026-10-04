"""Engine layer end to end (DoD 5): in-house engine, Cocos family, Egret / Laya, Flutter, native, media.

The two cases that must stay distinguishable (SeaWorld correction, docs/05):
  * ``custom_engine``          - no known engine + capability profile  -> ``engine.custom`` yes
  * ``cocos_creator3_wrapped`` - known engine (Cocos Creator 3.x) whose resources carry a custom wrapper header
                                 -> ``engine.custom`` no, wrapper deviation reported by the Cocos checker
"""
from __future__ import annotations

import pytest

KNOWN_ENGINE_IDS = None            # filled lazily from data/engines (the ids a custom engine must never be mistaken for)


def confirmed(r):
    return [c["id"] for c in r.details["detect"]["candidates"] if c["confirmed"]]


# ------------------------------------------------------------------------------------------------- custom engine
def test_custom_engine_is_custom_and_not_any_known_engine(runs):
    r = runs.cli("custom_engine")
    d = r.details["detect"]
    assert d["primary"] is None and d["is_game_engine"] is False
    assert not [c for c in d["candidates"] if c["confirmed"] and c["kind"] == "game_engine"]
    assert not [c for c in d["candidates"] if c["confirmed"] and c["id"].startswith(("cocos", "unity", "unreal", "godot"))]
    assert r.verdict("engine.custom") == "yes" and r.finding("engine.custom")["confidence"] >= 0.7
    assert r.verdict("engine.primary") == "unknown"
    custom = d["custom"]
    assert custom["verdict"] == "yes" and custom["kind"] == "in_house"
    cond = custom["conditions"]
    assert cond["render_api"] and cond["script_vm"] and cond["physics_lib"] and cond["custom_container"]
    assert cond["thin_uikit_shell"] and cond["game_signals"] and cond["known_engine_confirmed"] is False
    assert custom["next_steps"], "an in-house engine verdict must come with next steps"
    assert any(s["key"] == "engines.next.script_vm" and s["params"]["vm"] == "lua" for s in custom["next_steps"])


def test_custom_engine_profile_dimensions(runs):
    r = runs.cli("custom_engine")
    fp = r.details["fingerprint"]
    assert list(fp["render"]) == ["metal"]
    assert [h["id"] for h in fp["script_vms"]] == ["lua"] and [h["id"] for h in fp["physics"]] == ["box2d"]
    assert fp["host"]["thin_uikit_shell"] is True and {"CAMetalLayer", "CADisplayLink"} <= set(fp["host"]["main_loop_hints"])
    cont = {h["id"].rsplit("/", 1)[-1]: h["extra"]["verdict"] for h in fp["containers"]}
    assert cont == {"data.pak": "custom_format", "blob.dat": "encrypted_suspected"}
    pak = next(h for h in fp["containers"] if h["id"].endswith("data.pak"))
    assert pak["extra"].get("compression") in ("zlib", ["zlib"]) or "zlib" in str(pak["extra"])
    assert r.verdict("engine.container.unknown") == "suspected"
    assert "Metal" in fp["summary_text"] and "Lua" in fp["summary_text"] and "Box2D" in fp["summary_text"]
    assert r.report["classification"]["category"] == "game"
    # the profile and the verdict reach the Markdown report
    assert "自研" in r.md or "in-house" in r.md.lower()


def test_wrapped_cocos_resources_do_not_turn_a_known_engine_into_a_custom_one(runs):
    plain = runs.cli("cocos_creator3")
    wrapped = runs.cli("cocos_creator3_wrapped")
    custom = runs.cli("custom_engine")
    for r in (plain, wrapped):
        assert r.details["detect"]["primary"]["id"] == "cocos_creator_3x" and r.details["detect"]["primary"]["confirmed"]
        assert r.verdict("engine.custom") == "no" and r.details["detect"]["custom"]["conditions"]["known_engine_confirmed"] is True
    # ... but the custom container header on resources / scripts is reported, as suspected, with the deviation named
    assert plain.verdict("engine.script.encrypted") == "no" and plain.verdict("engine.resource.encrypted") == "no"
    assert wrapped.verdict("engine.script.encrypted") == "suspected" and wrapped.verdict("engine.resource.encrypted") == "suspected"
    cocos = wrapped.details["cocos"]
    assert "custom_wrapper_header_on_scripts" in cocos["xxtea_hint"]["deviations"]
    assert cocos["xxtea_hint"]["sign_prefix"]["ascii"] == "NHPK" and cocos["xxtea_hint"]["sign_prefix"]["is_template_default_sign"] is False
    assert cocos["resources"]["classified"]["counts"]["by_kind"]["custom_header"] == 12
    # the two situations produce opposite engine.custom / engine.primary answers
    assert (custom.verdict("engine.custom"), wrapped.verdict("engine.custom")) == ("yes", "no")
    assert custom.details["detect"]["primary"] is None and wrapped.details["detect"]["primary"] is not None


# ---------------------------------------------------------------------------------------------- Cocos family
@pytest.mark.parametrize("name,engine_id,variant,script,resource", [
    ("cocos_cpp_lua_plain", "cocos2dx_lua", "cocos2dx_lua", "no", "no"),
    ("cocos_lua_xxtea", "cocos2dx_lua", "cocos2dx_lua", "suspected", "no"),
    ("cocos_js_jsc", "cocos2dx_js", "cocos2dx_js", "suspected", None),
    ("cocos_creator3", "cocos_creator_3x", "cocos_creator_3x", "no", "no"),
])
def test_cocos_family(runs, name, engine_id, variant, script, resource):
    r = runs.cli(name)
    assert r.details["detect"]["primary"]["id"] == engine_id and r.details["detect"]["primary"]["confirmed"]
    assert r.verdict("engine.primary") == "yes"
    assert r.details["cocos"]["variant"] == variant and r.verdict("engine.cocos.variant", "engine:cocos") == "yes"
    assert r.verdict("engine.script.encrypted", "engine:cocos") == script
    if resource:
        assert r.verdict("engine.resource.encrypted", "engine:cocos") == resource
    assert r.verdict("engine.custom") == "no" and r.stage("engine.other")["status"] == "ok"
    # "compiled / compressed is not encrypted" must be spelled out wherever the checker says "no"
    if script == "no":
        assert "encrypt" in r.finding("engine.script.encrypted", "engine:cocos")["summary"].lower()


def test_cocos_lua_plain_vs_xxtea_scripts(runs):
    plain = runs.cli("cocos_cpp_lua_plain").details["cocos"]["scripts"]
    xxtea = runs.cli("cocos_lua_xxtea").details["cocos"]["scripts"]
    assert plain["suspected_encrypted"] == 0 and plain["plain"] == 7
    assert xxtea["suspected_encrypted"] == 5
    hint = runs.cli("cocos_lua_xxtea").details["cocos"]["xxtea_hint"]
    assert hint["xxtea_shape"] is True and hint["sign_prefix"]["ascii"] == "XXTEA" and hint["consistent_sign_and_shape"] is True
    assert runs.cli("cocos_cpp_lua_plain").details["cocos"]["xxtea_hint"]["xxtea_shape"] is False


def test_cocos_creator_version_hint(runs):
    assert runs.cli("cocos_creator3").details["cocos"]["version_hint"] == "3.8.2"


@pytest.mark.parametrize("name,engine_id,key", [("egret_app", "egret", "egret"), ("laya_app", "layaair", "laya")])
def test_egret_and_laya(runs, name, engine_id, key):
    r = runs.cli(name)
    assert r.details["detect"]["primary"]["id"] == engine_id and r.details["detect"]["primary"]["confirmed"]
    assert r.verdict("engine.script.encrypted", "engine:" + key) == "no"
    assert r.verdict("engine.resource.encrypted", "engine:" + key) == "no"
    assert r.details[key]["version_hint"] and r.details[key]["scripts"]["plain"] >= 2
    assert not [c for c in r.details["detect"]["candidates"] if c["id"].startswith("cocos") and c["confirmed"]]


def test_flutter(runs):
    r = runs.cli("flutter_app")
    assert r.details["detect"]["primary"]["id"] == "flutter" and r.verdict("engine.flutter_aot") == "yes"
    fl = r.details["flutter"]
    assert fl["engine_framework"] is True and fl["flutter_assets"]["present"] and fl["kernel_blob_present"] is False
    assert fl["binary_scan"]["hits"]["dart_snapshot"] and fl["app_framework_binary"].endswith("App.framework/App")
    assert any(i["id"] == "flutter" for i in r.report["libraries"])
    assert r.verdict("engine.custom") == "no"


# ------------------------------------------------------------------------------------- native / media / libs
def test_native_swiftui_app_with_firebase_and_appsflyer(runs):
    r = runs.cli("native_swift_app")
    assert r.details["detect"]["primary"]["id"] == "native_swiftui" and r.details["detect"]["primary"]["kind"] == "native"
    assert r.details["detect"]["is_game_engine"] is False
    langs = {x["lang"] for x in r.details["detect"]["languages"]}
    assert "swift" in langs
    ids = {i["id"] for i in r.report["libraries"]}
    assert {"firebase_core", "firebase_analytics", "appsflyer", "swift_runtime"} <= ids
    assert {"appsflyer", "firebase_analytics"} <= set(r.report["summary"]["libs"]["privacy_tags"]["tracking"])
    trackers = r.report["privacy"]["trackers"]
    assert trackers, "tracking SDKs must show up in the privacy section"
    assert r.report["classification"]["category"] != "game"
    assert r.stage("engine.unity")["status"] == "skipped" and r.stage("engine.other")["status"] == "skipped"
    assert r.verdict("meta.permissions") == "yes"
    assert r.report["privacy"]["permissions"][0]["key"] == "NSLocationWhenInUseUsageDescription"


def test_media_app_is_classified_from_metadata_and_frameworks(runs):
    r = runs.cli("media_app")
    c = r.report["classification"]
    assert c["category"] == "media" and c["subcategory"] == "music" and c["confidence"] >= 0.9
    kinds = {e["ref"].split(":")[0] for e in c["evidence"]}
    assert "iTunesMetadata.plist" in kinds and "Info.plist" in kinds
    assert r.details["detect"]["is_game_engine"] is False and r.verdict("engine.custom") == "no"
    assert r.report["app"]["distribution"]["type"] in ("appstore", "unsigned_or_repackaged", "unknown")
    assert any(m == "audio" for m in r.report["app"]["background_modes"])


def test_cocos_games_are_classified_as_games(runs):
    for name in ("cocos_creator3", "egret_app", "unity_il2cpp_plain", "custom_engine"):
        assert runs.cli(name).report["classification"]["category"] == "game", name
