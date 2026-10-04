from __future__ import annotations

import pytest

from fixtures import engine_checker_builder as B
from fixtures.macho_builder import build_macho
from ipa_analyzer.models import Status, Verdict

V = Verdict


def test_egret_and_laya_positive(runner):
    r = runner.run(B.egret_files())
    assert r.status == Status.OK and r.data["egret"]["version_hint"] == "5.4.1"
    assert r.data["egret"]["manifest"] == {"plain_json": True, "initial": 1, "game": 1}
    assert r.verdict("engine.script.encrypted", "egret") == V.NO and r.verdict("engine.resource.encrypted", "egret") == V.NO
    r2 = runner.run(B.laya_files())
    assert r2.data["laya"]["version_hint"] == "2.13.0" and "laya" in r2.data
    assert r2.verdict("engine.script.encrypted", "laya") == V.NO


def test_egret_wrapped_resources_suspected(runner):
    r = runner.run(B.egret_files(wrapped_res=True), detect=["egret"])
    f = r.finding("engine.resource.encrypted", "egret")
    assert f.verdict == V.SUSPECTED and r.data["egret"]["wrapper_clusters"][0]["tag"] == "EGRX"


def test_minified_js_only_app_does_not_trigger_egret_or_laya(runner):
    r = runner.run({"main.min.js": B.JS_MINIFIED, "a.png": b"\x89PNG\r\n\x1a\n" + B.rand(30)})
    assert "egret" not in r.data and "laya" not in r.data


@pytest.mark.parametrize("kw,verdict", [({"version": 8}, V.NO), ({"version": 10, "encrypted_index": True}, V.YES),
                                         ({"version": 9, "encrypted_index": True}, V.YES), ({"version": 3}, V.NO),
                                         ({"version": 8, "truncate_footer": True}, V.UNKNOWN),
                                         ({"version": 8, "bad_index": True}, V.UNKNOWN)])
def test_unreal_pak_three_situations(runner, kw, verdict):
    r = runner.run(B.unreal_files(**kw), detect=["unreal"])
    f = r.finding("engine.pak.encrypted", "unreal")
    assert f.verdict == verdict
    if verdict == V.NO:
        assert "not encrypted content" in f.summary and "entries" in f.summary


def test_unreal_applies_from_pak_footer_alone_and_iostore(runner):
    assert runner.run(B.unreal_files(version=8)).data["unreal"]["containers"][0]["version"] == 8
    files = {"Content/Paks/a.utoc": B.ue_utoc(encrypted=True), "Content/Paks/a.ucas": B.rand(500)}
    r = runner.run(files, detect=["unreal"])
    assert r.verdict("engine.pak.encrypted", "unreal") == V.YES and r.data["unreal"]["containers"][0]["ucas_present"]


def test_unreal_not_triggered_by_random_pak(runner):
    r = runner.run({"data.pak": B.rand(1000)})
    assert "unreal" not in r.data


def test_godot_pck_cases(runner):
    r = runner.run({"game.pck": B.godot_pck()})
    assert r.verdict("engine.pak.encrypted", "godot") == V.NO and r.data["godot"]["packs"][0]["engine_version"] == "4.2.0"
    assert runner.run({"game.pck": B.godot_pck(dir_encrypted=True)}).verdict("engine.pak.encrypted", "godot") == V.YES
    flagged = runner.run({"game.pck": B.godot_pck(entries=[("res://a.gde", True)])})
    assert flagged.verdict("engine.pak.encrypted", "godot") == V.YES and flagged.verdict("engine.script.encrypted", "godot") == V.YES
    assert runner.run({"game.pck": B.godot_pck(truncate=True)}, detect=["godot"]).verdict(
        "engine.pak.encrypted", "godot") == V.UNKNOWN


def test_godot_loose_scripts(runner):
    files = {"a.gdc": b"GDSC" + b"\x65\0\0\0" + B.rand(30), "b.gde": b"GDEC" + B.rand(40), "c.gd": "extends Node\n"}
    r = runner.run(files, detect=["godot"])
    assert r.verdict("engine.script.encrypted", "godot") == V.YES
    r2 = runner.run({"a.gdc": b"GDSC" + b"\x65\0\0\0" + B.rand(30)}, detect=["godot"])
    assert r2.verdict("engine.script.encrypted", "godot") == V.NO


@pytest.mark.parametrize("kind,hermes_v,script_v", [("hermes", V.YES, V.NO), ("plain", V.NO, V.NO), ("opaque", V.UNKNOWN, V.SUSPECTED)])
def test_react_native_bundles(runner, kind, hermes_v, script_v):
    r = runner.run(B.rn_files(kind=kind), detect=["react_native"])
    assert r.verdict("engine.hermes", "react_native") == hermes_v
    assert r.verdict("engine.script.encrypted", "react_native") == script_v
    if kind == "hermes":
        assert r.data["react_native"]["hermes_versions"] == [96]


def test_flutter_aot_and_jit(runner):
    r = runner.run(B.flutter_files(), detect=["flutter"])
    assert r.verdict("engine.flutter_aot", "flutter") == V.YES and r.data["flutter"]["engine_framework"]
    r2 = runner.run(B.flutter_files(kernel=True))
    assert r2.verdict("engine.flutter_aot", "flutter") == V.NO
    r3 = runner.run({"Frameworks/Flutter.framework/Flutter": build_macho(filetype="dylib")})
    assert r3.verdict("engine.flutter_aot", "flutter") == V.UNKNOWN


def test_flutter_word_without_framework_is_not_flutter(runner):
    assert "flutter" not in runner.run({"about.txt": "we love Flutter"}).data


def test_defold(runner):
    assert runner.run(B.defold_files(encrypted=(False, True))).verdict("engine.pak.encrypted", "defold") == V.YES
    r = runner.run(B.defold_files())
    assert r.verdict("engine.pak.encrypted", "defold") == V.NO and r.data["defold"]["archives"][0]["entries"] == 2
    assert runner.run(B.defold_files(version=5), detect=["defold"]).verdict("engine.pak.encrypted", "defold") == V.UNKNOWN


def test_gamemaker(runner):
    assert runner.run(B.gamemaker_files()).verdict("engine.pak.encrypted", "gamemaker") == V.NO
    r = runner.run(B.gamemaker_files(broken=True))
    assert r.verdict("engine.pak.encrypted", "gamemaker") == V.SUSPECTED
    assert runner.run({"game.ios": B.rand(2000)}).verdict("engine.pak.encrypted", "gamemaker") == V.SUSPECTED


def test_solar2d_and_love(runner):
    r = runner.run(B.solar2d_files())
    assert r.verdict("engine.resource.encrypted", "solar2d_love") == V.NO
    assert r.data["solar2d_love"]["solar2d"]["profile"]["bytecode"]["by_version"] == {"5.1": 3}
    assert runner.run(B.solar2d_files(encrypted=True), detect=["solar2d"]).verdict(
        "engine.resource.encrypted", "solar2d_love") == V.UNKNOWN
    assert runner.run(B.love_files()).verdict("engine.resource.encrypted", "solar2d_love") == V.NO
    enc = runner.run(B.love_files(encrypted=True))
    assert enc.verdict("engine.resource.encrypted", "solar2d_love") == V.YES


def test_xamarin(runner):
    r = runner.run(B.xamarin_files())
    f = r.finding("engine.script.encrypted", "xamarin")
    assert f.verdict == V.NO and r.data["xamarin"]["assemblies"][0]["is_dotnet"]
    assert runner.run(B.xamarin_files(broken=3)).verdict("engine.script.encrypted", "xamarin") == V.SUSPECTED
    native = runner.run(B.xamarin_files(native_dll=True)).data["xamarin"]["assemblies"]
    assert next(a for a in native if a["path"] == "native.dll")["is_dotnet"] is False


def test_web_hybrid(runner):
    r = runner.run(B.web_files(obfuscated=True))
    d = r.data["web_hybrid"]["scripts"]
    assert d["obfuscator_style_js"] >= 1 and d["plain_ratio"] == 1.0
    assert r.verdict("engine.script.encrypted", "web_hybrid") == V.NO
    assert runner.run(B.web_files(encrypted=True)).verdict("engine.script.encrypted", "web_hybrid") == V.SUSPECTED


def test_generic_scripts_custom_wrapper_cluster(runner):
    """Self-made engine: many files with standard extensions but a shared custom 4-byte header."""
    r = runner.run(B.custom_wrapper_files(24), custom={"verdict": "suspected", "confidence": 0.5})
    c = r.data["generic_scripts"]["wrapper_clusters"][0]
    assert c["tag"] == "ZZPK" and c["files"] == 24 and c["size_field_offset"] == 4
    assert set(c["exts"]) == {".json", ".png", ".js"}
    assert r.verdict("engine.script.encrypted", "generic_scripts") == V.SUSPECTED
    f = r.finding("engine.resource.encrypted", "generic_scripts")
    assert f.verdict == V.SUSPECTED and "vendor not asserted" in f.summary
    assert all("netease" not in x.summary.lower() for x in r.res.findings)


def test_generic_scripts_small_clusters_ignored_and_plain_ok(runner):
    r = runner.run(B.custom_wrapper_files(4), detect=[])
    assert "wrapper_clusters" not in r.data.get("generic_scripts", {}) or r.data["generic_scripts"]["wrapper_clusters"] == []
    r2 = runner.run({"a.js": B.JS_PLAIN, "b.js": B.JS_MINIFIED, "c.js": B.JS_PLAIN})
    assert r2.verdict("engine.script.encrypted", "generic_scripts") == V.NO


def test_lua_checker_profile_for_unknown_engine(runner):
    files = {"a.lua": B.LUA_PLAIN, "b.lua": B.LUA53_PLAIN, "c.luac": B.build_lua_bytecode("5.3") + B.rand(50),
             "d.luac": B.build_lua_bytecode("luajit2.1") + B.rand(50), "e.lua": B.xxtea_like(900, 3)}
    r = runner.run(files)
    lua = r.data["lua"]["scripts"]["lua"]
    assert lua["bytecode"]["by_version"] == {"5.3": 1, "luajit_2.1": 1} and lua["files"]["total"] == 5
    assert r.verdict("engine.script.encrypted", "lua") == V.SUSPECTED


def test_vendor_dirs_are_ignored(runner):
    files = {"Frameworks/Sdk.framework/a.js": B.rand(3000), "Sdk.bundle/x.lua": B.rand(3000), "www/index.html": "<html></html>"}
    r = runner.run(files)
    assert "generic_scripts" not in r.data
