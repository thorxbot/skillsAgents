from __future__ import annotations

import pytest

from fixtures import engine_checker_builder as B
from fixtures.macho_builder import build_macho
from ipa_analyzer.engines.api import get_checkers
from ipa_analyzer.models import Status, Verdict

VARIANT_CASES = [
    ("cocos_creator_3x", lambda: B.cocos_creator3x_files(), ["cocos_creator_3x"]),
    ("cocos_creator_2x", lambda: B.cocos_creator2x_files(), []),
    ("cocos2dx_lua", lambda: B.cocos2dx_lua_files("plain"), []),
    ("cocos2dx_js", lambda: B.cocos2dx_js_files(), []),
    ("cocos2d_iphone", lambda: B.cocos2d_iphone_files(), []),
    ("cocos2dx_cpp", lambda: B.cocos2dx_cpp_files(), []),
]


@pytest.mark.parametrize("variant,files,detect", VARIANT_CASES)
def test_six_variants_detected_from_layout(runner, variant, files, detect):
    r = runner.run(files(), detect=detect)
    assert r.status == Status.OK
    assert r.data["cocos"]["variant"] == variant
    f = r.finding("engine.cocos.variant", "cocos")
    assert f.verdict == Verdict.YES and f.params["variant"] == variant


def test_creator3_version_hint_and_bundles(runner):
    r = runner.run(B.cocos_creator3x_files(), detect=["cocos_creator_3x"])
    d = r.data["cocos"]
    assert d["version_hint"] == "3.8.2" and d["version_sources"][0]["source"] == "src/settings.json"
    names = {b["name"] for b in d["bundles"]}
    assert {"main", "resources"} <= names and d["bundle_total"] == 2
    main = next(b for b in d["bundles"] if b["name"] == "main")
    assert main["config_summary"]["uuids"] == 2 and main["script"] == "index.js"


def test_plain_scripts_are_not_encrypted(runner):
    r = runner.run(B.cocos2dx_lua_files("plain"))
    f = r.finding("engine.script.encrypted", "cocos")
    assert f.verdict == Verdict.NO and "not encrypted" in f.summary
    s = r.data["cocos"]["scripts"]
    assert s["plain"] == 7 and s["suspected_encrypted"] == 0


def test_minified_js_not_reported_as_encrypted(runner):
    files = B.cocos_creator3x_files()
    files["main.js"] = B.JS_MINIFIED
    r = runner.run(files, detect=["cocos_creator_3x"])
    assert r.verdict("engine.script.encrypted", "cocos") == Verdict.NO


@pytest.mark.parametrize("mode,key,ver", [("luac51", "5.1", "5.1"), ("luac53", "5.3", "5.3"), ("luajit", "luajit_2.1", "2.1")])
def test_lua_bytecode_is_no_and_labelled_compiled(runner, mode, key, ver):
    r = runner.run(B.cocos2dx_lua_files(mode), detect=["cocos2dx_lua"])
    f = r.finding("engine.script.encrypted", "cocos")
    assert f.verdict == Verdict.NO
    assert "not encrypted content" in f.summary
    lua = r.data["cocos"]["scripts"]["lua"]
    assert lua["bytecode"]["by_version"] == {key: 5} or lua["bytecode"]["by_version"].get(key) == 5
    assert lua["files"]["bytecode"] == 5 and lua["bytecode"]["arch_bits"]


def test_cocos_lua_xxtea_is_suspected_with_sign_evidence(runner):
    r = runner.run(B.cocos2dx_lua_files("xxtea"), detect=["cocos2dx_lua"])
    f = r.finding("engine.script.encrypted", "cocos")
    assert f.verdict == Verdict.SUSPECTED and f.confidence >= 0.8
    hint = r.data["cocos"]["xxtea_hint"]
    assert hint["sign_prefix"]["ascii"] == "XXTEA" and hint["consistent_sign_and_shape"]
    assert any(e.ref == "script sign prefix" for e in f.evidence)
    assert r.data["cocos"]["scripts"]["suspected_encrypted"] == 5


def test_lua_profile_mixed_versions_and_dialect(runner):
    files = B.cocos2dx_lua_files("plain")
    files["src/app/v53.lua"] = B.LUA53_PLAIN
    files["src/app/bc.luac"] = B.build_lua_bytecode("5.1") + B.rand(60)
    files["src/app/bc3.luac"] = B.build_lua_bytecode("5.3") + B.rand(60)
    lua = runner.run(files, detect=["cocos2dx_lua"]).data["cocos"]["scripts"]["lua"]
    assert lua["bytecode"]["by_version"] == {"5.1": 1, "5.3": 1}
    assert any("5.3" in h for h in lua["dialect_hints"])
    assert any("more than one Lua version" in n for n in lua["consistency"]["notes"])
    assert not lua["custom_lua_suspected"]


def test_tampered_lua_header_flags_custom_lua(runner):
    files = B.cocos2dx_lua_files("plain")
    files["src/app/t.luac"] = B.build_lua_bytecode("5.3", tamper="luac_data") + B.rand(60)
    r = runner.run(files, detect=["cocos2dx_lua"])
    assert r.data["cocos"]["scripts"]["lua"]["custom_lua_suspected"] is True
    assert r.verdict("engine.script.encrypted", "cocos") == Verdict.SUSPECTED


def test_creator_jsc_is_documented_xxtea_yes(runner):
    r = runner.run(B.cocos_creator3x_files(jsc=True), detect=["cocos_creator_3x"])
    f = r.finding("engine.script.encrypted", "cocos")
    assert f.verdict == Verdict.YES and r.data["cocos"]["scripts"]["jsc_interpretation"] == {"creator_xxtea_documented": 2}


def test_cocos2dx_js_jsc_is_only_suspected(runner):
    r = runner.run(B.cocos2dx_js_files(jsc=True))
    f = r.finding("engine.script.encrypted", "cocos")
    assert f.verdict == Verdict.SUSPECTED and "SpiderMonkey" in f.summary


def test_creator3_encrypted_scripts_suspected_creator2_jsc_yes(runner):
    r = runner.run(B.cocos_creator3x_files(encrypted_js=True), detect=["cocos_creator_3x"])
    assert r.verdict("engine.script.encrypted", "cocos") == Verdict.SUSPECTED
    r2 = runner.run(B.cocos_creator2x_files(jsc=True))
    assert r2.data["cocos"]["variant"] == "cocos_creator_2x"
    assert r2.verdict("engine.script.encrypted", "cocos") == Verdict.YES


def test_ccz_encrypted_and_plain_counts(runner):
    r = runner.run(B.cocos2dx_cpp_files(encrypted=True, n=7))
    ccz = r.data["cocos"]["resources"]["ccz"]
    assert ccz["encrypted"] == 7 and ccz["plain"] == 0 and ccz["total"] == 7
    f = r.finding("engine.resource.encrypted", "cocos")
    assert f.verdict == Verdict.YES and f.params["encrypted"] == 7
    r2 = runner.run(B.cocos2dx_cpp_files(encrypted=False, n=4))
    ccz2 = r2.data["cocos"]["resources"]["ccz"]
    assert ccz2["plain"] == 4 and ccz2["encrypted"] == 0 and ccz2["plain_zlib_header_ok"] == 4
    assert r2.verdict("engine.resource.encrypted", "cocos") == Verdict.NO


def test_ccz_mixed_and_stock_deviation(runner):
    files = {"a/p1.ccz": B.ccz_bytes(encrypted=True), "a/p2.ccz": B.ccz_bytes(encrypted=True, version=1),
             "a/p3.ccz": B.ccz_bytes(encrypted=True, comp=3), "a/n1.ccz": B.ccz_bytes(encrypted=False)}
    ccz = runner.run(files).data["cocos"]["resources"]["ccz"]
    assert (ccz["encrypted"], ccz["plain"], ccz["deviating_from_stock"]) == (3, 1, 2)
    assert "CCZp comp=3 ver=0" in ccz["header_shapes"]
    assert "ccz_header_deviates_from_stock" in runner.run(files).data["cocos"]["resource_deviations"]


def test_custom_wrapper_cluster_on_resources_and_scripts(runner):
    r = runner.run(B.cocos_creator3x_files(wrapped=True), detect=["cocos_creator_3x"])
    clusters = r.data["cocos"]["resources"]["wrapper_clusters"]
    assert clusters and clusters[0]["tag"] == "PKA1" and clusters[0]["size_field_offset"] == 4
    assert clusters[0]["files"] >= 24
    assert r.verdict("engine.resource.encrypted", "cocos") == Verdict.SUSPECTED
    assert r.verdict("engine.script.encrypted", "cocos") == Verdict.SUSPECTED
    s = r.finding("engine.script.encrypted", "cocos")
    assert "custom_wrapper_header_on_scripts" in r.data["cocos"]["xxtea_hint"]["deviations"]
    assert "PKA1" not in s.title                       # no vendor / engine claim from the tag


def test_native_app_with_atlas_plist_does_not_trigger_cocos(runner):
    r = runner.run(B.native_plist_png_files())
    assert r.status == Status.SKIPPED
    assert "cocos" not in r.data


def test_applies_via_detect_without_layout_gives_unknown_variant(runner):
    r = runner.run({"res/a.png": b"\x89PNG\r\n\x1a\n" + B.rand(40)}, detect=["cocos2dx_cpp"])
    d = r.data["cocos"]
    assert d["variant"] == "unknown" and "detect_says_cocos_but_layout_unrecognised" in d["xxtea_hint"]["deviations"]
    assert r.verdict("engine.cocos.variant", "cocos") == Verdict.UNKNOWN


def test_binary_hints_from_symbols_and_strings_when_unencrypted(runner):
    exe = build_macho(strings=["cocos2d-x-3.17.2", "setXXTEAKeyAndSign", "Lua 5.1.5  Copyright (C) 1994-2012 Lua.org, PUC-Rio"],
                      symbols=["_xxtea_decrypt", "__ZN7cocos2d8Director11getInstanceEv"])
    r = runner.run(B.cocos2dx_lua_files("luac51"), detect=["cocos2dx_lua"], main_binary=exe)
    d = r.data["cocos"]
    hits = d["xxtea_hint"]["binary"]["hits"]
    assert d["xxtea_hint"]["binary"]["status"] == "scanned"
    assert hits["xxtea_api"] and hits["xxtea_key_setter"] and hits["cocos_cpp"]
    assert d["version_hint"] == "3.17.2"
    rt = d["scripts"]["lua"]["runtime_versions"]
    assert rt and rt[0]["flavor"] == "puc" and rt[0]["version"] == "5.1.5"
    assert d["scripts"]["lua"]["consistency"]["ok"] is True


def test_fairplay_encrypted_binary_degrades_and_says_so(runner):
    exe = build_macho(encrypted=True, strings=["setXXTEAKeyAndSign"], symbols=["_xxtea_decrypt"])
    r = runner.run(B.cocos2dx_lua_files("xxtea"), detect=["cocos2dx_lua"], main_binary=exe)
    b = r.data["cocos"]["xxtea_hint"]["binary"]
    assert b["status"] == "skipped_encrypted" and b["encrypted"] is True and not b["strings_scanned"]
    assert not b["hits"].get("xxtea_key_setter")          # C strings are ciphertext: never reported
    assert any("FairPlay" in w for w in r.res.warnings)
    assert "FairPlay" in r.finding("engine.script.encrypted", "cocos").summary or "limited" in r.finding(
        "engine.script.encrypted", "cocos").summary or "Binary-based hints" in r.finding("engine.script.encrypted", "cocos").summary


def test_lua_runtime_mismatch_noted(runner):
    exe = build_macho(strings=["Lua 5.3.6  Copyright (C) 1994-2020 Lua.org, PUC-Rio"])
    lua = runner.run(B.cocos2dx_lua_files("luac51"), detect=["cocos2dx_lua"], main_binary=exe).data["cocos"]["scripts"]["lua"]
    assert lua["consistency"]["ok"] is False and any("not matched" in n for n in lua["consistency"]["notes"])


def test_sampling_is_reported(runner):
    files = {"src/s%d.lua" % i: B.LUA_PLAIN for i in range(260)}
    files.update(B.cocos2dx_lua_files("plain"))
    r = runner.run(files, detect=["cocos2dx_lua"])
    c = r.data["cocos"]["scripts"]["counts"]
    assert c["sampled"] == 200 and c["of"] > 260
    f = r.finding("engine.script.encrypted", "cocos")
    assert f.params["sampled"] == 200 and f.verdict == Verdict.NO and f.confidence < 0.85


def test_mixed_project_with_channel_shell_does_not_fail(runner):
    files = B.cocos2dx_lua_files("plain")
    files.update({"Frameworks/Channel.framework/Channel": build_macho(filetype="dylib"), "channel/sdk.js": B.JS_PLAIN,
                  "src/own_framework/core.lua": B.LUA_PLAIN, "HD/a.ccz": B.ccz_bytes(encrypted=True)})
    r = runner.run(files, detect=["cocos2dx_lua"])
    assert r.status == Status.OK and r.data["cocos"]["variant"] == "cocos2dx_lua"
    assert r.data["cocos"]["resources"]["ccz"]["encrypted"] == 1


def test_cocos_checker_registered_once():
    ids = [c.engine_id for c in get_checkers()]
    assert ids.count("cocos") == 1
