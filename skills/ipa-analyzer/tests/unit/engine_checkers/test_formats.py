from __future__ import annotations

import pytest

from fixtures import engine_checker_builder as B
from fixtures.formats_builder import build_lua_bytecode
from ipa_analyzer.engines.formats import common, hermes, jsc, pak_ue, pck_godot, plist_atlas, xxtea_hint


# --- classify_blob ---------------------------------------------------------------------------------
def test_classify_plain_bytecode_tampered_xor_compressed_custom_entropy():
    assert common.classify_blob(B.LUA_PLAIN.encode(), 500).kind == common.K_PLAIN
    assert common.classify_blob(build_lua_bytecode("5.3") + B.rand(40), 100).kind == common.K_LUA_BC
    assert common.classify_blob(build_lua_bytecode("luajit2.1") + B.rand(40), 100).kind == common.K_LUA_BC
    t = common.classify_blob(build_lua_bytecode("5.3", tamper="luac_data") + B.rand(40), 100)
    assert t.kind == common.K_LUA_BC_TAMPERED and t.bucket == "suspected_encrypted"
    key = 0x5A
    masked = bytes(b ^ key for b in build_lua_bytecode("5.1") + B.rand(60))
    assert common.classify_blob(masked, len(masked)).kind == common.K_LUA_XOR
    import zlib
    comp = zlib.compress(b"hello world " * 200)
    assert common.classify_blob(comp[:4096], len(comp)).kind == common.K_COMPRESSED
    assert common.classify_blob(b"ZZPK" + B.rand(900), 904).kind == common.K_CUSTOM_HEADER
    assert common.classify_blob(B.rand(4000, 9), 4000).kind == common.K_HIGH_ENTROPY
    assert common.classify_blob(b"\0" * 2000, 2000).kind == common.K_BINARY
    assert common.classify_blob(b"", 0).kind == common.K_EMPTY
    assert common.classify_blob(hermes.MAGIC_BYTES + b"\0" * 60, 70).kind == common.K_HERMES
    b64 = (b"QUJD" * 200)
    assert common.classify_blob(b64, len(b64)).kind == common.K_ENCODED_TEXT


def test_minified_js_is_plain_not_encrypted():
    assert common.classify_blob(B.JS_MINIFIED.encode()[:4096], 5000).kind == common.K_PLAIN


def test_entropy_high_needs_enough_bytes():
    assert common.entropy_is_high(7.9, 100) is None
    assert common.entropy_is_high(7.9, 4096) is True
    assert common.entropy_is_high(5.0, 4096) is False


def test_evenly_sample_deterministic():
    items = list(range(100))
    s, total = common.evenly_sample(items, 10)
    assert total == 100 and len(s) == 10 and s == common.evenly_sample(items, 10)[0] and s[0] == 0
    assert common.evenly_sample(items, 0)[0] == items


# --- hermes ------------------------------------------------------------------------------------------
def test_hermes_header():
    data = B.hermes_bundle(96, 400)
    info = hermes.parse_header(data, 400)
    assert info.valid and info.version == 96 and info.file_length == 400 and info.file_length_matches is True
    assert hermes.parse_header(data, 999).file_length_matches is False
    assert not hermes.parse_header(b"var x=1;").valid
    assert hermes.parse_header(data[:10]).truncated
    delta = hermes.DELTA_MAGIC_BYTES + data[8:]
    assert hermes.parse_header(delta).delta_form and not hermes.parse_header(delta).valid


# --- unreal pak --------------------------------------------------------------------------------------
@pytest.mark.parametrize("version,enc", [(3, False), (4, False), (4, True), (7, True), (8, False), (8, True), (9, True),
                                          (10, False), (11, True)])
def test_pak_footer_versions(version, enc):
    data = B.ue_pak(version, encrypted_index=enc)
    info = pak_ue.parse_footer(data[-pak_ue.TAIL_BYTES:], len(data))
    assert info.valid and info.version == version and info.index_in_bounds
    assert info.index_encrypted == (enc if version >= 4 else None)


def test_pak_footer_v8_with_four_names_and_truncation():
    data = B.ue_pak(8, names=4)
    info = pak_ue.parse_footer(data[-pak_ue.TAIL_BYTES:], len(data))
    assert info.valid and info.version == 8 and info.compression_methods == ["Zlib", "Oodle"]
    cut = B.ue_pak(8, truncate_footer=True)
    assert not pak_ue.parse_footer(cut[-pak_ue.TAIL_BYTES:], len(cut)).valid
    assert pak_ue.parse_footer(b"abc", 3).truncated
    bad = B.ue_pak(8, bad_index=True)
    assert pak_ue.parse_footer(bad[-pak_ue.TAIL_BYTES:], len(bad)).index_in_bounds is False


def test_utoc_header():
    t = pak_ue.parse_utoc_header(B.ue_utoc(encrypted=True))
    assert t.valid and t.encrypted and "encrypted" in t.flag_names
    assert pak_ue.parse_utoc_header(B.ue_utoc(encrypted=False)).encrypted is False
    assert not pak_ue.parse_utoc_header(b"x" * 100).valid
    assert pak_ue.parse_utoc_header(b"-==--==--==--==-" + b"\0" * 8).truncated


# --- godot ---------------------------------------------------------------------------------------------
def _read_dir(data, **kw):
    info = pck_godot.parse_header(data[:128])
    return pck_godot.read_directory(info, lambda off, n: data[off:off + n], len(data), **kw)


def test_pck_formats():
    p = _read_dir(B.godot_pck(entries=[("res://a.gd", False), ("res://b.gde", True), ("res://c.tscn", False)]))
    assert p.valid and p.pack_format == 2 and p.engine_version == "4.2.0" and p.dir_encrypted is False
    assert p.entries_read == 3 and p.file_encrypted_count == 1 and p.script_files == {"gd": 1, "gde": 1}
    v1 = _read_dir(B.godot_pck(fmt=1))
    assert v1.valid and v1.pack_format == 1 and v1.file_count == 1 and v1.directory_status == "read"
    enc = _read_dir(B.godot_pck(dir_encrypted=True))
    assert enc.dir_encrypted and enc.directory_status == "encrypted"
    cut = _read_dir(B.godot_pck(truncate=True))
    assert cut.directory_status in ("truncated", "malformed")
    assert not pck_godot.parse_header(b"PK\x03\x04").valid


def test_gdsc_gdec_markers():
    assert pck_godot.classify_script_head(b"GDSC\x65\0\0\0") == "gdc"
    assert pck_godot.classify_script_head(b"GDEC" + b"\0" * 8) == "gde"
    assert pck_godot.classify_script_head(b"extends Node") == "other"


# --- xxtea / jsc / plist -------------------------------------------------------------------------------
CFG = {"prefix_min_len": 2, "prefix_max_len": 16, "prefix_support_min": 0.9, "min_files": 3, "mod4_share_min": 0.9}


def test_xxtea_hint_consistent_and_deviations():
    files = [B.xxtea_like(900 + 4 * i, i) for i in range(8)]
    hint = xxtea_hint.script_hint([f[:64] for f in files], [len(f) for f in files], CFG)
    assert hint["sign_prefix"]["ascii"] == "XXTEA" and hint["sign_prefix"]["is_template_default_sign"]
    assert hint["xxtea_shape"] and hint["consistent_sign_and_shape"]
    assert xxtea_hint.deviations(hint, {}) == []
    odd = [b"ABCD" + B.rand(900 + i, i) for i in range(8)]
    h2 = xxtea_hint.script_hint([f[:64] for f in odd], [len(f) for f in odd], CFG)
    assert h2["sign_prefix"]["ascii"] == "ABCD" and not h2["xxtea_shape"]
    dev = xxtea_hint.deviations(h2, {"blowfish": ["BF_set_key"]})
    assert "common_prefix_without_xxtea_size_structure" in dev and "blowfish_hint_in_binary" in dev
    noprefix = [B.rand(1000 + 4 * i, 50 + i) for i in range(8)]
    h3 = xxtea_hint.script_hint([f[:64] for f in noprefix], [len(f) for f in noprefix], CFG)
    assert h3["sign_prefix"] is None
    assert "xxtea_in_binary_but_no_common_sign_prefix_in_scripts" in xxtea_hint.deviations(h3, {"xxtea_api": ["xxtea_decrypt"]})


def test_jsc_interpretation():
    info = jsc.classify_jsc(B.rand(400), 400, True)
    assert info.kind == "opaque"
    assert jsc.interpret("cocos_creator_3x", info) == "creator_xxtea_documented"
    assert jsc.interpret("cocos2dx_js", info) == "spidermonkey_bytecode_or_cipher"
    assert jsc.classify_jsc(b"var a=1;", 8, False).kind == "plain_text"
    assert jsc.classify_jsc(b"\x1f\x8b\x08" + b"\0" * 20, 23, True).kind == "gzip"


def test_plist_classification():
    atlas = ('<?xml version="1.0"?><plist version="1.0"><dict><key>frames</key><dict/><key>metadata</key><dict>'
             "<key>format</key><integer>2</integer><key>textureFileName</key><string>a.png</string></dict></dict></plist>")
    assert plist_atlas.classify_plist_bytes(atlas.encode())[0] == "atlas"
    part = B.cocos2dx_cpp_files()["effect.plist"]
    assert plist_atlas.classify_plist_bytes(part.encode())[0] == "particle"
    assert plist_atlas.classify_plist_object({"a": 1})[0] == "other"


@pytest.mark.parametrize("seed", range(20))
def test_parsers_never_raise_on_garbage(seed):
    data = B.rand(seed * 37 % 300 + 1, seed)
    for chunk in (data, data[: len(data) // 2], b""):
        hermes.parse_header(chunk, len(chunk))
        pak_ue.parse_footer(chunk, len(chunk))
        pak_ue.parse_utoc_header(chunk)
        info = pck_godot.parse_header(b"GDPC" + chunk)
        pck_godot.read_directory(info, lambda off, n, c=chunk: c[off:off + n], len(chunk))
        common.classify_blob(chunk, len(chunk))


def test_empty_and_tiny_script_files_do_not_crash(runner):
    files = B.cocos2dx_lua_files("plain")
    files.update({"src/empty.lua": b"", "src/one.lua": b"x", "src/e.luac": b"\x1bLua"})
    r = runner.run(files, detect=["cocos2dx_lua"])
    assert r.status.value == "ok" and r.data["cocos"]["scripts"]["counts"]["by_kind"].get("empty") == 1
