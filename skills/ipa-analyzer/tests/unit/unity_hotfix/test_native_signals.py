from __future__ import annotations

import pytest

from fixtures.macho_builder import build_fat, build_macho
from ipa_analyzer.unity.hotfix import detect, native_signals as ns

RULES = detect.load_rules()


def scan(tmp_path, data, name="bin"):
    p = tmp_path / name
    p.write_bytes(data)
    return ns.scan_binary(p, RULES, ref=name)


def versions(res):
    return {(r["flavor"], r["version"]) for r in res.runtime_versions}


def test_lua_version_strings(tmp_path):
    strings = ["Lua 5.3.6  Copyright (C) 1994-2020 Lua.org, PUC-Rio", "LuaJIT 2.1.0-beta3", "luaJIT_version_2_1_0_beta3"]
    res = scan(tmp_path, build_macho(strings=strings))
    assert ("puc", "5.3.6") in versions(res) and ("luajit", "2.1.0-beta3") in versions(res)
    assert not res.limited_by_encryption and res.ran
    best = {r["version"]: r["confidence"] for r in res.runtime_versions}
    assert best["5.3.6"] >= 0.9


def test_lua51_release_string_and_bare_version(tmp_path):
    res = scan(tmp_path, build_macho(strings=["$Lua: Lua 5.1.5  Copyright (C) 1994-2012 Lua.org, PUC-Rio $", "see Lua 5.4 manual"]))
    v = {(r["version"], r["confidence"]) for r in res.runtime_versions}
    assert ("5.1.5", 0.92) in v and ("5.4", 0.45) in v


def test_symbol_hints_imply_flavour_and_version(tmp_path):
    res = scan(tmp_path, build_macho(strings=["_lua_newuserdatauv", "_luaJIT_setmode", "luaopen_utf8", "lua_setfenv"]))
    syms = {h["symbol"] for h in res.symbol_hints}
    assert {"lua_newuserdatauv", "luaJIT_setmode", "luaopen_utf8", "lua_setfenv"} <= syms
    assert ("puc", "5.4") in versions(res) and any(f == "luajit" for f, _ in versions(res))


def test_framework_native_symbols(tmp_path):
    res = scan(tmp_path, build_macho(strings=["_xlua_tocsobj_safe", "_luaopen_xlua", "_ZN9hybridclr11interpreter", "JS_NewRuntime",
                                              "_ZN2v87Isolate3NewE", "tolua_pushuserdata"]))
    fw = {f["id"] for f in detect.merge_frameworks(RULES, res.observations)}
    assert {"xlua", "hybridclr", "tolua"} <= fw
    assert {b["id"] for b in res.js_backends} == {"quickjs", "v8"}


def test_fairplay_encrypted_binary_is_not_scanned_for_noise(tmp_path):
    strings = ["Lua 5.3.6  Copyright (C) 1994-2020 Lua.org, PUC-Rio", "_xlua_pushcsobj"]
    res = scan(tmp_path, build_macho(strings=strings, encrypted=True))
    assert res.limited_by_encryption and res.targets[0]["encrypted"] is True
    assert res.runtime_versions == [] and res.observations == []
    assert any("FairPlay" in n for n in res.notes)


def test_cryptid_zero_binary_with_encryption_command_is_scanned(tmp_path):
    res = scan(tmp_path, build_macho(strings=["LuaJIT 2.0.5"], encryption_info=True, cryptid=0))
    assert not res.limited_by_encryption and ("luajit", "2.0.5") in versions(res)


def test_fat_binary_uses_arm64_slice_and_non_macho_is_raw_scanned(tmp_path):
    fat = build_fat([build_macho(arch="armv7", strings=["Lua 5.1.5  Copyright (C) 1994-2012 Lua.org, PUC-Rio"]),
                     build_macho(arch="arm64", strings=["LuaJIT 2.1.0-beta3"])])
    res = scan(tmp_path, fat, "fat")
    assert versions(res) == {("luajit", "2.1.0-beta3")}
    res = scan(tmp_path, b"\0" * 100 + b"LuaJIT 2.1.0-beta3\0" + b"\0" * 100, "raw")
    assert ("luajit", "2.1.0-beta3") in versions(res) and res.targets[0]["format"] == "raw"


def test_range_helper_and_limits(tmp_path):
    assert ns._ranges(100, [(10, 20), (15, 30), (90, 200)]) == [(0, 10), (30, 90)]
    assert ns._ranges(10, []) == [(0, 10)]
    p = tmp_path / "big"
    p.write_bytes(b"\0" * 5000 + b"LuaJIT 2.1.0-beta3")
    res = ns.scan_binary(p, RULES, ref="big", max_bytes=1000)
    assert res.runtime_versions == [] and any("partial" in n for n in res.notes)


def test_garbage_input_does_not_crash(tmp_path):
    res = scan(tmp_path, b"\xcf\xfa\xed\xfe" + b"\xff" * 20)
    assert res.targets and isinstance(res.notes, list)
    res = scan(tmp_path, b"", "empty")
    assert res.runtime_versions == []


@pytest.mark.parametrize("pid,text,expect", [
    ("lua_full", b"Lua 5.4.6  Copyright (C) 1994-2023 Lua.org, PUC-Rio", ("puc", "5.4.6")),
    ("luajit_sym", b"luaJIT_version_2_1_0_beta3", ("luajit", "2.1.0-beta3")),
    ("luajit_str", b"LuaJIT 2.1.ROLLING", ("luajit", "2.1.ROLLING")),
])
def test_parse_lua_hit(pid, text, expect):
    rv = ns.parse_lua_hit(pid, text)
    assert (rv["flavor"], rv["version"]) == expect
