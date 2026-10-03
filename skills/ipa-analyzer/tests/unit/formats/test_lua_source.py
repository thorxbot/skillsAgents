from __future__ import annotations

import time

import pytest

from ipa_analyzer.formats import lua_source as ls


def mv(text):
    return ls.infer_dialect(text).min_version


@pytest.mark.parametrize(
    "src,expected",
    [
        ("local x = 1\nprint(x)\n", None),
        ("for i=1,3 do if i == 2 then goto continue end print(i) ::continue:: end", "5.2"),
        ("::top:: x = x + 1", "5.2"),
        ("local a = 7 // 2", "5.3"),
        ("local a = 1 << 4", "5.3"),
        ("local a = x >> 1", "5.3"),
        ("local a = x & 0xff", "5.3"),
        ("local a = x | y", "5.3"),
        ("local a = x ~ y", "5.3"),
        ("local a = ~x", "5.3"),
        ("local x <const> = 5", "5.4"),
        ("local f <close> = io.open('x')", "5.4"),
        ("local a, b <const> = 1, 2", "5.4"),
        ("local t = bit32.band(1, 2)", "5.2"),
        ("print(utf8.char(72))", "5.3"),
        ("print(math.tointeger(3.0))", "5.3"),
        ("local s = string.pack('i4', 1)", "5.3"),
        ("table.move(a, 1, 3, 2)", "5.3"),
        ("print(table.unpack(t))", "5.2"),
        ("x = a // b -- plus a << comment\nlocal y <const> = 1", "5.4"),
    ],
)
def test_min_version_from_syntax(src, expected):
    assert mv(src) == expected


@pytest.mark.parametrize(
    "src",
    [
        "-- goto skip // and ::label:: and a << b\nprint(1)",
        "--[[ goto x\n  a // b\n  local c <const> = 1 ]] print(1)",
        "--[==[ ]] x & y ]==] print(1)",
        "local s = 'goto // :: & | ~ << >>'",
        'local s = "a // b \\" still string // here"',
        "local s = [[ goto x\n a // b ]]",
        "local s = [==[ x | y ]] z ]==]",
        "local s = 'it''s'",  # adjacent strings, no operators
        "if a ~= b then print(1) end",  # ~= is plain inequality in every version
        "local goto_count = 0; local mygoto = 1; t.goto = 2",
        "print(a.bit32, bit32x)",
        "local url = 'http://example.com/x'",
        "x = y --[[ inline // ]] + 1",
        "#!/usr/bin/lua\nprint(1) -- 7 // 2",
    ],
)
def test_no_false_positive_from_strings_and_comments(src):
    h = ls.infer_dialect(src)
    assert h.min_version is None, h.signals


def test_comment_and_string_stripping_preserves_lines():
    src = 'a = "x\\\ny"\n--[[ one\ntwo ]]\nb = 1 -- tail\nc = [[l1\nl2]]\nd = 2'
    stripped = ls.strip_comments_and_strings(src)
    assert stripped.count("\n") == src.count("\n")
    assert "tail" not in stripped and "two" not in stripped and "l2" not in stripped
    assert "b = 1" in stripped and "d = 2" in stripped


def test_unterminated_constructs_do_not_hang_or_crash():
    for src in ["x = 'abc", 'y = "abc\nz = 1 // 2', "--[[ never closed\n a // b", "s = [[ never closed // ", "[=[", "--[=="]:
        ls.infer_dialect(src)
    assert mv('y = "abc\nz = 1 // 2') == "5.3"  # unterminated quote ends at the newline; code continues


def test_pathological_inputs_are_fast():
    start = time.monotonic()
    ls.infer_dialect("[[" * 100_000)
    ls.infer_dialect("--[[" * 100_000)
    ls.infer_dialect("'" * 200_000)
    ls.infer_dialect("[=" * 100_000)
    assert time.monotonic() - start < 5


def test_style_hints_do_not_set_a_version():
    h = ls.infer_dialect("setfenv(1, env)\nlocal u = unpack(t)\nmodule('m', package.seeall)\nx = loadstring('1')\ntable.getn(t)")
    assert h.min_version is None
    assert set(h.style_hints) == {"setfenv_getfenv", "global_unpack", "module_call", "loadstring", "table_getn"}


def test_method_and_field_names_are_not_style_hints():
    h = ls.infer_dialect("obj:module('x'); t.unpack(1); self.setfenv(2)")
    assert h.style_hints == []


def test_conflict_between_old_api_and_new_syntax():
    h = ls.infer_dialect("setfenv(1, e)\nlocal a = 1 // 2")
    assert h.min_version == "5.3" and h.conflicts


def test_luajit_signals():
    h = ls.infer_dialect('local ffi = require("ffi")\nffi.cdef[[ int x; ]]\nlocal n = 5LL\nprint(bit.band(1,2), jit.status())')
    assert set(h.luajit_signals) == {"ffi", "ll_suffix", "bit_lib", "jit"}
    # mention inside a comment/string only
    assert ls.infer_dialect('-- require("ffi")\nlocal s = "ffi.cdef"').luajit_signals == []


def test_bytes_input_truncation_and_bom():
    src = b"\xef\xbb\xbflocal a = 1 // 2\n"
    assert ls.infer_dialect(src).min_version == "5.3"
    big = b"x = 1\n" * 100_000 + b"y = 1 // 2\n"
    h = ls.infer_dialect(big, max_bytes=4096)
    assert h.truncated and h.min_version is None and h.scanned_bytes <= 4096
    assert not ls.infer_dialect(b"x = 1\n").truncated
    assert ls.infer_dialect("x = 1 // 2".encode("utf-16")).scanned_bytes > 0  # undecodable input must not raise


def test_confidence_scales_with_signal_strength():
    assert ls.infer_dialect("x = 1").confidence == 0.0
    assert ls.infer_dialect("local a <const> = 1").confidence >= 0.9
    assert ls.infer_dialect("print(utf8.char(1))").confidence < 0.9


def test_to_dict_shape():
    d = ls.infer_dialect("a = 1 // 2").to_dict()
    assert set(d) == {"min_version", "signals", "style_hints", "luajit_signals", "conflicts", "confidence", "scanned_bytes", "truncated"}
