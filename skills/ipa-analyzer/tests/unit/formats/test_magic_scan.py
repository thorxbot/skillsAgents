from __future__ import annotations

import random
import time

import pytest

from ipa_analyzer.formats import magic_scan as ms


def chunked(data: bytes, size: int):
    for i in range(0, len(data), size):
        yield data[i : i + size]


def offsets(res, pid):
    return [h.offset for h in res.hits if h.pattern == pid]


def test_basic_hits_and_offsets():
    data = b"\x00" * 10 + b"\x1bLua\x53" + b"\x00" * 7 + b"\x1bLJ\x02" + b"BSJB"
    res = ms.scan_stream([data])
    assert offsets(res, "lua_bytecode") == [10]
    assert offsets(res, "luajit_bytecode") == [22]
    assert offsets(res, "cli_metadata_bsjb") == [26]
    assert res.bytes_scanned == len(data) and res.stopped is None
    assert res.counts["lua_bytecode"] == 1


@pytest.mark.parametrize("size", [1, 2, 3, 5, 7, 16, 64, 1000])
def test_hits_identical_for_every_chunking(size):
    rng = random.Random(8)
    filler = bytes(b for b in rng.randbytes(5000) if b not in (0x1B, 0x4D, 0x42))
    data = filler[:900] + b"\x1bLua" + filler[900:2000] + b"\x1bLJ" + filler[2000:2500] + b"scripts/main.lua.bytes\x00" + filler[2500:]
    ref = ms.scan_stream([data])
    got = ms.scan_stream(chunked(data, size))
    assert [(h.pattern, h.offset, h.match) for h in got.hits] == [(h.pattern, h.offset, h.match) for h in ref.hits]
    assert offsets(ref, "lua_bytecode") == [900]
    assert offsets(ref, "script_path") == [2507]
    assert [h.match for h in ref.by_pattern("script_path")] == [b"scripts/main.lua.bytes"]


def test_signature_straddling_chunk_boundary():
    res = ms.scan_stream([b"xxxx\x1bL", b"uayyyy"])
    assert offsets(res, "lua_bytecode") == [4]
    res = ms.scan_stream([b"xx\x1b", b"L", b"J", b"zz"])
    assert offsets(res, "luajit_bytecode") == [2]
    res = ms.scan_stream([b"..BS", b"JB.."])
    assert offsets(res, "cli_metadata_bsjb") == [2]


def test_no_duplicate_hits_in_overlap():
    data = b"\x1bLua" * 3
    for size in (1, 3, 4, 5, 11):
        res = ms.scan_stream(chunked(data, size))
        assert offsets(res, "lua_bytecode") == [0, 4, 8]


def test_overlapping_literal_occurrences():
    pats = [ms.literal("aa", b"aa")]
    assert offsets(ms.scan_stream([b"aaaa"], pats), "aa") == [0, 1, 2]
    assert offsets(ms.scan_stream(chunked(b"aaaa", 1), pats), "aa") == [0, 1, 2]


def test_script_path_regex_shapes():
    text = b"x Assets/Lua/game.lua\0 a/b.dll.bytes\0 conf.js.txt\0 data.json\0 x.luax\0 ok.js,"
    res = ms.scan_stream([text])
    found = [h.match for h in res.by_pattern("script_path")]
    assert b"Assets/Lua/game.lua" in found
    assert b"a/b.dll.bytes" in found
    assert b"conf.js.txt" in found
    assert b"ok.js" in found
    assert not any(m.startswith(b"data.js") or m.startswith(b"x.lua") for m in found)


def test_regex_match_split_across_chunks_is_reported_whole():
    res = ms.scan_stream([b"pre scripts/ma", b"in.lua.by", b"tes tail"])
    assert [h.match for h in res.by_pattern("script_path")] == [b"scripts/main.lua.bytes"]


def test_context_snippet_bounds():
    data = b"A" * 40 + b"\x1bLua" + b"B" * 100
    hit = ms.scan_stream([data]).hits[0]
    assert hit.context.startswith(b"A" * 16 + b"\x1bLua") and len(hit.context) <= 16 + 4 + 48
    short = ms.scan_stream([b"\x1bLua"]).hits[0]
    assert short.context == b"\x1bLua"
    big = ms.scan_stream([b"\x1bLua" + b"c" * 1000], context_after=10).hits[0]
    assert len(big.context) <= 16 + 4 + 10


def test_max_hits():
    data = b"\x1bLua" * 100
    res = ms.scan_stream(chunked(data, 33), max_hits=7)
    assert len(res.hits) == 7 and res.stopped == "max_hits"
    res2 = ms.scan_stream([data], max_hits_per_pattern=3)
    assert len(res2.by_pattern("lua_bytecode")) == 3


def test_max_bytes_stops_and_truncates_last_chunk():
    data = b"." * 100 + b"\x1bLua" + b"." * 100 + b"\x1bLua"
    res = ms.scan_stream(chunked(data, 50), max_bytes=150)
    assert res.stopped == "max_bytes" and res.bytes_scanned == 150
    assert offsets(res, "lua_bytecode") == [100]
    res = ms.scan_stream(chunked(data, 50), max_bytes=10_000)
    assert res.stopped is None and len(res.hits) == 2


def test_max_bytes_cuts_signature_in_half():
    res = ms.scan_stream([b"..\x1bLu", b"a"], max_bytes=5)
    assert res.hits == []


def test_timeout():
    def slow():
        for _ in range(100):
            time.sleep(0.01)
            yield b"abc"

    start = time.monotonic()
    res = ms.scan_stream(slow(), max_seconds=0.05)
    assert res.stopped == "timeout" and time.monotonic() - start < 1


def test_callback_can_stop_and_observes_hits():
    seen = []

    def cb(hit):
        seen.append(hit.offset)
        return len(seen) >= 2

    res = ms.scan_stream([b"\x1bLua" * 10], on_hit=cb)
    assert seen == [0, 4] and res.stopped == "callback" and len(res.hits) == 2


def test_empty_inputs_and_pattern_validation():
    assert ms.scan_stream([]).hits == []
    assert ms.scan_stream([b"", b""]).bytes_scanned == 0
    assert ms.scan_stream([b"abc"], []).hits == []
    with pytest.raises(ValueError):
        ms.SigPattern("x")
    with pytest.raises(ValueError):
        ms.literal("x", b"")
    with pytest.raises(ValueError):
        ms.regex("x", b"a+", 0)


def test_large_stream_is_linear_enough():
    chunk = b"\x00" * (1 << 20)
    start = time.monotonic()
    res = ms.scan_stream((chunk for _ in range(32)), ms.SCRIPT_SIGNATURES, max_bytes=64 << 20)
    assert res.bytes_scanned == 32 << 20 and res.hits == []
    assert time.monotonic() - start < 10


def test_noisy_flag_on_mz():
    assert [p.noisy for p in ms.SCRIPT_SIGNATURES if p.id == "pe_mz"] == [True]
    res = ms.scan_stream([b"..MZ\x90\x00..This program cannot be run in DOS mode.."])
    assert offsets(res, "pe_mz") == [2] and len(res.by_pattern("pe_dos_stub")) == 1
