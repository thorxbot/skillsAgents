from __future__ import annotations

import io
import random
import struct
import time

import pytest

from fixtures import formats_builder as fb
from fixtures import unity_hotfix_builder as ub
from ipa_analyzer.unity.hotfix import detect, storage

RULES = detect.load_rules()


class MemSource:
    """Minimal ArchiveSource double over a dict of bytes."""

    def __init__(self, files):
        self.files = files

    def read_head(self, name, n):
        return self.files[name][:n]

    def open(self, name):
        return io.BytesIO(self.files[name])


def src(**files):
    return MemSource({k.replace("__", "/"): v for k, v in files.items()})


def rows(paths, magic=""):
    return [{"path": p, "size": 100, "magic": magic, "category": "other"} for p in paths]


def disc(paths, **kw):
    return storage.discover(rows(paths), lambda p: p, RULES, **kw)


def test_discover_loose_candidates_by_extension_and_dir():
    d = disc(["Data/Raw/Lua/main.lua", "Data/Raw/a.lua.bytes", "Data/Raw/b.luac", "Data/Raw/HotUpdate.dll.bytes", "Data/Raw/x.mjs",
              "Data/Raw/lua/helper.bytes", "Data/Raw/other/data.bytes", "Data/Raw/plain.png", "Data/Raw/lua.png",
              "Data/Managed/Assembly-CSharp.dll", "Data/Managed/Foo.dll.bytes"])
    assert sorted(i["path"] for i in d.loose["lua"]) == ["Data/Raw/Lua/main.lua", "Data/Raw/a.lua.bytes", "Data/Raw/b.luac", "Data/Raw/lua/helper.bytes"]
    assert sorted(i["path"] for i in d.loose["dll"]) == ["Data/Managed/Foo.dll.bytes", "Data/Raw/HotUpdate.dll.bytes"]
    assert [i["path"] for i in d.loose["js"]] == ["Data/Raw/x.mjs"]
    assert d.managed_dlls == ["Data/Managed/Assembly-CSharp.dll"]
    assert [i["path"] for i in d.bytes_sniff] == ["Data/Raw/other/data.bytes"]


def test_png_named_lua_is_not_a_script_candidate():
    d = disc(["Data/Raw/lua.png", "Data/Raw/lua_icon.png", "Data/Raw/lua/readme.png"])
    assert d.loose == {"lua": [], "dll": [], "js": []} and d.bundles == []


def test_sdk_scripts_are_excluded_but_counted():
    d = disc(["Frameworks/SDK.framework/script.js", "Res.bundle/omsdk.js", "UnityAdsResources.bundle/x.js", "Data/Raw/game.mjs",
              "Frameworks/A.framework/b.lua", "top/level.js"])
    assert [i["path"] for i in d.loose["js"]] == ["Data/Raw/game.mjs"]
    assert d.excluded["js"] >= 3 and d.excluded.get("lua") == 1


def test_bundle_and_serialized_discovery():
    d = disc(["Data/Raw/a.bundle", "Data/Raw/b.b", "Data/Raw/c.unity3d", "Data/resources.assets", "Data/sharedassets0.assets",
              "Data/level0", "Data/globalgamemanagers", "Data/sharedassets0.assets.resS", "Data/Raw/pic.bundle"], )
    assert [b["path"] for b in d.bundles] == ["Data/Raw/a.bundle", "Data/Raw/b.b", "Data/Raw/c.unity3d", "Data/Raw/pic.bundle"]
    assert len(d.serialized) == 4
    r = rows(["Data/Raw/x.dat"], magic="unityfs")
    assert [b["path"] for b in storage.discover(r, lambda p: p, RULES).bundles] == ["Data/Raw/x.dat"]


def test_extra_bundle_paths_used_when_given():
    d = storage.discover([], lambda p: p, RULES, extra_bundle_paths=["Data/Raw/z.dat", "Data/Raw/y.dat"])
    assert [b["path"] for b in d.bundles] == ["Data/Raw/y.dat", "Data/Raw/z.dat"]


def test_pick_sample_is_deterministic_even_and_bounded():
    items = [{"path": "p%03d" % i} for i in range(250)]
    s = storage.pick_sample(items, 100)
    assert len(s) == 100 and s == storage.pick_sample(items, 100)
    assert s[0]["path"] == "p000" and s[-1]["path"] >= "p240"
    assert storage.pick_sample(items, 1000) == items and storage.pick_sample(items, 0) == []


def test_load_loose_blob_reads_head_and_small_dll():
    dll = fb.build_pe_cli("HotUpdate", ["mscorlib"], types=1)
    s = src(a__dll=dll, b__lua=b"print(1)")
    b = storage.load_loose_blob(s, {"path": "a/dll", "size": len(dll)}, "dll")
    assert b.data == dll and b.kind == "dll" and b.name == "dll"
    b = storage.load_loose_blob(s, {"path": "b/lua", "size": 8}, "lua")
    assert b.sample == b"print(1)" and b.data is None


def bundle_info(name="Data/Raw/x.bundle"):
    return {"path": name, "size": 0}


@pytest.mark.parametrize("compression", ["none", "lz4", "lzma"])
def test_scan_bundle_finds_lua_dll_and_names(compression):
    lua = fb.build_lua_bytecode("5.3") + b"payload"
    pe = fb.build_pe_cli("HotUpdate", ["UnityEngine.CoreModule", "mscorlib"], types=4)
    data = ub.build_bundle([ub.textasset("Main.lua", lua), ub.textasset("HotUpdate.dll", pe)], compression=compression,
                           container_paths=["assets/lua/Main.lua.bytes", "assets/hot/HotUpdate.dll.bytes", "assets/x/app.js"])
    cs = storage.scan_bundle(src(Data__Raw__x_bundle=data), bundle_info("Data/Raw/x_bundle"), max_bytes=1 << 26)
    assert cs.status == "ok" and cs.unity_version.startswith("2021.3")
    kinds = sorted((b.kind, b.name) for b in cs.blobs)
    assert ("lua", "Main.lua") in kinds and ("dll", "HotUpdate.dll") in kinds
    dll = next(b for b in cs.blobs if b.kind == "dll")
    assert dll.data == pe
    assert cs.script_names["lua"] and any(n.endswith("Main.lua.bytes") for n in cs.script_names["lua"])
    assert cs.script_name_counts["js"] == 1 and cs.script_names["dll"]


def test_scan_bundle_luajit_and_lua_text_hints():
    plain = ("local function f()\n  local x = require(\"mod\")\nend\n" * 4).encode()
    data = ub.build_bundle([ub.textasset("a.lua", fb.build_lua_bytecode("luajit2.1") + b"x"), ub.textasset("b.lua", plain)])
    cs = storage.scan_bundle(src(b=data), bundle_info("b"), max_bytes=1 << 26)
    assert any(b.kind == "lua" and b.head[:3] == b"\x1bLJ" for b in cs.blobs)
    assert cs.lua_text_hits >= 8


def test_false_signature_hits_in_noise_are_rejected():
    rng = random.Random(3)
    noise = bytearray(rng.randbytes(200_000))
    for i in range(0, 200_000 - 8, 997):                      # sprinkle bare signatures with no valid header around
        noise[i:i + 3] = b"\x1bLJ" if i % 2 else b"MZ\x90"
    data = fb.build_unityfs([bytes(noise)], compression="lz4")
    cs = storage.scan_bundle(src(b=data), bundle_info("b"), max_bytes=1 << 26)
    assert cs.status in ("ok", "partial") and cs.blobs == [] and cs.rejected_hits > 0


def test_not_unityfs_variants_are_reported_with_a_reason():
    rng = random.Random(1)
    base = ub.build_bundle([b"x" * 100])
    cases = {
        "enc": (rng.randbytes(70_000), "encrypted_suspected"),
        "text": (b"hello world, this is not a bundle\n" * 100, "not_unityfs"),
        "web": (b"UnityWeb\0" + b"\0\0\0\x06" + b"5.x.x\0" + b"2018.4.1f1\0" + b"\0" * 200, "unsupported"),
        "trunc": (base[:60], None),
    }
    for name, (data, want) in cases.items():
        cs = storage.scan_bundle(src(x=data), bundle_info("x"), max_bytes=1 << 20)
        if want:
            assert cs.status == want, (name, cs.status, cs.detail)
        else:
            assert cs.status in ("header_error", "blocks_info_error", "encrypted_suspected", "not_unityfs"), cs.status


def test_block_decompress_failure_is_not_a_crash():
    raw = bytearray(ub.build_bundle([b"y" * 4000, b"z" * 4000], compression="lz4"))
    built = fb.build_unityfs_ex([b"a" * 4000], compression="lz4")
    data = bytearray(built.data)
    for i in range(built.data_offset, built.data_offset + 12):
        data[i] ^= 0xFF
    cs = storage.scan_bundle(src(x=bytes(data)), bundle_info("x"), max_bytes=1 << 20)
    assert cs.status == "block_decompress_failed" and cs.blobs == []
    assert isinstance(raw, bytearray)


def test_huge_declared_sizes_do_not_blow_up():
    built = fb.build_unityfs_ex([b"a" * 4000], compression="lz4")
    data = built.patched(built.size_field_offset, ">q", 1 << 50)
    cs = storage.scan_bundle(src(x=data), bundle_info("x"), max_bytes=1 << 20)
    assert cs.status in ("header_error", "blocks_info_error")
    data = built.patched(built.usize_field_offset, ">I", 0xFFFFFFF0)
    assert storage.scan_bundle(src(x=data), bundle_info("x"), max_bytes=1 << 20).status in ("header_error", "blocks_info_error")


def test_byte_limit_stops_the_scan_and_reports_partial():
    big = fb.build_unityfs([bytes(random.Random(5).randbytes(32768)) for _ in range(40)], compression="lz4")
    t = time.monotonic()
    cs = storage.scan_bundle(src(x=big), bundle_info("x"), max_bytes=100_000)
    assert cs.status == "partial" and cs.stopped == "max_bytes" and cs.bytes_scanned <= 100_000
    assert time.monotonic() - t < 5


def test_single_block_larger_than_limit_is_skipped_with_limit_status():
    data = fb.build_unityfs([bytes(3_000_000)], compression="lzma")
    cs = storage.scan_bundle(src(x=data), bundle_info("x"), max_bytes=1_000_000)
    assert cs.status == "limit"


def test_scan_serialized_finds_signatures():
    pe = fb.build_pe_cli("HotUpdate", ["mscorlib"], types=2)
    blob = ub.serialized_blob([ub.textasset("H.dll", pe), ub.textasset("m.lua", fb.build_lua_bytecode("5.1") + b"zz")],
                              container_paths=["res/a.js.txt"])
    cs = storage.scan_serialized(src(r=blob), {"path": "r"}, max_bytes=1 << 24)
    assert {b.kind for b in cs.blobs} == {"lua", "dll"} and cs.script_name_counts["js"] == 1
    assert next(b for b in cs.blobs if b.kind == "dll").data == pe
