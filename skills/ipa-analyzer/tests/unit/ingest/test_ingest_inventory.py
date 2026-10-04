from __future__ import annotations

import json
import os
import time
import zlib
from pathlib import Path

import pytest

from fixtures.ipa_builder import ZipBuilder, build_ipa
from ipa_analyzer import pipeline
from ipa_analyzer.analyzers import inventory as inv_mod
from ipa_analyzer.analyzers.ingest_stage import IngestStage
from ipa_analyzer.analyzers.inventory import InventoryStage, build_inventory, list_categories, select_for_split
from ipa_analyzer.config import EXTRACT_CATEGORIES, Config, LimitsConfig
from ipa_analyzer.context import AnalysisContext
from ipa_analyzer.errors import InvalidInput, LimitExceeded
from ipa_analyzer.ingest.source import DirSource, ZipSource
from ipa_analyzer.models import Status

MACHO = b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01\x00\x00\x00\x00\x02\x00\x00\x00" + b"\0" * 64
DYLIB_MACHO = b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01\x00\x00\x00\x00\x06\x00\x00\x00" + b"\0" * 64
APP_FILES = {
    "Info.plist": b"bplist00" + b"\0" * 40, "Foo": MACHO, "Frameworks/UnityFramework.framework/UnityFramework": DYLIB_MACHO,
    "Frameworks/UnityFramework.framework/Info.plist": b"bplist00" + b"\0" * 40,
    "Frameworks/libfoo.dylib": DYLIB_MACHO, "PlugIns/Share.appex/Share": MACHO, "Watch/W.app/W": MACHO,
    "Watch/W.app/Info.plist": b"bplist00",
    "Assets.car": b"BOMStore" + b"\0" * 20, "Data/Managed/Metadata/global-metadata.dat": b"\xaf\x1b\xb1\xfa" + os.urandom(6000),
    "Data/Raw/ab/b.dat": b"UnityFS\0" + b"\0" * 5000, "Data/level0": os.urandom(10_000), "Data/data.pak": os.urandom(5000),
    "icon.png": b"\x89PNG\r\n\x1a\n" + b"\0" * 100, "en.lproj/Localizable.strings": b"bplist00", "zh-Hans.lproj/InfoPlist.strings": b"x",
    "Base.lproj/Main.storyboardc/Info.plist": b"bplist00", "Base.lproj/Main.storyboardc/A.nib": b"NIBArchive" + b"\0" * 30,
    "Res.bundle/x.png": b"\x89PNG\r\n\x1a\n", "_CodeSignature/CodeResources": b"<?xml version='1.0'?><plist/>",
    "embedded.mobileprovision": b"0\x82", "SC_Info/Foo.sinf": b"s", "clip.mp4": b"\0\0\0\x18ftypmp42\0\0\0\0",
    "font.ttf": b"\x00\x01\x00\x00\x00\x11\x01\x00", "x.metallib": b"MTLB\x01\x80\x02\0", "script.lua": "print('x')\n" * 400,
    "b.luac": b"\x1bLuaS\0\x19\x93", "readme.txt": "hello",
}
RAW = {"iTunesMetadata.plist": b"bplist00xx"}


def _ctx(tmp_path, ipa, **cfg):
    return AnalysisContext(Config(output_dir=tmp_path / "out", **cfg), ipa)


def _run(ctx):
    r1 = IngestStage().run(ctx)
    ctx.results["ingest"] = r1.data
    r2 = InventoryStage().run(ctx)
    ctx.results["inventory"] = r2.data
    return r1, r2


@pytest.fixture()
def sample_ipa(tmp_path):
    return build_ipa(tmp_path / "Sample.ipa", APP_FILES, app_name="Foo", raw_files=RAW)


def test_ingest_result_shape_and_binding(tmp_path, sample_ipa):
    ctx = _ctx(tmp_path, sample_ipa)
    r1 = IngestStage().run(ctx)
    d = r1.data
    assert r1.status == Status.OK
    assert d["kind"] == "ipa" and d["app_root"] == "Payload/Foo.app/" and d["app_name_dir"] == "Foo.app"
    assert d["size"] == sample_ipa.stat().st_size and len(d["sha256"]) == 64 and d["entries"] > 10
    import hashlib
    assert d["sha256"] == hashlib.sha256(sample_ipa.read_bytes()).hexdigest()
    assert ctx.is_bound and ctx.out_dir.name == "Sample-" + d["sha256"][:12] and ctx.app_root == d["app_root"]
    assert ctx.source is not None
    ctx.close()


def test_ingest_directory_inputs(tmp_path, sample_ipa):
    import zipfile
    ex = tmp_path / "ex"
    zipfile.ZipFile(sample_ipa).extractall(ex)
    ctx = _ctx(tmp_path, ex)
    d = IngestStage().run(ctx).data
    assert d["kind"] == "payload_dir" and d["app_root"] == "Payload/Foo.app/"
    sha_a = d["sha256"]
    ctx.close()
    ctx = _ctx(tmp_path, ex / "Payload" / "Foo.app")
    d = IngestStage().run(ctx).data
    assert d["kind"] == "app_dir" and d["app_root"] == "" and d["app_name_dir"] == "Foo.app"
    ctx.close()
    ctx = _ctx(tmp_path, ex)                    # tree digest is deterministic
    assert IngestStage().run(ctx).data["sha256"] == sha_a
    ctx.close()


@pytest.mark.parametrize("builder,match", [
    (lambda p: p.write_bytes(b""), "empty"),
    (lambda p: p.write_bytes(b"hello hello hello hello"), "unsupported"),
    (lambda p: build_ipa(p, {"x": b"1"}, payload=False), "no iOS application bundle"),
    (lambda p: p.write_bytes(__import__("fixtures.ipa_builder", fromlist=["x"]).build_zip_bytes({})), "no files"),
    (lambda p: p.write_bytes(build_ipa(p, {"x": b"1"}).read_bytes()[:-30]), "zip"),
])
def test_ingest_invalid_inputs(tmp_path, builder, match):
    p = tmp_path / "bad.ipa"
    builder(p)
    ctx = _ctx(tmp_path, p)
    with pytest.raises(InvalidInput, match=match):
        IngestStage().run(ctx)
    ctx.close()


def test_ingest_missing_path(tmp_path):
    ctx = _ctx(tmp_path, tmp_path / "nope.ipa")
    with pytest.raises(InvalidInput):
        IngestStage().run(ctx)


def test_ingest_zip_bomb_hits_limits(tmp_path):
    zb = ZipBuilder()
    zb.add("Payload/A.app/Info.plist", b"x")
    zb.add("Payload/A.app/zeros.bin", b"\0" * 8_000_000)           # ~8 KB compressed
    p = tmp_path / "bomb.ipa"
    p.write_bytes(zb.finish())
    ctx = _ctx(tmp_path, p)
    ctx.cfg.limits = LimitsConfig(max_file_size=1_000_000, max_ratio=50.0)
    with pytest.raises(LimitExceeded, match="bomb"):
        IngestStage().run(ctx)
    # with default limits the same archive is analysable (a big zero file is not by itself hostile)
    ctx = _ctx(tmp_path, p)
    assert IngestStage().run(ctx).status == Status.OK
    ctx.close()
    ctx = _ctx(tmp_path, p)
    ctx.cfg.limits = LimitsConfig(max_files=1)
    with pytest.raises(LimitExceeded):
        IngestStage().run(ctx)


def test_ingest_warnings_for_hostile_names(tmp_path):
    p = build_ipa(tmp_path / "h.ipa", {"Info.plist": b"x", "a.TXT": b"1", "A.txt": b"2"},
                  raw_files={"../evil": b"x", "/abs": b"y"})
    ctx = _ctx(tmp_path, p)
    r = IngestStage().run(ctx)
    assert r.status == Status.OK
    assert any("unsafe" in w for w in r.data["warnings"]) and any("differ only by case" in w for w in r.data["warnings"])
    ctx.close()


def test_inventory_stage_end_to_end(tmp_path, sample_ipa):
    ctx = _ctx(tmp_path, sample_ipa)
    r1, r2 = _run(ctx)
    assert r2.status == Status.OK
    d = r2.data
    by_name = {f["path"]: f for f in d["files"]}
    P = "Payload/Foo.app/"
    assert d["files_total"] == len(d["files"]) == len(by_name) and d["files_truncated"] is False
    assert [f["path"] for f in d["files"]] == sorted(by_name)
    cats = {p[len(P):] if p.startswith(P) else p: f["category"] for p, f in by_name.items()}
    expected = {
        "Foo": "executable", "Frameworks/UnityFramework.framework/UnityFramework": "framework",
        "Frameworks/UnityFramework.framework/Info.plist": "plist", "Frameworks/libfoo.dylib": "dylib",
        "PlugIns/Share.appex/Share": "plugin", "Watch/W.app/W": "plugin", "Assets.car": "assets_car",
        "Data/Managed/Metadata/global-metadata.dat": "engine_data", "Data/Raw/ab/b.dat": "assetbundle",
        "Data/level0": "engine_data", "Data/data.pak": "packed_archive", "icon.png": "image",
        "en.lproj/Localizable.strings": "localization", "Base.lproj/Main.storyboardc/A.nib": "ui_layout",
        "Base.lproj/Main.storyboardc/Info.plist": "ui_layout", "Res.bundle/x.png": "image",
        "_CodeSignature/CodeResources": "signing", "embedded.mobileprovision": "signing", "SC_Info/Foo.sinf": "signing",
        "clip.mp4": "video", "font.ttf": "font", "x.metallib": "shader", "script.lua": "script", "b.luac": "script",
        "readme.txt": "text", "Info.plist": "plist", "iTunesMetadata.plist": "signing",
    }
    for k, v in expected.items():
        assert cats[k] == v, k
    assert by_name[P + "Data/Raw/ab/b.dat"]["magic"] == "unityfs"
    assert by_name[P + "Foo"]["magic"] == "macho" and by_name[P + "Data/level0"]["ext"] == ""
    assert by_name[P + "Foo"]["ext"] == "" and by_name[P + "icon.png"]["ext"] == ".png"
    assert "entropy" in by_name[P + "Data/level0"] and by_name[P + "Data/level0"]["entropy"] > 7.5
    assert "entropy" not in by_name[P + "Foo"]                       # < 4 KiB
    assert by_name[P + "script.lua"]["entropy"] < 4.0
    # aggregates
    assert sum(c["count"] for c in d["by_category"]) == d["files_total"]
    assert sum(c["size"] for c in d["by_category"]) == d["total_size"]
    assert [c["size"] for c in d["by_category"]] == sorted((c["size"] for c in d["by_category"]), reverse=True)
    assert abs(sum(c["percent"] for c in d["by_category"]) - 100) < 0.5
    assert [t["size"] for t in d["top_files"]] == sorted((t["size"] for t in d["top_files"]), reverse=True)
    assert d["localizations"] == ["Base", "en", "zh-Hans"]
    assert {a["path"][len(P):] for a in d["archives"]} == {"Data/data.pak"}
    units = {u["rel"]: u for u in d["nested_units"]}
    assert units["Frameworks/UnityFramework.framework"]["kind"] == "framework"
    assert units["Frameworks/UnityFramework.framework"]["file_count"] == 2
    assert units["Frameworks/UnityFramework.framework"]["path"] == P + "Frameworks/UnityFramework.framework"
    assert units["PlugIns/Share.appex"]["kind"] == "appex" and units["Watch/W.app"]["kind"] == "watch_app"
    assert units["Res.bundle"]["kind"] == "bundle" and units["Frameworks/libfoo.dylib"]["kind"] == "dylib"
    hints = d["structure_hints"]
    assert set(hints["top_level_dirs"]) >= {"Frameworks", "PlugIns", "Watch", "SC_Info", "_CodeSignature", "Data"}
    assert hints["has"] == {"Frameworks": True, "PlugIns": True, "Watch": True, "SC_Info": True, "_CodeSignature": True,
                            "Data": True, "Assets_car": True, "embedded_mobileprovision": True,
                            "iTunesMetadata_plist": True}
    tree = d["tree"]
    assert tree["name"] == "Foo.app" and tree["size"] > 0
    top = {c["name"]: c for c in tree["children"]}
    assert top["Frameworks"]["children"][0]["name"] in ("UnityFramework.framework", "libfoo.dylib")
    # inventory.json holds the full table and is registered as an artifact
    full = json.loads((ctx.out_dir / "inventory.json").read_text(encoding="utf-8"))
    assert len(full["files"]) == d["files_total"] and ctx.artifacts["inventory.json"] == "inventory.json"
    assert [f.id for f in r2.findings] == ["inventory.summary"]
    json.dumps(d)
    ctx.close()


def test_tree_depth_aggregates_deeper_levels(tmp_path):
    p = build_ipa(tmp_path / "t.ipa", {"a/b/c/d/e.bin": b"12345", "a/b/c/f.bin": b"123", "a/g": b"1"}, app_name="T")
    src = ZipSource(p)
    t = build_inventory(src, "Payload/T.app/", root_name="T.app", tree_depth=3)["tree"]
    a = t["children"][0]
    b = a["children"][0]
    c = next(x for x in b["children"])
    assert (a["name"], b["name"], c["name"]) == ("a", "b", "c") and c["size"] == 8 and c["count"] == 2
    assert c["children"] == []                                          # depth 3 reached: aggregated
    assert t["size"] == 9 and t["count"] == 3
    src.close()


def test_dir_and_zip_sources_give_identical_inventory(tmp_path, sample_ipa):
    import zipfile
    ex = tmp_path / "ex"
    zipfile.ZipFile(sample_ipa).extractall(ex)
    zs, ds = ZipSource(sample_ipa), DirSource(ex)
    a = build_inventory(zs, "Payload/Foo.app/", root_name="Foo.app")
    b = build_inventory(ds, "Payload/Foo.app/", root_name="Foo.app")
    for f in a["files"] + b["files"]:
        f.pop("csize")
    assert a == b
    zs.close()


def test_sniffing_reads_only_headers(tmp_path):
    big = os.urandom(3_000_000)
    p = build_ipa(tmp_path / "big.ipa", {"Info.plist": b"bplist00", "big.bin": big, "Data/b.dat": b"UnityFS\0" + big}, app_name="B")
    inner = ZipSource(p)
    reads = {}

    class Counting:
        kind = "zip"
        path = inner.path

        def namelist(self):
            return inner.namelist()

        def read_head(self, name, n):
            data = inner.read_head(name, n)
            reads[name] = reads.get(name, 0) + len(data)
            return data

        def open(self, name):
            raise AssertionError("inventory must not open entries")

    inv = build_inventory(Counting(), "Payload/B.app/", root_name="B.app")  # type: ignore[arg-type]
    assert reads["Payload/B.app/big.bin"] <= 64 * 1024 and reads["Payload/B.app/Data/b.dat"] <= 64 * 1024
    f = {x["path"]: x for x in inv["files"]}
    assert f["Payload/B.app/big.bin"]["entropy"] > 7.9 and f["Payload/B.app/Data/b.dat"]["magic"] == "unityfs"
    inner.close()


def test_entropy_budget_is_bounded_and_reported(tmp_path):
    p = build_ipa(tmp_path / "e.ipa", {"f%02d.bin" % i: os.urandom(20_000) for i in range(10)}, app_name="E")
    src = ZipSource(p)
    inv = build_inventory(src, "Payload/E.app/", root_name="E.app", entropy_byte_budget=50_000)
    info = inv["entropy_info"]
    assert info["sampled_files"] == 3 and info["skipped_files"] == 7 and info["budget_exhausted"]
    assert sum("entropy" in f for f in inv["files"]) == 3
    src.close()


def test_unreadable_entry_does_not_break_inventory(tmp_path):
    zb = ZipBuilder()
    zb.add("Payload/A.app/Info.plist", b"bplist00")
    zb.add("Payload/A.app/bad.png", b"x" * 100, comp_data=b"\xffgarbage", method=8)
    zb.add("Payload/A.app/ok.txt", b"hello")
    p = tmp_path / "u.ipa"
    p.write_bytes(zb.finish())
    ctx = _ctx(tmp_path, p)
    r1, r2 = _run(ctx)
    assert r2.status == Status.OK and r2.data["read_errors"]["count"] == 1
    assert any("could not be read" in w for w in r2.warnings)
    bad = next(f for f in r2.data["files"] if f["path"].endswith("bad.png"))
    assert bad["magic"] == "unreadable" and bad["category"] == "image"
    ctx.close()


def test_ten_thousand_files_is_fast(tmp_path):
    files = {"res/d%02d/f%05d.%s" % (i % 50, i, ("png", "json", "bin", "lua")[i % 4]): (b"\x89PNG\r\n\x1a\n" if i % 4 == 0 else b"{}") + bytes(i % 5000)
             for i in range(10_000)}
    p = build_ipa(tmp_path / "many.ipa", files, app_name="M")
    ctx = _ctx(tmp_path, p)
    t0 = time.perf_counter()
    r1, r2 = _run(ctx)
    elapsed = time.perf_counter() - t0
    assert r2.data["files_total"] == 10_000 and elapsed < 5.0, elapsed
    ctx.close()


def test_inline_truncation_keeps_full_table_in_file(tmp_path, monkeypatch):
    monkeypatch.setattr(inv_mod, "INLINE_FILES_LIMIT", 5)
    p = build_ipa(tmp_path / "t.ipa", {"f%d" % i: b"x" for i in range(12)}, app_name="T")
    ctx = _ctx(tmp_path, p)
    r1, r2 = _run(ctx)
    assert len(r2.data["files"]) == 5 and r2.data["files_truncated"] is True and r2.data["files_total"] == 12
    from ipa_analyzer.util.filetypes import load_inventory_files
    assert len(load_inventory_files(r2.data, ctx.out_dir)) == 12
    ctx.close()


def test_split_extraction(tmp_path, sample_ipa):
    ctx = _ctx(tmp_path, sample_ipa, extract=("binary", "frameworks", "metadata", "bundles", "plists"))
    r1, r2 = _run(ctx)
    assert r2.status == Status.OK, r2.warnings
    sp = r2.data["split"]
    root = ctx.out_dir / "split"
    assert (root / "binary" / "Foo").is_file() and not (root / "binary" / "Frameworks").exists()
    assert (root / "frameworks" / "Frameworks" / "UnityFramework.framework" / "UnityFramework").is_file()
    assert (root / "frameworks" / "Frameworks" / "libfoo.dylib").is_file()
    assert (root / "metadata" / "Data" / "Managed" / "Metadata" / "global-metadata.dat").is_file()
    assert (root / "metadata" / "Info.plist").is_file() and (root / "metadata" / "_archive" / "iTunesMetadata.plist").is_file()
    assert (root / "bundles" / "Data" / "Raw" / "ab" / "b.dat").is_file() and (root / "bundles" / "Res.bundle" / "x.png").is_file()
    assert (root / "plists" / "Info.plist").is_file()
    assert sp["binary"]["files"] >= 1 and all(v["errors"] == 0 for v in sp.values())
    assert (root / "binary.manifest.json").is_file()
    ctx.close()
    # second run reuses everything
    ctx = _ctx(tmp_path, sample_ipa, extract=("binary",))
    _, r2 = _run(ctx)
    assert r2.data["split"]["binary"]["files"] >= 1
    ctx.close()


def test_split_all_and_limits(tmp_path, sample_ipa):
    ctx = _ctx(tmp_path, sample_ipa, extract=("all",))
    ctx.results["ingest"] = IngestStage().run(ctx).data
    ctx.cfg.limits = LimitsConfig(max_files=5)       # applies to extraction only (ingest already passed)
    r2 = InventoryStage().run(ctx)
    assert r2.status == Status.PARTIAL and r2.data["split"]["all"]["files"] == 5 and r2.data["split"]["all"]["errors"] > 0
    ctx.close()


def test_select_for_split_and_list_categories():
    assert list_categories() == tuple(EXTRACT_CATEGORIES)
    files = [{"path": "P/A.app/Foo", "category": "executable", "magic": "macho"},
             {"path": "P/A.app/x/global-metadata.dat", "category": "engine_data", "magic": "unknown"}]
    assert select_for_split("binary", files, "P/A.app/", []) == ["P/A.app/Foo"]
    assert select_for_split("metadata", files, "P/A.app/", []) == ["P/A.app/x/global-metadata.dat"]
    assert len(select_for_split("all", files, "P/A.app/", [])) == 2
    with pytest.raises(ValueError):
        select_for_split("nope", files, "", [])


def test_full_pipeline_with_stub_downstream(tmp_path, sample_ipa):
    cfg = Config(output_dir=tmp_path / "out", stages=("inventory",))
    ctx = AnalysisContext(cfg, sample_ipa)
    pipeline.run(ctx)
    assert ctx.stage_status("ingest") == Status.OK and ctx.stage_status("inventory") == Status.OK
    assert ctx.results["inventory"]["files_total"] > 20
    rep = pipeline.build_report(ctx)
    assert rep.input["sha256"] == ctx.results["ingest"]["sha256"]
    assert rep.resources["by_category"] and rep.structure["tree"]["name"] == "Foo.app"
    ctx.close()


def test_directory_input_through_stages(tmp_path, sample_ipa):
    import zipfile
    ex = tmp_path / "ex"
    zipfile.ZipFile(sample_ipa).extractall(ex)
    ctx_z = _ctx(tmp_path, sample_ipa)
    _, rz = _run(ctx_z)
    ctx_d = _ctx(tmp_path, ex)
    _, rd = _run(ctx_d)
    for key in ("by_category", "by_ext", "top_files", "localizations", "archives", "nested_units", "tree",
                "structure_hints", "files_total", "total_size"):
        assert rz.data[key] == rd.data[key], key
    ctx_z.close()
    ctx_d.close()


# --- R1 regressions -----------------------------------------------------------------------------------
def _custom_container_files(n=60):
    files = {"Info.plist": b"bplist00" + b"\0" * 40, "Foo": MACHO}
    for i in range(n):
        files["res/a%03d.json" % i] = b"NHPK" + os.urandom(40)          # extension says json, content is not
    for i in range(n // 2):
        files["res/t%03d.png" % i] = b"NHPT" + os.urandom(40)
    for i in range(55):
        files["res/b%03d.png" % i] = b"\x89PNG\r\n\x1a\n" + b"\0" * 20  # genuine PNGs: not a mismatch
    files["res/odd.json"] = b"QQQQ" + b"\0" * 8                         # a lone odd header stays below the threshold
    files["res/text.json"] = b'{"a": 1}'
    return files


def test_header_clusters_report_extension_content_mismatch(tmp_path):
    ipa = build_ipa(tmp_path / "c.ipa", _custom_container_files(), app_name="Foo")
    src = ZipSource(ipa)
    inv = build_inventory(src, "Payload/Foo.app/", root_name="Foo.app")
    hc = inv["header_clusters"]
    assert hc[0]["head_hex"] == b"NHPK".hex() and hc[0]["head_ascii"] == "NHPK" and hc[0]["count"] == 60
    assert hc[0]["exts"] == {".json": 60} and 0 < len(hc[0]["examples"]) <= 5
    assert hc[0]["examples"] == sorted(hc[0]["examples"]) and hc[0]["size"] == 60 * 44
    assert all(e.startswith("Payload/Foo.app/res/a") for e in hc[0]["examples"])
    assert len(hc) == 1                                   # 30 NHPT files / 1 odd file are below the threshold of 50
    assert inv["ext_magic_mismatch"]["files"] == 60 + 30 + 1
    src.close()


def test_header_cluster_threshold_is_configurable(tmp_path):
    ipa = build_ipa(tmp_path / "c.ipa", _custom_container_files(), app_name="Foo")
    src = ZipSource(ipa)
    inv = build_inventory(src, "Payload/Foo.app/", header_cluster_min=10)
    assert [(c["head_ascii"], c["count"]) for c in inv["header_clusters"]] == [("NHPK", 60), ("NHPT", 30)]
    assert inv["header_clusters"][1]["exts"] == {".png": 30}
    src.close()


def test_no_clusters_for_ordinary_apps(sample_ipa):
    inv = build_inventory(ZipSource(sample_ipa), "Payload/Foo.app/")
    assert inv["header_clusters"] == [] and inv["ext_magic_mismatch"]["files"] == 0


def _poison_hoff(data: bytes, name: bytes, hoff: int) -> bytes:
    """Give the central-directory record of ``name`` a zip64 local header offset ``hoff``."""
    import struct
    eocd = data.rfind(b"PK\x05\x06")
    cd_size, cd_off = struct.unpack_from("<LL", data, eocd + 12)
    cd = data[cd_off:cd_off + cd_size]
    out, pos = bytearray(), 0
    while pos < len(cd):
        nlen, elen, clen = struct.unpack_from("<HHH", cd, pos + 28)
        rec = bytearray(cd[pos:pos + 46 + nlen + elen + clen])
        if bytes(rec[46:46 + nlen]) == name:
            extra = struct.pack("<HHQ", 1, 8, hoff)
            struct.pack_into("<L", rec, 42, 0xFFFFFFFF)
            struct.pack_into("<H", rec, 30, elen + len(extra))
            rec[46 + nlen + elen:46 + nlen + elen] = extra
        out += rec
        pos += 46 + nlen + elen + clen
    tail = bytearray(data[eocd:])
    struct.pack_into("<L", tail, 12, len(out))
    return data[:cd_off] + bytes(out) + bytes(tail)


def test_one_malformed_entry_does_not_fail_inventory_or_extraction(tmp_path):
    ipa = build_ipa(tmp_path / "m.ipa", {"Info.plist": b"bplist00" + b"\0" * 40, "Foo": MACHO, "evil.bin": b"z" * 200},
                    app_name="Foo", compress=False)
    ipa.write_bytes(_poison_hoff(ipa.read_bytes(), b"Payload/Foo.app/evil.bin", 2 ** 63 + 5))
    ctx = _ctx(tmp_path, ipa)
    r1, r2 = _run(ctx)
    assert r1.status == Status.OK and r2.status == Status.OK, r2.error
    files = {f["path"]: f for f in r2.data["files"]}
    assert files["Payload/Foo.app/evil.bin"]["magic"] == "unreadable"
    assert files["Payload/Foo.app/Foo"]["magic"] == "macho"
    assert r2.data["read_errors"]["count"] == 1
    got = ctx.extract(["Payload/Foo.app/evil.bin", "Payload/Foo.app/Foo"])
    assert list(got) == ["Payload/Foo.app/Foo"]
    assert any("evil.bin" in w for w in ctx.warnings)
    ctx.close()
