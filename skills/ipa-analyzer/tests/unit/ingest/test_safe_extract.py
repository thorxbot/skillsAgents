from __future__ import annotations

import json
import os
from pathlib import Path, PureWindowsPath

import pytest

from fixtures.ipa_builder import ZipBuilder, build_ipa
from ipa_analyzer.config import Config, LimitsConfig
from ipa_analyzer.context import AnalysisContext
from ipa_analyzer.errors import LimitExceeded, UnsafePath
from ipa_analyzer.ingest import EntryInfo
from ipa_analyzer.ingest.safe_extract import (PathAllocator, SafeExtractor, check_archive_limits, join_within,
                                              map_components, unsafe_reason)
from ipa_analyzer.ingest.source import ZipSource


@pytest.mark.parametrize("name", [
    "../evil", "a/../../evil", "a/..", "..\\evil", "a\\..\\..\\evil", "/etc/passwd", "\\\\server\\share\\x",
    "\\evil", "C:\\Windows\\x", "c:/x", "C:x", "a/b\x00c", "", "./", "//",
])
def test_unsafe_names_rejected(name):
    assert unsafe_reason(name)
    with pytest.raises(UnsafePath):
        map_components(name)


@pytest.mark.parametrize("name,expected", [
    ("Payload/A.app/Info.plist", ["Payload", "A.app", "Info.plist"]),
    ("a/./b//c", ["a", "b", "c"]),
    ("CON.txt", ["_CON.txt"]),
    ("dir/aux", ["dir", "_aux"]),
    ("NUL", ["_NUL"]),
    ("a/COM1.log/x", ["a", "_COM1.log", "x"]),
    ("we<ir>d:name?.txt", ["we_ir_d_name_.txt"]),
    ("trailing. /x", ["trailing", "x"]),
    ("file.txt:stream", ["file.txt_stream"]),
    ("back\\slash.txt", ["back_slash.txt"]),
    ("dots../..x", ["dots", "..x"]),
    ("日本語/ファイル.txt", ["日本語", "ファイル.txt"]),
])
def test_map_components(name, expected):
    if expected is None:
        with pytest.raises(UnsafePath):
            map_components(name)
    else:
        assert map_components(name) == expected


def test_map_components_long_name_truncated_keeping_extension():
    comps = map_components("d/" + "x" * 400 + ".png")
    assert len(comps[1]) == 255 and comps[1].endswith(".png")


@pytest.mark.parametrize("comps,ok", [
    (["a", "b.txt"], True),
    (["..", "evil"], False),
    (["D:\\evil"], False),
    (["\\\\srv\\share"], False),
    (["a", "..", "..", "x"], False),
])
def test_join_within_windows_paths(comps, ok):
    root = PureWindowsPath("C:/out/work")
    if ok:
        assert join_within(root, comps).as_posix().startswith("C:/out/work")
    else:
        with pytest.raises(UnsafePath):
            join_within(root, comps)


def test_allocator_case_conflicts():
    a = PathAllocator()
    assert a.allocate(["Dir", "File.txt"]) == (["Dir", "File.txt"], False)
    assert a.allocate(["dir", "file.TXT"]) == (["Dir", "file~1.TXT"], True)       # dirs merge, file renamed
    assert a.allocate(["DIR", "FILE.txt"]) == (["Dir", "FILE~2.txt"], True)
    assert a.allocate(["x"]) == (["x"], False)
    assert a.allocate(["X", "child"]) == (["X~1", "child"], True)                 # file/dir clash
    n = PathAllocator()
    n.allocate(["caf\u00e9"])
    assert n.allocate(["cafe\u0301"])[0] == ["cafe\u0301~1"]                       # NFC / NFD clash


def _src(tmp_path, files=None, raw=None, **kw):
    p = build_ipa(tmp_path / "a.ipa", files or {}, raw_files=raw, **kw)
    return ZipSource(p)


def test_extract_refuses_zip_slip_and_continues(tmp_path):
    raw = {"../evil.txt": b"x", "Payload/../../evil2": b"y", "/abs/evil": b"z", "C:\\evil": b"w", "ok/file": b"fine"}
    src = _src(tmp_path, raw=raw)
    ex = SafeExtractor(src, tmp_path / "out", LimitsConfig())
    got, errors = ex.extract_many(list(raw))
    assert list(got) == ["ok/file"] and got["ok/file"].read_bytes() == b"fine"
    assert set(errors) == {"../evil.txt", "Payload/../../evil2", "/abs/evil", "C:\\evil"}
    assert not (tmp_path / "evil.txt").exists() and not (tmp_path / "evil2").exists()
    assert sorted(p.name for p in (tmp_path / "out").rglob("*") if p.is_file()) == ["file"]
    src.close()


def test_windows_reserved_names_and_manifest(tmp_path):
    raw = {"d/CON.txt": b"1", "d/aux": b"2", "d/con.TXT": b"3", "d/a:b": b"4"}
    src = _src(tmp_path, raw=raw)
    mp = tmp_path / "m.json"
    ex = SafeExtractor(src, tmp_path / "out", LimitsConfig(), manifest_path=mp)
    got, errors = ex.extract_many(list(raw))
    assert not errors
    assert got["d/CON.txt"].name == "_CON.txt" and got["d/aux"].name == "_aux" and got["d/a:b"].name == "a_b"
    assert got["d/con.TXT"].name == "_con~1.TXT"                      # collides with _CON.txt once sanitised
    ex.save_manifest()
    doc = json.loads(mp.read_text(encoding="utf-8"))
    assert doc["entries"]["d/CON.txt"]["sanitized"] is True and doc["entries"]["d/CON.txt"]["path"] == "d/_CON.txt"
    src.close()


def test_case_collision_gets_suffix_not_overwrite(tmp_path):
    src = _src(tmp_path, raw={"d/Readme.md": b"UPPER", "d/README.MD": b"lower", "D/other": b"o"})
    ex = SafeExtractor(src, tmp_path / "out", LimitsConfig())
    got, errors = ex.extract_many(["d/Readme.md", "d/README.MD", "D/other"])
    assert not errors
    assert got["d/Readme.md"].read_bytes() == b"UPPER" and got["d/README.MD"].read_bytes() == b"lower"
    assert got["d/Readme.md"] != got["d/README.MD"]
    assert got["D/other"].parent == got["d/Readme.md"].parent         # directories differing in case merge
    src.close()


def test_symlinks_recorded_not_created(tmp_path):
    src = _src(tmp_path, {"real": b"x"}, symlinks={"Current": "real", "evil": "/etc/passwd"})
    ex = SafeExtractor(src, tmp_path / "out", LimitsConfig(), manifest_path=tmp_path / "m.json")
    got, errors = ex.extract_many([e.name for e in src.namelist()])
    assert not errors and len(got) == 1
    assert not any(p.is_symlink() for p in (tmp_path / "out").rglob("*"))
    rec = ex.manifest["Payload/Test.app/Current"]
    assert rec["symlink_target"] == "real" and rec["symlink_created"] is False
    src.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink creation")
def test_symlink_creation_only_inside_root(tmp_path):
    src = _src(tmp_path, {"real": b"x"}, symlinks={"ok": "real", "up": "../../../outside", "abs": "/etc"})
    ex = SafeExtractor(src, tmp_path / "out", LimitsConfig(), create_symlinks=True)
    ex.extract_many([e.name for e in src.namelist()])
    links = {p.name: os.readlink(p) for p in (tmp_path / "out").rglob("*") if p.is_symlink()}
    assert links == {"ok": "real"}
    src.close()


def test_limits_file_total_count_ratio(tmp_path):
    src = _src(tmp_path, {"a": b"x" * 100, "b": b"y" * 100, "c": b"z" * 100})
    names = ["Payload/Test.app/%s" % n for n in "abc"]
    ex = SafeExtractor(src, tmp_path / "o1", LimitsConfig(max_file_size=50))
    got, errors = ex.extract_many(names)
    assert not got and all("per-file limit" in m for m in errors.values())
    ex = SafeExtractor(src, tmp_path / "o2", LimitsConfig(max_total_extract=250))
    got, errors = ex.extract_many(names)
    assert len(got) == 2 and len(errors) == 1 and "total extraction limit" in next(iter(errors.values()))
    ex = SafeExtractor(src, tmp_path / "o3", LimitsConfig(max_files=1))
    got, errors = ex.extract_many(names)
    assert len(got) == 1 and len(errors) == 2
    z = ZipBuilder()
    z.add("zeros", b"\0" * 4_000_000)
    zp = tmp_path / "z.zip"
    zp.write_bytes(z.finish())
    zs = ZipSource(zp)
    ex = SafeExtractor(zs, tmp_path / "o4", LimitsConfig(max_ratio=50), ratio_floor=1_000_000)
    with pytest.raises(LimitExceeded, match="ratio"):
        ex.extract("zeros")
    assert not any((tmp_path / "o4").rglob("*")) or not any(p.is_file() for p in (tmp_path / "o4").rglob("*"))
    ex = SafeExtractor(zs, tmp_path / "o5", LimitsConfig(max_ratio=50))      # below the default floor: allowed
    assert ex.extract("zeros").stat().st_size == 4_000_000
    zs.close()
    src.close()


def test_atomic_write_leaves_no_partial_files(tmp_path):
    zb = ZipBuilder()
    zb.add("bad", b"x" * 100, comp_data=b"\xff garbage", method=8)
    zb.add("good", b"fine")
    p = tmp_path / "t.zip"
    p.write_bytes(zb.finish())
    src = ZipSource(p)
    ex = SafeExtractor(src, tmp_path / "out", LimitsConfig())
    got, errors = ex.extract_many(["bad", "good"])
    assert list(got) == ["good"] and "bad" in errors
    assert [f.name for f in (tmp_path / "out").iterdir()] == ["good"]
    src.close()


def test_reuse_and_manifest_reload_keep_mapping(tmp_path):
    src = _src(tmp_path, raw={"A/x.TXT": b"1", "a/X.txt": b"2"})
    mp = tmp_path / "m.json"
    ex = SafeExtractor(src, tmp_path / "out", LimitsConfig(), manifest_path=mp)
    first, _ = ex.extract_many(["A/x.TXT", "a/X.txt"])
    ex.save_manifest()
    ex2 = SafeExtractor(src, tmp_path / "out", LimitsConfig(), manifest_path=mp)     # new run, reversed request order
    second, _ = ex2.extract_many(["a/X.txt", "A/x.TXT"])
    assert second == first
    assert ex2.budget.total_bytes == 0                                              # nothing re-extracted
    first["a/X.txt"].unlink()                                                       # file gone: same path again
    third, _ = ex2.extract_many(["a/X.txt"])
    assert third["a/X.txt"] == first["a/X.txt"] and third["a/X.txt"].read_bytes() == b"2"
    src.close()


def test_directory_entries_are_skipped(tmp_path):
    src = _src(tmp_path, {"f": b"x"})
    ex = SafeExtractor(src, tmp_path / "out", LimitsConfig())
    got, errors = ex.extract_many(["Payload/", "Payload/Test.app/", "Payload/Test.app/f"])
    assert list(got) == ["Payload/Test.app/f"] and not errors
    src.close()


def test_check_archive_limits_cases():
    lim = LimitsConfig(max_total_extract=1000, max_file_size=500, max_files=3, max_ratio=10.0)
    ok = [EntryInfo("a", 100, 50), EntryInfo("d/", 0, is_dir=True)]
    assert check_archive_limits(ok, 1000, lim) == []
    with pytest.raises(LimitExceeded, match="more than 3 files"):
        check_archive_limits([EntryInfo("f%d" % i, 1, 1) for i in range(4)], 100, lim)
    with pytest.raises(LimitExceeded, match="bomb"):
        check_archive_limits([EntryInfo("big", 10_000, 10)], 100, lim)                # one huge, ratio 1000
    with pytest.raises(LimitExceeded, match="overall"):
        check_archive_limits([EntryInfo("m%d" % i, 400, 1) for i in range(3)], 100, lim)
    # big but not compressible: warning only
    w = check_archive_limits([EntryInfo("a", 400, 390), EntryInfo("b", 400, 390), EntryInfo("c", 400, 390)], 1170, lim)
    assert any("extraction limit" in x for x in w)
    # zero compressed size with large declared size counts as infinite ratio
    with pytest.raises(LimitExceeded):
        check_archive_limits([EntryInfo("z", 10_000, 0)], 100, lim)


def test_ctx_extract_integration(tmp_path):
    from ipa_analyzer.analyzers.ingest_stage import IngestStage

    ipa = build_ipa(tmp_path / "a.ipa", {"Info.plist": b"plist", "CON.txt": b"c"}, raw_files={"../evil": b"x"})
    ctx = AnalysisContext(Config(output_dir=tmp_path / "out"), ipa)
    res = IngestStage().run(ctx)
    ctx.results["ingest"] = res.data
    got = ctx.extract(["Payload/Test.app/Info.plist", "Payload/Test.app/CON.txt", "../evil", "Payload/Test.app/missing"])
    assert set(got) == {"Payload/Test.app/Info.plist", "Payload/Test.app/CON.txt"}
    assert got["Payload/Test.app/CON.txt"].name == "_CON.txt"
    assert all(Path(p).resolve().is_relative_to(ctx.workdir.resolve()) if hasattr(Path, "is_relative_to") else True
               for p in got.values())
    assert sum("unsafe" in w for w in ctx.warnings) == 1 and any("no such entry" in w for w in ctx.warnings)
    assert (ctx.workdir / "extract.manifest.json").is_file()
    assert ctx.extract(["Payload/Test.app/Info.plist"]) == {"Payload/Test.app/Info.plist": got["Payload/Test.app/Info.plist"]}
    ctx.close()
