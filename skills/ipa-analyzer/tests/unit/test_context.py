from __future__ import annotations

import pytest

from ipa_analyzer.config import Config
from ipa_analyzer.context import AnalysisContext
from ipa_analyzer.errors import InvalidInput
from ipa_analyzer.ingest import ArchiveSource, open_source


def _bound_ctx(tmp_path, ipa, app_root="Payload/A.app/"):
    ctx = AnalysisContext(Config(output_dir=tmp_path / "out"), ipa, source=open_source(ipa), app_root=app_root)
    ctx.bind_input("ab" * 32, "My App")
    return ctx


def test_results_alias_reads_only():
    ctx = AnalysisContext(Config(), "x.ipa")
    ctx.results["engine.unity"] = {"v": 1}
    assert ctx.results["unity"] is ctx.results["engine.unity"]
    assert ctx.results.get("unity") == {"v": 1} and "unity" in ctx.results
    assert list(ctx.results) == ["engine.unity"]
    assert ctx.results.get("nope") is None


def test_unbound_context_raises_for_out_dir():
    with pytest.raises(RuntimeError):
        AnalysisContext(Config(), "x.ipa").out_dir


def test_bind_input_layout(tmp_path):
    ctx = AnalysisContext(Config(output_dir=tmp_path / "out"), tmp_path / "A b.ipa")
    ctx.bind_input("0123456789abcdef" * 4)
    assert ctx.out_dir == tmp_path / "out" / "A b-0123456789ab"
    assert ctx.out_dir.is_dir() and ctx.workdir == ctx.out_dir / "work"
    ctx.bind_input("ff" * 32)           # idempotent: directory does not move
    assert ctx.out_dir.name == "A b-0123456789ab"


def test_artifact_path_cannot_escape(tmp_path):
    ctx = AnalysisContext(Config(), "x", out_dir=tmp_path / "o")
    assert ctx.artifact_path("sub/f.json").parent.is_dir()
    with pytest.raises(ValueError):
        ctx.artifact_path("../evil")


def test_rel_and_app_path(tmp_path):
    ctx = AnalysisContext(Config(), "x", app_root="Payload/A.app/")
    assert ctx.rel("Payload/A.app/Info.plist") == "Info.plist" and ctx.rel("iTunesMetadata.plist") is None
    assert ctx.app_path("Frameworks/U.framework/U") == "Payload/A.app/Frameworks/U.framework/U"
    assert AnalysisContext(Config(), "x", app_root="").rel("a/b") == "a/b"


def test_default_extract_and_cache(make_zip, tmp_path):
    ipa = make_zip({"Payload/A.app/Info.plist": b"plist", "Payload/A.app/CON.txt": b"x", "Payload/A.app/d/": b""})
    ctx = _bound_ctx(tmp_path, ipa)
    got = ctx.extract(["Payload/A.app/Info.plist", "Payload/A.app/CON.txt", "Payload/A.app/missing", "Payload/A.app/d/"])
    assert set(got) == {"Payload/A.app/Info.plist", "Payload/A.app/CON.txt"}
    assert got["Payload/A.app/Info.plist"].read_bytes() == b"plist"
    assert all(str(p).startswith(str(ctx.workdir)) for p in got.values())
    assert any("no such entry" in w for w in ctx.warnings)
    again = ctx.extract(["Payload/A.app/Info.plist"])
    assert again == {"Payload/A.app/Info.plist": got["Payload/A.app/Info.plist"]}
    ctx.close()


def test_default_extract_refuses_unsafe_and_oversized(make_zip, tmp_path):
    ipa = make_zip({"Payload/A.app/big": b"0" * 100, "../evil": b"x"})
    ctx = _bound_ctx(tmp_path, ipa)
    ctx.cfg.limits.max_file_size = 10
    assert ctx.extract(["../evil", "/abs", "C:/x", "Payload/A.app/big"]) == {}
    assert len(ctx.warnings) == 4
    ctx.close()


def test_zip_source_contract(make_zip):
    ipa = make_zip({"a/b.bin": b"0123456789", "a/": b""})
    src = open_source(ipa)
    assert isinstance(src, ArchiveSource) and src.kind == "zip"
    names = {e.name: e for e in src.namelist()}
    assert names["a/"].is_dir and names["a/b.bin"].size == 10
    assert src.read_head("a/b.bin", 4) == b"0123" and src.stat("a/b.bin").size == 10
    with src.open("a/b.bin") as fh:
        assert fh.read() == b"0123456789"
    with pytest.raises(KeyError):
        src.stat("nope")
    src.close()


def test_zip_source_invalid(tmp_path):
    bad = tmp_path / "bad.ipa"
    bad.write_bytes(b"not a zip")
    with pytest.raises(InvalidInput):
        open_source(bad)
