"""engine.unity stage end to end on synthetic IPAs (real ingest / inventory / macho stages, fake dumper)."""
from __future__ import annotations

import json
import random
import shutil
from pathlib import Path

import pytest

from fixtures.fake_dumper import __file__ as FAKE_DUMPER_FILE
from fixtures.ipa_builder import build_ipa
from fixtures.unity_builder import (build_block_encrypted_bundle, build_serialized_file,
                                    build_standard_bundle, build_unity_app, mono_samples)
from ipa_analyzer import pipeline
from ipa_analyzer.analyzers import unity as unity_mod
from ipa_analyzer.analyzers.unity import EngineUnityStage
from ipa_analyzer.config import Config
from ipa_analyzer.context import AnalysisContext
from ipa_analyzer.il2cpp import Il2CppErrorCode, Il2CppRunResult
from ipa_analyzer.models import Status, to_jsonable

DETECT_UNITY = {"primary": {"id": "unity", "name": "Unity", "confidence": 0.9, "confirmed": True},
                "candidates": [{"id": "unity", "name": "Unity", "confidence": 0.9, "confirmed": True}]}


def make_ctx(tmp_path, files, *, mutate=None, detect=DETECT_UNITY):
    ipa = build_ipa(tmp_path / "game.ipa", files, app_name="Game")
    cfg = Config(output_dir=tmp_path / "out", stages=("macho",), formats=("json",), keep_workdir=True)
    cfg.offline = True
    if mutate:
        mutate(cfg)
    ctx = AnalysisContext(cfg, ipa)
    pipeline.ensure_analyzers_loaded()
    pipeline.run(ctx)
    if detect is not None:
        ctx.results["engine.detect"] = detect
    return ctx


def run(tmp_path, files, **kw):
    ctx = make_ctx(tmp_path, files, **kw)
    return ctx, EngineUnityStage().run(ctx)


def finding(res, fid):
    return next(f for f in res.findings if f.id == fid)


@pytest.fixture
def forbid_runner(monkeypatch):
    calls = []

    def fake(req, tools, cfg):
        calls.append(req)
        return Il2CppRunResult(ok=False, error_code=Il2CppErrorCode.E_UNKNOWN, message="mock")
    monkeypatch.setattr(unity_mod, "run_il2cpp_dump", fake)
    return calls


@pytest.fixture
def fake_tool(tmp_path):
    d = tmp_path / "faketool"
    d.mkdir()
    shutil.copyfile(FAKE_DUMPER_FILE, str(d / "fake_dumper.py"))
    (d / "config.json").write_text(json.dumps({"RequireAnyKey": True, "DumpMethod": True}), encoding="utf-8")
    return d / "fake_dumper.py"


def use_fake(cfg, tool):
    cfg.il2cpp.tool_path = str(tool)
    cfg.il2cpp.backend_order = ["il2cppdumper"]
    cfg.offline = True


# ---------------------------------------------------------------------------------- activation
def test_non_unity_is_skipped(tmp_path):
    ctx, res = run(tmp_path, build_unity_app(), detect={"primary": None, "candidates": [
        {"id": "cocos", "confidence": 0.8}]})
    assert res.status == Status.SKIPPED and res.reason == "not a Unity app"
    _, res = run(tmp_path / "b", {"Info.plist": b"x"}, detect={"primary": None, "candidates": []})
    assert res.status == Status.SKIPPED


def test_primary_unity_without_candidates_list_still_runs(tmp_path, forbid_runner):
    ctx, res = run(tmp_path, build_unity_app(), detect={"primary": {"id": "unity", "confidence": 0.7}, "candidates": []})
    assert res.status != Status.SKIPPED and res.data["backend"] == "il2cpp"


def test_unity_without_metadata_or_dlls_is_unknown_not_a_crash(tmp_path):
    ctx, res = run(tmp_path, build_unity_app(backend="none"))
    assert res.status == Status.OK and res.data["backend"] == "unknown"
    assert finding(res, "unity.backend").verdict.value == "unknown"
    assert finding(res, "unity.metadata.present").verdict.value == "no"
    assert finding(res, "unity.assetbundle.encryption").verdict.value == "unknown"
    assert finding(res, "unity.il2cpp.precheck").verdict.value == "n/a"


# ---------------------------------------------------------------------------------- plain il2cpp app
def test_plain_il2cpp_app_data_shape_and_findings(tmp_path, forbid_runner):
    ctx, res = run(tmp_path, build_unity_app(binary_unity_string="2021.3.16f1"),
                   mutate=lambda c: setattr(c.il2cpp, "enabled", False))
    d = res.data
    assert d["backend"] == "il2cpp" and d["version"]["value"] == "2021.3.16f1"
    kinds = {s["source"] for s in d["version"]["sources"]}
    assert {"serialized:globalgamemanagers", "serialized", "binary"} <= kinds
    assert d["binary"] == {"path": "Payload/Game.app/Frameworks/UnityFramework.framework/UnityFramework",
                           "slice": "arm64", "encrypted": False}
    m = d["metadata"]
    assert m["present"] and m["version"] == 24 and m["header_ok"] is True and m["string_region_ok"] is True
    assert m["verdict"] == "no" and m["string_region"]["size"] > 0 and m["entropy"] < 7
    assert m["evidence"] and all({"kind", "ref", "detail"} <= set(e) for e in m["evidence"])
    assert d["precheck"]["ready"] is True and d["dump"]["ran"] is False and d["dump"]["skipped_reason"] == "disabled"
    assert finding(res, "unity.il2cpp.dump").verdict.value == "n/a"
    assert finding(res, "unity.metadata.encrypted").verdict.value == "no"
    assert finding(res, "unity.binary.fairplay").verdict.value == "no"
    assert finding(res, "unity.il2cpp.precheck").verdict.value == "yes"
    assert to_jsonable(d) == d
    assert ctx.results.get("engine.unity") is None          # results are only filled by the pipeline; data is JSON-able
    assert not forbid_runner


def test_ids_are_frozen_ids(tmp_path, forbid_runner):
    ctx, res = run(tmp_path, build_unity_app(), mutate=lambda c: setattr(c.il2cpp, "enabled", False))
    frozen = {"unity.detected", "unity.version", "unity.backend", "unity.metadata.present", "unity.metadata.encrypted",
              "unity.binary.fairplay", "unity.il2cpp.precheck", "unity.il2cpp.dump", "unity.il2cpp.names_obfuscated",
              "unity.assetbundle.encryption", "unity.mono.dll_encrypted"}
    assert {f.id for f in res.findings} <= frozen


# ---------------------------------------------------------------------------------- pre-check gates
def test_fairplay_binary_never_reaches_the_runner(tmp_path, forbid_runner):
    ctx, res = run(tmp_path, build_unity_app(encrypted_binary=True))
    assert not forbid_runner
    assert res.status == Status.OK
    assert res.data["precheck"] == {**res.data["precheck"], "ready": False, "error_code": "E_BINARY_FAIRPLAY"}
    assert res.data["binary"]["encrypted"] is True
    f = finding(res, "unity.il2cpp.dump")
    assert f.verdict.value == "no" and f.params["error_code"] == "E_BINARY_FAIRPLAY" and f.remediation
    assert finding(res, "unity.binary.fairplay").verdict.value == "yes"
    # the other verdicts survive and no binary strings were trusted
    assert finding(res, "unity.metadata.encrypted").verdict.value == "no"
    assert finding(res, "unity.version").verdict.value == "yes"
    assert any("FairPlay" in w for w in res.warnings)


def test_forced_dump_does_not_override_fairplay(tmp_path, forbid_runner):
    ctx, res = run(tmp_path, build_unity_app(encrypted_binary=True), mutate=lambda c: setattr(c.il2cpp, "force_dump", True))
    assert not forbid_runner and res.data["precheck"]["error_code"] == "E_BINARY_FAIRPLAY"


@pytest.mark.parametrize("variant,verdict", [("xor_strings", "suspected"), ("wrong_magic", "suspected"),
                                              ("random", "yes")])
def test_suspect_metadata_blocks_the_runner(tmp_path, forbid_runner, variant, verdict):
    ctx, res = run(tmp_path, build_unity_app(metadata_variant=variant))
    assert not forbid_runner
    assert finding(res, "unity.metadata.encrypted").verdict.value == verdict
    assert res.data["precheck"]["error_code"] == "E_METADATA_ENCRYPTED" and not res.data["precheck"]["ready"]
    assert res.data["dump"]["ran"] is False and res.status == Status.OK


def test_force_dump_runs_the_runner_past_a_suspect_metadata(tmp_path, forbid_runner):
    ctx, res = run(tmp_path, build_unity_app(metadata_variant="xor_strings"),
                   mutate=lambda c: setattr(c.il2cpp, "force_dump", True))
    assert len(forbid_runner) == 1 and forbid_runner[0].force_dump is True
    assert res.data["precheck"]["forced"] is True and res.data["precheck"]["ready"] is True
    assert res.status == Status.PARTIAL and "E_UNKNOWN" in (res.reason or "")


def test_missing_il2cpp_markers_only_warn(tmp_path, forbid_runner):
    ctx, res = run(tmp_path, build_unity_app(with_binary_markers=False))
    assert res.data["precheck"]["ready"] and "no_il2cpp_markers_in_binary" in res.data["precheck"]["warnings"]
    assert len(forbid_runner) == 1                       # still attempted


# ---------------------------------------------------------------------------------- dump end to end
def test_end_to_end_with_the_fake_dumper(tmp_path, fake_tool):
    ctx, res = run(tmp_path, build_unity_app(metadata_version=24), mutate=lambda c: use_fake(c, fake_tool))
    assert res.status == Status.OK, (res.reason, res.warnings)
    dump = res.data["dump"]
    assert dump["ran"] and dump["ok"] and dump["backend"] == "il2cppdumper" and dump["error_code"] is None
    assert dump["out_dir"] == "il2cpp"
    assert dump["artifacts"]["dump.cs"] == "il2cpp/dump.cs"          # relative to ctx.out_dir, POSIX
    assert (ctx.out_dir / dump["artifacts"]["dump.cs"]).is_file()
    assert all(not Path(v).is_absolute() and "\\" not in v for v in dump["artifacts"].values())
    s = dump["summary"]
    assert s["classes"] >= 1 and s["methods"] >= 1 and "HybridCLR" in s["framework_namespaces"]
    assert "Game.Core" in dump["namespaces"] and s["obfuscation"]["level"] in ("none", "low")
    assert ctx.artifacts["il2cpp.dump.cs"] == "il2cpp/dump.cs"
    f = finding(res, "unity.il2cpp.dump")
    assert f.verdict.value == "yes" and f.params["backend"] == "il2cppdumper"
    ob = finding(res, "unity.il2cpp.names_obfuscated")
    assert ob.params["source"] == "dump"
    assert to_jsonable(res.data) == res.data
    assert not (ctx.workdir / "unity" / "run").exists() or not any((ctx.workdir / "unity" / "run").iterdir())


def test_dump_failure_is_partial_and_keeps_earlier_verdicts(tmp_path, monkeypatch):
    monkeypatch.setattr(unity_mod, "run_il2cpp_dump", lambda req, tools, cfg: Il2CppRunResult(
        ok=False, error_code=Il2CppErrorCode.E_DOTNET_MISSING, message="no dotnet",
        remediation="install .NET"))
    ctx, res = run(tmp_path, build_unity_app())
    assert res.status == Status.PARTIAL and "E_DOTNET_MISSING" in res.reason
    f = finding(res, "unity.il2cpp.dump")
    assert f.verdict.value == "no" and f.params["error_code"] == "E_DOTNET_MISSING" and f.remediation == "install .NET"
    assert res.data["dump"]["ran"] is True and res.data["dump"]["ok"] is False
    assert finding(res, "unity.metadata.encrypted").verdict.value == "no"
    assert finding(res, "unity.version").verdict.value == "yes"


def test_runner_crash_is_contained(tmp_path, monkeypatch):
    def boom(req, tools, cfg):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(unity_mod, "run_il2cpp_dump", boom)
    ctx, res = run(tmp_path, build_unity_app())
    assert res.status == Status.PARTIAL and res.data["dump"]["error_code"] == "E_UNKNOWN"


def test_runner_receives_a_thin_binary_and_cross_checked_versions(tmp_path, monkeypatch):
    seen = {}

    def fake(req, tools, cfg):
        seen["req"] = req
        seen["exists"] = (Path(req.binary_path).is_file(), Path(req.metadata_path).is_file())
        return Il2CppRunResult(ok=True, backend="il2cppdumper", backend_version="x", out_dir=req.out_dir,
                               artifacts={})
    monkeypatch.setattr(unity_mod, "run_il2cpp_dump", fake)
    ctx, res = run(tmp_path, build_unity_app(unity_version="2022.3.62f3c1"))
    req = seen["req"]
    assert seen["exists"] == (True, True)
    assert req.unity_version == "2022.3.62f3" and req.metadata_version == 24
    assert req.out_dir == ctx.out_dir / "il2cpp"
    assert res.status == Status.OK and finding(res, "unity.il2cpp.dump").verdict.value == "yes"


# ---------------------------------------------------------------------------------- versions
def test_version_conflicts_are_reported(tmp_path, forbid_runner):
    files = build_unity_app(unity_version="2021.3.16f1", bundles={"Data/Raw/a.bundle": build_standard_bundle(
        "lz4", engine_version="2021.3.10f1")},
        extra={"Data/unity default resources": build_serialized_file("2021.3.1f1")})
    ctx, res = run(tmp_path, files, mutate=lambda c: setattr(c.il2cpp, "enabled", False))
    v = res.data["version"]
    assert v["value"] == "2021.3.16f1"
    assert {c["kind"] for c in v["conflicts"]} == {"stale", "bundle"}
    f = finding(res, "unity.version")
    assert f.verdict.value == "yes" and f.params["conflicts"] == 2


def test_no_version_source_is_unknown(tmp_path, forbid_runner):
    files = build_unity_app()
    del files["Data/globalgamemanagers"], files["Data/level0"]
    ctx, res = run(tmp_path, files, mutate=lambda c: setattr(c.il2cpp, "enabled", False))
    assert res.data["version"]["value"] is None and finding(res, "unity.version").verdict.value == "unknown"


def test_binary_string_version_is_used_for_unencrypted_binaries(tmp_path, forbid_runner):
    files = build_unity_app(binary_unity_string="2019.4.40f1")
    del files["Data/globalgamemanagers"], files["Data/level0"]
    ctx, res = run(tmp_path, files, mutate=lambda c: setattr(c.il2cpp, "enabled", False))
    assert res.data["version"]["value"] == "2019.4.40f1"
    assert res.data["version"]["sources"][0]["source"] == "binary"


# ---------------------------------------------------------------------------------- bundles in the stage
def test_standard_bundles_and_paths_sample(tmp_path, forbid_runner):
    std = build_standard_bundle("lz4")
    bundles = {"Data/Raw/b%02d.bundle" % i: std for i in range(5)}
    ctx, res = run(tmp_path, build_unity_app(bundles=bundles), mutate=lambda c: setattr(c.il2cpp, "enabled", False))
    b = res.data["bundles"]
    assert b["total"] == 5 and b["by_class"]["standard"] == 5 and b["verdict"] == "no"
    assert len(b["paths_sample"]) == 5 and b["paths_sample"][0].startswith("Payload/Game.app/Data/Raw/")
    assert finding(res, "unity.assetbundle.encryption").verdict.value == "no"
    assert b["addressables"]["catalog_found"] is False


def test_encrypted_bundles_stage(tmp_path, forbid_runner):
    bundles = {"Data/Raw/e%d.bundle" % i: random.Random(i).randbytes(9000) for i in range(4)}
    bundles["Data/Raw/aa/catalog.bin"] = b"\x01" * 100
    ctx, res = run(tmp_path, build_unity_app(bundles=bundles), mutate=lambda c: setattr(c.il2cpp, "enabled", False))
    assert finding(res, "unity.assetbundle.encryption").verdict.value == "yes"
    assert res.data["bundles"]["addressables"]["catalog_found"] is True


def test_block_encrypted_bundles_stage(tmp_path, forbid_runner):
    bundles = {"Data/Raw/k%d.b" % i: build_block_encrypted_bundle(seed=i) for i in range(3)}
    ctx, res = run(tmp_path, build_unity_app(bundles=bundles), mutate=lambda c: setattr(c.il2cpp, "enabled", False))
    b = res.data["bundles"]
    assert b["by_class"]["block_encrypted_suspected"] == 3 and b["verdict"] == "suspected"
    f = finding(res, "unity.assetbundle.encryption")
    assert f.verdict.value == "suspected" and any("marker" in e.detail for e in f.evidence)


def test_bundle_sampling_limit_comes_from_config(tmp_path, forbid_runner):
    std = build_standard_bundle("lz4")
    bundles = {"Data/Raw/b%02d.bundle" % i: std for i in range(30)}

    def mut(c):
        c.il2cpp.enabled = False
        c.unity.bundle_deep_sample = 4
    ctx, res = run(tmp_path, build_unity_app(bundles=bundles), mutate=mut)
    assert 4 <= res.data["bundles"]["sampled"] <= 5


# ---------------------------------------------------------------------------------- mono
def test_mono_app(tmp_path, forbid_runner):
    ctx, res = run(tmp_path, build_unity_app(backend="mono"))
    assert res.data["backend"] == "mono" and not forbid_runner
    assert finding(res, "unity.backend").params["backend"] == "mono"
    assert res.data["mono"]["verdict"] == "no"
    assert finding(res, "unity.mono.dll_encrypted").verdict.value == "no"
    assert finding(res, "unity.il2cpp.dump").verdict.value == "n/a"
    assert finding(res, "unity.il2cpp.precheck").verdict.value == "n/a"


def test_encrypted_mono_assemblies(tmp_path, forbid_runner):
    files = build_unity_app(backend="mono")
    files["Data/Managed/Assembly-CSharp.dll"] = mono_samples()["random"]
    ctx, res = run(tmp_path, files)
    assert finding(res, "unity.mono.dll_encrypted").verdict.value == "yes"


def test_both_metadata_and_dlls_is_unknown_backend(tmp_path, forbid_runner):
    files = build_unity_app(backend="il2cpp")
    files["Data/Managed/Assembly-CSharp.dll"] = mono_samples()["good"]
    ctx, res = run(tmp_path, files)
    assert res.data["backend"] == "unknown" and finding(res, "unity.backend").verdict.value == "unknown"
    assert not forbid_runner


# ---------------------------------------------------------------------------------- facts for the hot-fix stage
def test_facts_exposed_for_wp5b(tmp_path, forbid_runner):
    std = build_standard_bundle("lz4")
    ctx, res = run(tmp_path, build_unity_app(bundles={"Data/Raw/x.bundle": std}),
                   mutate=lambda c: setattr(c.il2cpp, "enabled", False))
    d = res.data
    assert d["metadata"]["path"].endswith("global-metadata.dat") and d["metadata"]["header_ok"] is True
    sr = d["metadata"]["string_region"]
    assert set(sr) == {"offset", "size"} and sr["size"] > 0
    with ctx.source.open(d["metadata"]["path"]) as fh:
        fh.seek(sr["offset"])
        assert b"mscorlib" in fh.read(sr["size"])
    assert d["bundles"]["total"] == 1 and d["bundles"]["paths_sample"] == [
        "Payload/Game.app/Data/Raw/x.bundle"]
    assert d["binary"]["path"].endswith("UnityFramework")


# ---------------------------------------------------------------------------------- i18n coverage
def test_every_emitted_finding_has_complete_zh_and_en_text(tmp_path, forbid_runner, fake_tool):
    from ipa_analyzer.report.i18n import load_catalog
    scenarios = [
        (build_unity_app(encrypted_binary=True, bundles={"Data/Raw/e.bundle": random.Random(1).randbytes(9000)}), None),
        (build_unity_app(backend="mono"), None),
        (build_unity_app(backend="none"), None),
        (build_unity_app(metadata_variant="xor_strings"), None),
        (build_unity_app(), lambda c: setattr(c.il2cpp, "enabled", False)),
    ]
    ids = set()
    for i, (files, mut) in enumerate(scenarios):
        ctx, res = run(tmp_path / str(i), files, mutate=mut)
        for f in res.findings:
            ids.add(f.id)
            for lang in ("zh", "en"):
                text = load_catalog(lang).finding_text(f.to_dict())
                assert text.localized, (lang, f.id)
                assert "{" not in text.summary and "{" not in text.title, (lang, f.id, text.summary)
    assert len(ids) >= 9
