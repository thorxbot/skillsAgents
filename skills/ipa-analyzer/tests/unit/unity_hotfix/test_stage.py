from __future__ import annotations

import json
import random
import zlib

import pytest

from fixtures import formats_builder as fb
from fixtures import unity_hotfix_builder as ub
from ipa_analyzer import pipeline
from ipa_analyzer.analyzers.unity_hotfix import NAME, EngineUnityHotfixStage
from ipa_analyzer.models import Status, Verdict, to_jsonable

FINDING_IDS = {"unity.hotfix.framework", "unity.hotfix.lua", "unity.hotfix.lua_version", "unity.hotfix.csharp_dll",
               "unity.hotfix.js", "unity.hotfix.resource_update", "unity.hotfix.script_protection"}
STR_5_3 = "Lua 5.3.6  Copyright (C) 1994-2020 Lua.org, PUC-Rio"


def urandom(n: int) -> bytes:
    return random.Random(n).randbytes(n)


def run(tmp_path, files=None, **kw):
    files = files if files is not None else ub.build_hotfix_app()
    ctx = ub.make_context(tmp_path, files, **kw)
    res = EngineUnityHotfixStage().run(ctx)
    return ctx, res


def fw_ids(res, min_conf=0.5):
    return {f["id"] for f in res.data["frameworks"] if f["confidence"] >= min_conf}


def finding(res, fid):
    return next(f for f in res.findings if f.id == fid)


def test_registration_matches_contract():
    spec = pipeline.ensure_analyzers_loaded().get(NAME)
    assert spec.requires == ("engine.unity",) and set(spec.after) == {"inventory", "macho"}


def test_skipped_without_unity_result_and_without_source(tmp_path):
    files = ub.build_hotfix_app()
    ctx = ub.make_context(tmp_path, files)
    ctx.results.pop("engine.unity")
    res = EngineUnityHotfixStage().run(ctx)
    assert res.status == Status.SKIPPED and "engine.unity" in res.reason
    ctx.results["engine.unity"] = {}
    ctx.source = None
    assert EngineUnityHotfixStage().run(ctx).status == Status.SKIPPED


@pytest.mark.parametrize("identifiers,expect", [
    (["HybridCLR", "HomologousImageMode", "LoadMetadataForAOTAssembly"], "hybridclr"),
    (["ILRuntime", "ILRuntime.Runtime.Enviorment", "CLRBindings"], "ilruntime"),
    (["XLua", "XLua.LuaDLL"], "xlua"),
    (["LuaInterface", "LuaFileUtils", "LuaState"], "tolua"),
    (["Puerts", "JsEnv", "BackendV8"], "puerts"),
    (["Puerts", "BackendQuickJS"], "puerts"),
    (["UnityEngine.AddressableAssets", "UnityEngine.ResourceManagement.ResourceProviders"], "addressables"),
    (["YooAsset", "YooAssets"], "yooasset"),
    (["IFix.Core", "IFix"], "ifix"),
])
def test_framework_positive_via_metadata_strings(tmp_path, identifiers, expect):
    ctx, res = run(tmp_path, ub.build_hotfix_app(identifiers=identifiers))
    assert res.status == Status.OK
    assert expect in fw_ids(res), res.data["frameworks"]
    assert res.data["evidence_sources"]["metadata_strings"]["ran"] is True
    assert finding(res, "unity.hotfix.framework").verdict in (Verdict.YES, Verdict.SUSPECTED)


def test_puerts_backend_is_reported_from_type_names(tmp_path):
    _, res = run(tmp_path, ub.build_hotfix_app(identifiers=["Puerts", "BackendV8"]))
    assert [b["id"] for b in res.data["js"]["backends"]] == ["v8"]
    _, res = run(tmp_path / "q", ub.build_hotfix_app(identifiers=["Puerts", "BackendQuickJS"]))
    assert [b["id"] for b in res.data["js"]["backends"]] == ["quickjs"]


def test_puerts_backend_from_native_symbols(tmp_path):
    files = ub.build_hotfix_app(identifiers=["Puerts"], encrypted_binary=False, binary_strings=["_JS_NewRuntime", "_JS_NewContext"])
    _, res = run(tmp_path, files)
    assert "quickjs" in {b["id"] for b in res.data["js"]["backends"]}


def test_metadata_v39_layout_still_scanned(tmp_path):
    _, res = run(tmp_path, ub.build_hotfix_app(identifiers=["XLua"], metadata_layout="v39"))
    assert "xlua" in fw_ids(res) and res.data["evidence_sources"]["metadata_strings"]["region_source"] == "locator"


def test_stage_region_from_engine_unity_is_used_when_valid(tmp_path):
    files = ub.build_hotfix_app(identifiers=["XLua"])
    meta = ub.build_metadata(["XLua"])
    unity = ub.metadata_result(files, string_region=None)
    ctx = ub.make_context(tmp_path, files, unity=unity)
    ctx.results["engine.unity"]["metadata"]["string_region"] = {"offset": 1, "size": 1}     # nonsense: must not break
    res = EngineUnityHotfixStage().run(ctx)
    assert "xlua" in fw_ids(res) and meta.string_region


def test_metadata_encrypted_degrades_to_native_symbols_and_files(tmp_path):
    files = ub.build_hotfix_app(metadata_encrypted=True, encrypted_binary=False,
                                binary_strings=["_xlua_pushcsobj", "_luaopen_xlua", STR_5_3],
                                loose={"Data/Raw/Lua/main.lua.bytes": ub.lua_chunk("5.3")})
    unity = ub.metadata_result(files, verdict="yes")
    ctx, res = run(tmp_path, files, unity=unity)
    assert res.status == Status.PARTIAL and "metadata_strings" in res.reason
    assert res.data["evidence_sources"]["metadata_strings"]["ran"] is False
    assert any("metadata_strings" in d for d in res.data["degraded"])
    assert "xlua" in fw_ids(res)
    assert res.data["lua"]["bytecode"]["by_version"] == {"5.3": 1}
    assert res.data["lua"]["runtime_versions"][0]["version"] == "5.3.6"
    assert res.data["lua"]["consistency"]["ok"] is True and res.data["lua"]["consistency"]["checked"] is True


def test_metadata_unreadable_with_clean_verdict_is_partial_not_crash(tmp_path):
    ctx, res = run(tmp_path, ub.build_hotfix_app(metadata_encrypted=True), unity=None)
    assert res.status == Status.PARTIAL
    assert finding(res, "unity.hotfix.framework").verdict in (Verdict.UNKNOWN, Verdict.SUSPECTED)


def test_file_clues_when_everything_else_is_unavailable(tmp_path):
    files = ub.build_hotfix_app(metadata_encrypted=True, extra={
        "Data/Raw/aa/settings.json": json.dumps({"m_AddressablesVersion": "1.21.2"}), "Data/Raw/aa/catalog.json": "{}"})
    _, res = run(tmp_path, files, unity=ub.metadata_result(files, verdict="yes"))
    assert "addressables" in fw_ids(res) and next(f for f in res.data["frameworks"] if f["id"] == "addressables")["version_hint"] == "1.21.2"


def test_hybridclr_and_xlua_coexist(tmp_path):
    lua = ub.textasset("Main.lua", ub.lua_chunk("luajit2.1", bits=64, strip=True))
    dll = ub.textasset("HotUpdate.dll", fb.build_pe_cli("HotUpdate", ["UnityEngine.CoreModule", "mscorlib"], types=6))
    files = ub.build_hotfix_app(identifiers=["HybridCLR", "HomologousImageMode", "XLua", "XLua.LuaDLL"],
                                bundles={"Data/Raw/scripts.bundle": ub.build_bundle([lua, dll])})
    _, res = run(tmp_path, files)
    assert {"hybridclr", "xlua"} <= fw_ids(res)
    assert res.data["lua"]["bytecode"]["by_version"] == {"luajit_2.1": 1}
    hot = [a for a in res.data["csharp"]["assemblies"] if a["kind"] == "hot"]
    assert [a["name"] for a in hot] == ["HotUpdate"] and hot[0]["source"] == "bundle"
    assert "HybridCLR" in res.data["summary_text"] and "xLua" in res.data["summary_text"] and "LuaJIT 2.1" in res.data["summary_text"]
    assert "scripts in AssetBundles" in res.data["summary_text"]
    st = res.data["storage"]
    assert st["in_bundles"]["lua"] == 1 and st["in_bundles"]["dll"] == 1 and st["loose"]["lua"] == 0
    assert finding(res, "unity.hotfix.framework").verdict == Verdict.YES


def test_pure_unity_without_hotfix_does_not_false_positive(tmp_path):
    files = ub.build_hotfix_app(extra={"Data/Raw/lua.png": b"\x89PNG\r\n\x1a\n" + b"\0" * 100,
                                       "Data/Raw/lua_ui/button.png": b"\x89PNG\r\n\x1a\n" + b"\0" * 50,
                                       "Data/Raw/music.ogg": b"OggS" + b"\0" * 60})
    _, res = run(tmp_path, files)
    assert res.status == Status.OK
    assert [f for f in res.data["frameworks"] if f["confidence"] >= 0.35] == []
    assert res.data["lua"]["files"]["total"] == 0 and res.data["csharp"]["assemblies"] == []
    assert finding(res, "unity.hotfix.lua").verdict in (Verdict.UNKNOWN, Verdict.NO)       # never "yes"
    assert finding(res, "unity.hotfix.framework").verdict in (Verdict.UNKNOWN, Verdict.NO)
    assert res.data["script_protection"]["lua"] in ("n/a", "unknown")


def test_clean_unencrypted_pure_unity_may_report_no_but_never_yes(tmp_path):
    files = ub.build_hotfix_app(encrypted_binary=False)
    _, res = run(tmp_path, files)
    assert finding(res, "unity.hotfix.framework").verdict == Verdict.NO
    assert finding(res, "unity.hotfix.lua").verdict == Verdict.NO
    assert res.data["script_protection"] == {"lua": "n/a", "js": "n/a", "csharp": "n/a"}


def test_encrypted_binary_fixture_produces_no_noise(tmp_path):
    files = ub.build_hotfix_app(encrypted_binary=True, binary_strings=["_xlua_pushcsobj", STR_5_3, "_ZN9hybridclr1"])
    _, res = run(tmp_path, files)
    assert fw_ids(res, 0.2) == set()
    nat = res.data["evidence_sources"]["native"]
    assert nat["limited_by_encryption"] is True and any("FairPlay" in n for n in nat["notes"])
    assert res.data["lua"]["runtime_versions"] == []
    assert any("native_signals" in d for d in res.data["degraded"])
    fnd = finding(res, "unity.hotfix.framework")
    assert "decrypted" in fnd.remediation and fnd.verdict != Verdict.YES
    assert "binary-based detection limited" in res.data["summary_text"]


def test_lua_version_profile_mixed_and_consistency_warning(tmp_path):
    loose = {"Data/Raw/Lua/a.lua.bytes": ub.lua_chunk("5.1", bits=32), "Data/Raw/Lua/b.lua.bytes": ub.lua_chunk("5.3"),
             "Data/Raw/Lua/c.lua.bytes": ub.lua_chunk("5.3"), "Data/Raw/Lua/d.lua": "print('x')\nlocal y = 1 // 2\n"}
    files = ub.build_hotfix_app(encrypted_binary=False, binary_strings=[STR_5_3], loose=loose, identifiers=["XLua"])
    _, res = run(tmp_path, files)
    lua = res.data["lua"]
    assert lua["bytecode"]["by_version"] == {"5.1": 1, "5.3": 2} and lua["files"]["plain"] == 1 and lua["files"]["total"] == 4
    assert lua["consistency"]["ok"] is False
    assert any("5.1" in n and "mismatch" in n for n in lua["consistency"]["notes"])
    assert any("5.3" in h for h in lua["dialect_hints"])
    assert lua["runtime_versions"][0]["version"] == "5.3.6"
    vf = finding(res, "unity.hotfix.lua_version")
    assert vf.verdict == Verdict.YES and vf.confidence <= 0.6
    assert finding(res, "unity.hotfix.lua").verdict == Verdict.YES


def test_lua_header_tamper_and_xor_make_custom_lua_suspected(tmp_path):
    xor = bytes(b ^ 0x5A for b in ub.lua_chunk("5.3"))
    loose = {"Data/Raw/Lua/a.lua.bytes": ub.lua_chunk("5.3", tamper="luac_int"), "Data/Raw/Lua/b.lua.bytes": xor,
             "Data/Raw/Lua/c.lua.bytes": urandom(5000)}
    _, res = run(tmp_path, ub.build_hotfix_app(loose=loose))
    lua = res.data["lua"]
    assert lua["custom_lua_suspected"] is True and lua["bytecode"]["invalid"] == 1
    assert lua["files"]["encrypted_suspected"] == 2
    assert res.data["script_protection"]["lua"] == "suspected"
    assert finding(res, "unity.hotfix.script_protection").verdict == Verdict.SUSPECTED


def test_plain_and_standard_bytecode_are_not_protected_but_not_claimed_encrypted(tmp_path):
    loose = {"Data/Raw/Lua/a.lua": "print(1)\n", "Data/Raw/Lua/b.lua.bytes": ub.lua_chunk("5.4"),
             "Data/Raw/Lua/c.lua.txt": zlib.compress(b"print(2)\n" * 100)}
    _, res = run(tmp_path, ub.build_hotfix_app(loose=loose))
    assert res.data["lua"]["files"]["compressed"] == 1 and res.data["lua"]["files"]["encrypted_suspected"] == 0
    assert res.data["script_protection"]["lua"] == "no"


def test_csharp_dll_classification_loose_and_bundle(tmp_path):
    pe = lambda n, refs=("UnityEngine.CoreModule", "mscorlib"), t=3: fb.build_pe_cli(n, list(refs), types=t)   # noqa: E731
    xor = bytes(b ^ 0x5A for b in pe("XorHot"))
    loose = {"Data/Raw/HotUpdate.dll.bytes": pe("HotUpdate"), "Data/Raw/mscorlib.dll.bytes": pe("mscorlib", ()),
             "Data/Raw/Comp.dll.bytes": zlib.compress(pe("Comp") * 3), "Data/Raw/Xor.dll.bytes": xor,
             "Data/Raw/Rand.dll.bytes": urandom(9000)}
    b = ub.build_bundle([ub.textasset("Bundled.dll", pe("BundledHot"))])
    _, res = run(tmp_path, ub.build_hotfix_app(identifiers=["HybridCLR"], loose=loose, bundles={"Data/Raw/c.bundle": b}))
    by = {a["name"]: a for a in res.data["csharp"]["assemblies"]}
    assert by["HotUpdate"]["kind"] == "hot" and by["HotUpdate"]["format"] == "pe_cli" and by["HotUpdate"]["asm_refs"]
    assert by["mscorlib"]["kind"] == "aot_meta"
    assert by["BundledHot"]["source"] == "bundle" and by["BundledHot"]["kind"] == "hot"
    formats = sorted(a["format"] for a in res.data["csharp"]["assemblies"])
    assert formats.count("compressed") == 1 and formats.count("encrypted_suspected") == 2
    xo = next(a for a in res.data["csharp"]["assemblies"] if a.get("xor_hypothesis"))
    assert xo["xor_hypothesis"]["key_hex"] == "5a"
    assert res.data["script_protection"]["csharp"] == "suspected"
    f = finding(res, "unity.hotfix.csharp_dll")
    assert f.verdict == Verdict.YES and "nothing is decrypted" in f.summary


def test_bundle_sampling_and_limits(tmp_path):
    bundles = {"Data/Raw/b%03d.bundle" % i: ub.build_filler_bundle(i) for i in range(120)}
    files = ub.build_hotfix_app(bundles=bundles)
    _, res = run(tmp_path, files)
    sc = res.data["storage"]["scanned"]
    assert sc["bundles_sampled"] == 100 and sc["total"] == 120 and sc["sample_ratio"] == pytest.approx(100 / 120, abs=1e-3)
    assert "sampled 100/120 bundles" in res.data["summary_text"]
    _, res = run(tmp_path / "small", files, unity_cfg={"hotfix_scan_bundles": 7})
    assert res.data["storage"]["scanned"]["bundles_sampled"] == 7


def test_per_bundle_byte_cap_is_honoured(tmp_path):
    big = fb.build_unityfs([random.Random(i).randbytes(32768) for i in range(60)], compression="lz4")
    files = ub.build_hotfix_app(bundles={"Data/Raw/big.bundle": big})
    _, res = run(tmp_path, files, unity_cfg={"hotfix_scan_bytes_per_bundle": 1 << 20})
    assert res.data["storage"]["scanned"]["bytes_scanned"] <= (1 << 20) + 200_000      # + the serialized files
    assert res.status == Status.OK


def test_unreadable_bundles_are_reported_not_hidden(tmp_path):
    bundles = {"Data/Raw/e%d.bundle" % i: urandom(70_000 + i) for i in range(3)}
    bundles["Data/Raw/ok.bundle"] = ub.build_filler_bundle(1)
    bundles["Data/Raw/blk.bundle"] = ub.build_bundle([b"q" * 5000])
    _, res = run(tmp_path, ub.build_hotfix_app(bundles=bundles))
    sc = res.data["storage"]["scanned"]
    assert sc["bundles_unreadable"] == 3 and sc["unreadable_by_reason"] == {"encrypted_suspected": 3}
    assert "3 sampled bundle(s) unreadable" in res.data["summary_text"]
    assert finding(res, "unity.hotfix.lua").verdict in (Verdict.UNKNOWN, Verdict.NO)
    assert res.data["script_protection"]["lua"] == "unknown"


def test_cdn_hosts_domain_only(tmp_path):
    files = ub.build_hotfix_app(
        literals=["https://user:pw@janacdn.example.cn:8443/game/v1/a.bundle?token=SECRET", "https://api.game.com/x",
                  "https://www.w3.org/2000/svg"],
        extra={"Data/Raw/version.txt": json.dumps({"version": "2.0", "files": [], "root": "https://dl.example-cdn.net/p/tok123/"}),
               "Data/Raw/aa/settings.json": json.dumps({"m_AddressablesVersion": "1.0.0"})})
    _, res = run(tmp_path, files)
    hosts = res.data["resource_update"]["hosts"]
    assert "janacdn.example.cn" in hosts and "dl.example-cdn.net" in hosts and "api.game.com" not in hosts
    blob = json.dumps(res.data["resource_update"]) + res.data["summary_text"] + finding(res, "unity.hotfix.resource_update").summary
    for bad in ("SECRET", "tok123", "8443", "pw@", "/game/v1", "w3.org"):
        assert bad not in blob, bad
    assert len(hosts) <= 20


def test_mono_app_without_metadata_still_runs(tmp_path):
    files = ub.build_hotfix_app(with_metadata=False, extra={"Data/Managed/Assembly-CSharp.dll": fb.build_pe_cli("Assembly-CSharp", ["mscorlib"], types=5)})
    unity = ub.metadata_result(files, present=False)
    unity["backend"] = "mono"
    unity["metadata"] = {"path": None, "present": False, "verdict": "unknown"}
    _, res = run(tmp_path, files, unity=unity)
    assert res.status == Status.OK and res.data["csharp"]["managed_dlls_in_data_managed"] == 1
    assert res.data["csharp"]["assemblies"] == []                  # the Mono main assembly is not a hot-update assembly


def test_missing_inventory_is_partial_not_crash(tmp_path):
    files = ub.build_hotfix_app(identifiers=["XLua"])
    ctx = ub.make_context(tmp_path, files)
    ctx.results.pop("inventory")
    res = EngineUnityHotfixStage().run(ctx)
    assert res.status == Status.PARTIAL and "inventory" in res.reason
    assert "xlua" in fw_ids(res)


def test_dump_namespaces_are_used_when_present(tmp_path):
    files = ub.build_hotfix_app(metadata_encrypted=True)
    unity = ub.metadata_result(files, verdict="yes")
    unity["dump"] = {"ran": True, "ok": True, "namespaces": ["YooAsset", "XLua.CSObjectWrap"], "summary": {"framework_namespaces": ["HybridCLR"]}}
    _, res = run(tmp_path, files, unity=unity)
    assert {"yooasset", "xlua", "hybridclr"} <= fw_ids(res)
    assert res.data["evidence_sources"]["dump_namespaces"]["used"] is True


def test_unattributed_scripts_still_answer_the_question(tmp_path):
    loose = {"Data/Raw/Lua/a.lua.bytes": ub.lua_chunk("5.3"), "Data/Raw/Hot.dll.bytes": fb.build_pe_cli("HotX", ["UnityEngine.CoreModule"], types=2)}
    _, res = run(tmp_path, ub.build_hotfix_app(loose=loose))
    ids = fw_ids(res)
    assert "lua_unattributed" in ids and "csharp_unattributed" in ids
    assert finding(res, "unity.hotfix.framework").verdict == Verdict.SUSPECTED
    assert "scripts in loose files" in res.data["summary_text"]


def test_output_shape_is_json_and_contract_complete(tmp_path):
    loose = {"Data/Raw/Lua/a.lua.bytes": ub.lua_chunk("5.3")}
    _, res = run(tmp_path, ub.build_hotfix_app(identifiers=["XLua"], loose=loose))
    data = res.data
    assert json.loads(json.dumps(to_jsonable(data))) == to_jsonable(data)
    for key in ("frameworks", "lua", "js", "csharp", "resource_update", "storage", "script_protection", "summary_text"):
        assert key in data
    for f in data["frameworks"]:
        assert {"id", "name", "kind", "confidence", "version_hint", "evidence"} <= set(f) and f["kind"] in ("csharp", "lua", "js", "resource")
    assert {"runtime_versions", "bytecode", "files", "dialect_hints", "consistency", "custom_lua_suspected"} <= set(data["lua"])
    assert {"by_version", "invalid", "stripped_count", "arch_bits"} <= set(data["lua"]["bytecode"])
    assert {"plain", "bytecode", "compressed", "encrypted_suspected", "total"} <= set(data["lua"]["files"])
    assert {"ok", "notes"} <= set(data["lua"]["consistency"])
    assert {"backends", "files", "formats"} <= set(data["js"]) and {"plain", "encrypted_suspected", "total"} <= set(data["js"]["files"])
    assert {"frameworks", "catalogs", "manifests", "hosts"} <= set(data["resource_update"])
    assert {"loose", "in_bundles", "in_serialized", "scanned"} <= set(data["storage"])
    assert {"bundles_sampled", "total"} <= set(data["storage"]["scanned"])
    assert set(data["script_protection"]) == {"lua", "js", "csharp"}
    assert all(v in {v_.value for v_ in Verdict} for v in data["script_protection"].values())
    assert {f.id for f in res.findings} == FINDING_IDS
    for f in res.findings:
        assert f.title and f.summary and 0 <= f.confidence <= 1
    # protection verdicts are never 'no' for what could not be inspected
    assert data["frameworks"][0]["version_hint"] is None


def test_runs_through_the_real_pipeline(tmp_path):
    from ipa_analyzer.config import Config
    from ipa_analyzer.context import AnalysisContext
    files = ub.build_hotfix_app(identifiers=["XLua"])
    ctx = ub.make_context(tmp_path, files)
    ctx.cfg.stages = ("engine.unity.hotfix",)
    # engine.unity is a hard dependency, so the full chain is selected; here we only check registration wiring
    reg = pipeline.ensure_analyzers_loaded()
    assert "engine.unity" in reg.closure([NAME]) and isinstance(ctx.cfg, Config) and isinstance(ctx, AnalysisContext)


def test_block_encrypted_and_high_entropy_bundles_degrade_gracefully(tmp_path):
    from fixtures import unity_builder as wp5
    bundles = {"Data/Raw/blk%d.bundle" % i: wp5.build_block_encrypted_bundle(seed=5 + i) for i in range(4)}
    bundles["Data/Raw/enc.bundle"] = urandom(80_000)
    bundles["Data/Raw/std.bundle"] = ub.build_filler_bundle(2)
    _, res = run(tmp_path, ub.build_hotfix_app(identifiers=["HybridCLR", "HomologousImageMode"], bundles=bundles))
    assert res.status == Status.OK
    sc = res.data["storage"]["scanned"]
    assert sc["bundles_unreadable"] == 5 and sc["bundles_readable"] == 1
    assert sc["unreadable_by_reason"] == {"block_decompress_failed": 4, "encrypted_suspected": 1}
    # the framework is still identified from metadata, but scripts cannot be located: unknown, never "no"
    assert "hybridclr" in fw_ids(res)
    assert res.data["script_protection"]["csharp"] == "unknown"
    assert res.data["script_protection"]["lua"] == "unknown"
    assert finding(res, "unity.hotfix.lua").verdict == Verdict.UNKNOWN
    assert "unreadable" in res.data["summary_text"]


def test_i18n_placeholders_are_all_provided_by_finding_params(tmp_path):
    import string
    from ipa_analyzer.util.paths import resource_dir
    _, res = run(tmp_path, ub.build_hotfix_app(identifiers=["XLua"], loose={"Data/Raw/Lua/a.lua.bytes": ub.lua_chunk("5.3")}))
    for lang in ("zh", "en"):
        doc = json.loads((resource_dir("data") / "i18n" / lang / "unity_hotfix.json").read_text(encoding="utf-8"))
        for f in res.findings:
            entry = doc[f.id]
            assert entry["title"] and entry["summary"]
            for text in (entry["summary"], entry["remediation"]):
                fields = {n for _, n, _, _ in string.Formatter().parse(text) if n}
                assert fields <= set(f.params), (lang, f.id, fields - set(f.params))
                text.format_map(f.params)
