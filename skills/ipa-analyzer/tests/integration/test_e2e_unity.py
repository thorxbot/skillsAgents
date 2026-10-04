"""Unity end to end: IL2CPP / Mono / metadata / AssetBundle matrix (DoD 2, 3, 4, 6) and the hot-update family (DoD 7).

Every assertion is made on the ``report.json`` the user would get from ``scripts/ipa_analyze.py``.
"""
from __future__ import annotations

import pytest

from fixtures.e2e_support import run_cli
from fixtures.full_ipa_builders import DUMPER_SCRIPT, build_unity_variant


# ----------------------------------------------------------------------------------------- IL2CPP basics
def test_plain_il2cpp_is_recognised_and_ready_to_dump(runs):
    r = runs.cli("unity_il2cpp_plain")
    u = r.details["unity"]
    assert r.details["detect"]["primary"]["id"] == "unity" and r.details["detect"]["primary"]["confirmed"]
    assert r.verdict("engine.primary") == "yes" and r.verdict("unity.detected") == "yes"
    assert u["backend"] == "il2cpp" and u["version"]["value"] == "2021.3.16f1"
    assert r.verdict("unity.backend") == "yes"
    assert u["metadata"]["present"] and u["metadata"]["version"] == 24 and u["metadata"]["header_ok"] is True
    assert r.verdict("unity.metadata.present") == "yes" and r.verdict("unity.metadata.encrypted") == "no"
    assert u["bundles"]["by_class"]["standard"] == 5 and r.verdict("unity.assetbundle.encryption") == "no"
    assert r.verdict("unity.binary.fairplay") == "no" and r.verdict("protect.fairplay") == "no"
    assert r.verdict("unity.il2cpp.precheck") == "yes" and u["precheck"]["ready"] is True
    assert r.verdict("engine.custom") == "no"
    assert r.report["classification"]["category"] == "game"


def test_without_dotnet_and_tool_offline_the_report_is_complete_and_the_dump_failure_is_actionable(runs):
    """DoD 6 (library level; the hermetic process-level variant is in test_no_dotnet_offline.py)."""
    r = runs.cli("unity_il2cpp_plain")
    assert r.returncode == 0
    dump = r.details["unity"]["dump"]
    assert dump["ran"] is True and dump["ok"] is False and dump["error_code"] == "E_TOOL_DOWNLOAD_FAILED"
    assert dump["artifacts"] == {} or "dump.cs" not in dump["artifacts"]
    f = r.finding("unity.il2cpp.dump")
    assert f["verdict"] == "no" and f["params"]["error_code"] == "E_TOOL_DOWNLOAD_FAILED"
    assert "--il2cpp-tool" in f["remediation"] and "--offline" in f["remediation"]        # tells the user what to do
    st = r.stage("engine.unity")
    assert st["status"] == "partial" and "E_TOOL_DOWNLOAD_FAILED" in st["reason"]
    assert "E_TOOL_DOWNLOAD_FAILED" in r.md and "能否 dump" in r.md
    for name in ("meta", "libs", "protect", "classify", "report"):
        assert r.stage(name)["status"] == "ok"                        # everything else is complete


def test_fake_dumper_produces_a_dump_summary(runs):
    """DoD acceptance: with a (fake) dumper injected, the same fixture yields a full dump summary.

    The tool path is deliberately *relative* (the dumper runs in another working directory): this caught a bug
    where the relative path was resolved against the scratch directory.
    """
    r = runs.cli("unity_il2cpp_plain", "--il2cpp-tool", "tests/fixtures/fake_dumper.py")
    assert r.returncode == 0
    assert r.verdict("unity.il2cpp.dump") == "yes"
    dump = r.details["unity"]["dump"]
    assert dump["ok"] and dump["error_code"] is None and dump["backend"] == "il2cppdumper"
    assert {"dump.cs", "script.json", "il2cpp.h", "stringliteral.json", "DummyDll"} <= set(dump["artifacts"])
    s = dump["summary"]
    assert s["assemblies"] == 2 and s["classes"] == 2 and s["methods"] == 3 and s["string_literals"] == 2
    assert s["framework_namespaces"] == ["HybridCLR"] and s["obfuscation"]["level"] == "none"
    assert r.stage("engine.unity")["status"] == "ok"
    out = r.report_path.parent
    for rel in dump["artifacts"].values():
        assert (out / rel).exists()
    assert "已成功 dump" in r.md
    assert r.verdict("unity.il2cpp.names_obfuscated") == "no"


def test_fake_dumper_abs_path_equivalent(runs):
    r = runs.cli("unity_il2cpp_plain", "--il2cpp-tool", str(DUMPER_SCRIPT))
    assert r.verdict("unity.il2cpp.dump") == "yes"


def test_no_il2cpp_flag_skips_the_dump(runs):
    r = runs.cli("unity_il2cpp_plain", "--no-il2cpp", "--il2cpp-tool", str(DUMPER_SCRIPT))
    assert r.returncode == 0 and not r.details["unity"]["dump"].get("ok")
    assert r.verdict("unity.il2cpp.dump") in ("no", "n/a")


def test_fairplay_encrypted_binary_blocks_the_dump(runs):
    """DoD 3: cryptid=1 -> protect.fairplay yes, dump skipped with E_BINARY_FAIRPLAY and advice."""
    r = runs.cli("unity_il2cpp_encrypted_binary", "--il2cpp-tool", str(DUMPER_SCRIPT))   # even with a working tool
    assert r.returncode == 0
    assert r.verdict("protect.fairplay") == "yes" and r.verdict("unity.binary.fairplay") == "yes"
    fp = r.report["protection"]
    assert any(f["id"] == "protect.fairplay" and f["verdict"] == "yes" for f in fp["findings"])
    assert r.verdict("unity.il2cpp.precheck") == "no"
    dump = r.details["unity"]["dump"]
    assert dump["ok"] is False and dump["error_code"] == "E_BINARY_FAIRPLAY"
    assert not dump.get("artifacts"), "a FairPlay-encrypted binary must never reach the dumper"
    f = r.finding("unity.il2cpp.dump")
    assert f["params"]["error_code"] == "E_BINARY_FAIRPLAY" and f["remediation"]
    assert "decrypt" in f["remediation"].lower() or "解密" in f["remediation"]
    assert "FairPlay" in r.md
    # metadata / bundle / hot-update evidence that does not need the binary is still produced
    assert r.verdict("unity.metadata.encrypted") == "no" and r.verdict("unity.assetbundle.encryption") == "no"


def test_xor_metadata_and_high_entropy_bundles(runs):
    r = runs.cli("unity_il2cpp_meta_xor")
    u = r.details["unity"]
    assert r.verdict("unity.metadata.encrypted") in ("yes", "suspected")
    assert r.verdict("unity.metadata.encrypted") != "no" and u["metadata"]["verdict"] in ("yes", "suspected")
    assert r.verdict("unity.assetbundle.encryption") == "yes"
    assert u["bundles"]["by_class"]["high_entropy_unknown"] == 4 and u["bundles"]["by_class"]["standard"] == 1
    assert u["precheck"]["ready"] is False and u["precheck"]["error_code"] == "E_METADATA_ENCRYPTED"
    assert u["dump"]["error_code"] == "E_METADATA_ENCRYPTED"
    # the hot-update stage degrades (no metadata string table) and says so instead of reporting "no framework"
    hf = r.stage("engine.unity.hotfix")
    assert hf["status"] == "partial" and "metadata_strings" in hf["reason"]
    assert r.verdict("unity.hotfix.framework") in ("unknown", "suspected")


def test_mono_backend_and_encrypted_dll(runs):
    r = runs.cli("unity_mono")
    u = r.details["unity"]
    assert u["backend"] == "mono" and r.verdict("unity.backend") == "yes"
    assert r.verdict("unity.il2cpp.dump") == "n/a" and r.verdict("unity.il2cpp.precheck") == "n/a"
    assert r.verdict("unity.mono.dll_encrypted") == "suspected"
    by = {a["path"].rsplit("/", 1)[-1]: a for a in u["mono"]["assemblies"]}
    assert by["Plain.dll"]["valid_pe_cli"] is True and by["Encrypted.dll"]["valid_pe_cli"] is False
    assert r.verdict("unity.metadata.present") == "no"


# ----------------------------------------------------------------------------- metadata / bundle matrix (DoD 2)
@pytest.mark.parametrize("variant,encrypted", [("normal", {"no"}), ("wrong_magic", {"yes", "suspected"}),
                                               ("xor_strings", {"yes", "suspected"}), ("xor_header", {"yes", "suspected"}),
                                               ("random", {"yes", "suspected"}), ("truncated", {"yes", "suspected"})])
def test_metadata_variants(runs, tmp_path, variant, encrypted):
    ipa = build_unity_variant(tmp_path / "ipa", "m_" + variant, metadata_variant=variant)
    r = run_cli(ipa, tmp_path / "out", runs.home, ["--stages", "engine.unity"], name=variant)
    assert r.returncode == 0, r.proc.stderr[-800:]
    assert r.verdict("unity.metadata.encrypted") in encrypted, r.finding("unity.metadata.encrypted")
    ready = r.details["unity"]["precheck"]["ready"]
    assert ready is (variant == "normal")
    if variant != "normal":
        assert r.details["unity"]["precheck"]["error_code"] == "E_METADATA_ENCRYPTED"
        assert r.verdict("unity.il2cpp.precheck") == "no"       # never a blind dumper run on modified metadata


@pytest.mark.parametrize("variant,verdicts,klass", [
    ("standard", {"no"}, "standard"), ("standard_lzma", {"no"}, "standard"), ("standard_none", {"no"}, "standard"),
    ("standard_lz4hc", {"no"}, "standard"), ("offset_prefix", {"suspected", "yes"}, "offset_prefix"),
    ("xor_single", {"yes"}, "xor_simple"), ("xor_repeating", {"yes"}, "xor_simple"),
    ("high_entropy", {"yes"}, "high_entropy_unknown")])
def test_assetbundle_variants(runs, tmp_path, variant, verdicts, klass):
    ipa = build_unity_variant(tmp_path / "ipa", "b_" + variant, bundle_variant=variant)
    r = run_cli(ipa, tmp_path / "out", runs.home, ["--stages", "engine.unity"], name=variant)
    assert r.returncode == 0
    assert r.verdict("unity.assetbundle.encryption") in verdicts
    assert r.details["unity"]["bundles"]["by_class"][klass] == 5
    assert r.verdict("unity.assetbundle.encryption") != "unknown"


# ------------------------------------------------------------------------------------------------- hot update
def fw_ids(r, minimum=0.5):
    return {f["id"] for f in r.details["unity"]["hotfix"]["frameworks"] if f["confidence"] >= minimum}


def test_hot_update_stage_runs_on_every_unity_fixture_with_all_contract_findings(runs):
    ids = {"unity.hotfix.framework", "unity.hotfix.lua", "unity.hotfix.lua_version", "unity.hotfix.csharp_dll",
           "unity.hotfix.js", "unity.hotfix.resource_update", "unity.hotfix.script_protection"}
    for name in ("unity_hybridclr", "unity_ilruntime", "unity_xlua_lua53", "unity_tolua_luajit", "unity_lua_mixed_versions",
                 "unity_lua_tampered", "unity_puerts_quickjs", "unity_addressables_remote", "unity_hotdll_encrypted"):
        r = runs.cli(name)
        assert r.stage("engine.unity.hotfix")["status"] == "ok", name
        assert ids <= {f["id"] for f in r.report["findings"]}, name
        h = r.details["unity"]["hotfix"]
        assert {"frameworks", "lua", "js", "csharp", "resource_update", "storage", "script_protection", "summary_text"} <= set(h)


def test_hybridclr(runs):
    r = runs.cli("unity_hybridclr")
    assert fw_ids(r) == {"hybridclr"} and r.verdict("unity.hotfix.framework") == "yes"
    asm = {a["name"]: a for a in r.details["unity"]["hotfix"]["csharp"]["assemblies"]}
    assert asm["HotUpdate"]["kind"] == "hot" and asm["HotUpdate"]["source"] == "bundle" and asm["HotUpdate"]["format"] == "pe_cli"
    assert asm["mscorlib"]["kind"] == "aot_meta" and asm["System"]["kind"] == "aot_meta"      # AOT supplementary metadata DLLs
    assert r.verdict("unity.hotfix.csharp_dll") == "yes" and r.verdict("unity.hotfix.script_protection") == "no"
    assert r.verdict("unity.hotfix.lua") in ("no", "unknown")


def test_ilruntime(runs):
    r = runs.cli("unity_ilruntime")
    assert fw_ids(r) == {"ilruntime"}
    asm = r.details["unity"]["hotfix"]["csharp"]["assemblies"]
    assert [(a["name"], a["source"], a["kind"]) for a in asm] == [("Hotfix", "loose", "hot")]
    assert "ILRuntime" in asm[0]["asm_refs"]


def test_xlua_with_lua53_bytecode_in_a_bundle(runs):
    r = runs.cli("unity_xlua_lua53")
    h = r.details["unity"]["hotfix"]
    assert fw_ids(r) == {"xlua"} and r.verdict("unity.hotfix.framework") == "yes"
    assert h["lua"]["bytecode"]["by_version"] == {"5.3": 2} and h["lua"]["bytecode"]["arch_bits"] == {"64": 2}
    assert h["lua"]["runtime_versions"][0]["version"] == "5.3.6" and h["lua"]["runtime_versions"][0]["flavor"] == "puc"
    assert h["lua"]["consistency"]["ok"] is True and h["lua"]["custom_lua_suspected"] is False
    assert h["storage"]["in_bundles"]["lua"] == 2 and h["storage"]["loose"]["lua"] == 0
    assert h["script_protection"]["lua"] == "no"
    assert r.verdict("unity.hotfix.lua_version") == "yes"
    # compiled is not encrypted -- the finding must say so rather than claim protection
    prot = r.finding("unity.hotfix.script_protection")
    assert prot["verdict"] == "no" and ("compiled" in prot["summary"].lower() or "bytecode" in prot["summary"].lower())


def test_tolua_with_luajit_bytecode(runs):
    r = runs.cli("unity_tolua_luajit")
    h = r.details["unity"]["hotfix"]
    assert fw_ids(r) == {"tolua"}
    assert h["lua"]["bytecode"]["by_version"] == {"luajit_2.1": 1} and h["lua"]["bytecode"]["stripped_count"] == 1
    assert h["lua"]["runtime_versions"][0]["flavor"] == "luajit" and h["lua"]["runtime_versions"][0]["version"].startswith("2.1")
    assert h["lua"]["consistency"]["ok"] is True and h["script_protection"]["lua"] == "no"


def test_mixed_lua_versions_raise_a_consistency_warning(runs):
    r = runs.cli("unity_lua_mixed_versions")
    lua = r.details["unity"]["hotfix"]["lua"]
    assert lua["bytecode"]["by_version"] == {"5.1": 2, "5.4": 2}
    assert lua["consistency"]["ok"] is False
    notes = " ".join(lua["consistency"]["notes"])
    assert "5.1" in notes and "5.4" in notes and "5.3" in notes and "mismatch" in notes
    assert lua["runtime_versions"][0]["version"] == "5.3.6"
    f = r.finding("unity.hotfix.lua_version")
    assert f["verdict"] == "yes" and f["confidence"] <= 0.6                  # a contradiction caps the confidence


def test_tampered_lua_headers_are_reported_as_suspected(runs):
    r = runs.cli("unity_lua_tampered")
    lua = r.details["unity"]["hotfix"]["lua"]
    assert lua["custom_lua_suspected"] is True and lua["bytecode"]["invalid"] == 1
    assert lua["files"]["encrypted_suspected"] == 2
    assert r.details["unity"]["hotfix"]["script_protection"]["lua"] == "suspected"
    assert r.verdict("unity.hotfix.script_protection") == "suspected"
    assert any(f["id"] == "unity.hotfix.script_protection" for f in r.report["protection"]["findings"])


def test_puerts_with_quickjs(runs):
    r = runs.cli("unity_puerts_quickjs")
    h = r.details["unity"]["hotfix"]
    assert fw_ids(r) == {"puerts"}
    assert [b["id"] for b in h["js"]["backends"]] == ["quickjs"]
    assert h["js"]["files"]["plain"] == 1 and h["script_protection"]["js"] == "no"
    assert r.verdict("unity.hotfix.js") == "yes"


def test_addressables_remote_catalog(runs):
    r = runs.cli("unity_addressables_remote")
    ru = r.details["unity"]["hotfix"]["resource_update"]
    assert fw_ids(r) == {"addressables"} and r.verdict("unity.hotfix.resource_update") == "yes"
    assert ru["frameworks"][0]["id"] == "addressables" and ru["frameworks"][0]["version_hint"] == "1.21.2"
    assert ru["hosts"] == ["cdn.example-game.net"]                          # domain only: no path, no query
    assert ru["catalogs"] and ru["catalogs"][0]["kind"] == "local"


def test_encrypted_hot_dlls_are_suspected_not_decrypted(runs):
    r = runs.cli("unity_hotdll_encrypted")
    h = r.details["unity"]["hotfix"]
    assert fw_ids(r) == {"hybridclr"}
    assert {a["format"] for a in h["csharp"]["assemblies"]} == {"encrypted_suspected"}
    xor = [a for a in h["csharp"]["assemblies"] if a.get("xor_hypothesis")]
    assert xor and xor[0]["xor_hypothesis"]["key_hex"] == "5a"               # a hypothesis only, nothing is decrypted
    assert h["script_protection"]["csharp"] == "suspected"
    f = r.finding("unity.hotfix.csharp_dll")
    assert f["verdict"] == "suspected" and "nothing is decrypted" in f["summary"]


def test_non_unity_apps_show_why_the_unity_stages_were_skipped(runs):
    r = runs.cli("flutter_app")
    assert r.stage("engine.unity")["status"] == "skipped" and r.stage("engine.unity")["reason"] == "not a Unity app"
    assert r.stage("engine.unity.hotfix")["reason"] == "dependency engine.unity skipped"
    assert "不是 Unity 应用" in r.md
