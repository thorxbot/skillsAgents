from __future__ import annotations

import io

import pytest

from fixtures import unity_hotfix_builder as ub
from ipa_analyzer.unity.hotfix import detect, metadata_strings as ms

RULES = detect.load_rules()


def scan(built, **kw):
    return ms.scan_metadata(io.BytesIO(built.data), len(built.data), RULES, ref="meta", **kw)


def ids(res):
    return {f["id"] for f in detect.merge_frameworks(RULES, res.observations)}


@pytest.mark.parametrize("layout", ["v31", "v39"])
def test_pool_located_without_stage_region(layout):
    built = ub.build_metadata(["HybridCLR", "HomologousImageMode", "XLua"], layout=layout)
    res = scan(built, region=None)
    assert res.ran and res.region_source == "locator" and res.region == built.string_region
    assert {"hybridclr", "xlua"} <= ids(res)


def test_stage_region_used_when_plausible_and_bad_region_relocated():
    built = ub.build_metadata(["Puerts", "BackendV8"], layout="v39")
    res = scan(built, region=built.string_region)
    assert res.region_source == "stage" and "puerts" in ids(res)
    wrong = {"offset": 24, "size": 100}                      # hard-coded v31 offset on a v39-like file
    res = scan(built, region=wrong)
    assert res.region_source == "locator" and "puerts" in ids(res)
    assert any("does not look like an identifier pool" in n for n in res.notes)
    res = scan(built, region={"offset": len(built.data) + 5, "size": 10})
    assert res.region_source == "locator"


@pytest.mark.parametrize("verdict", ["yes", "suspected"])
def test_encrypted_metadata_is_skipped_not_scanned(verdict):
    built = ub.build_metadata(["HybridCLR"])
    res = scan(built, verdict=verdict)
    assert not res.ran and res.observations == [] and "verdict" in res.skipped_reason


def test_random_data_yields_no_pool():
    built = ub.build_metadata(encrypted=True)
    res = scan(built, verdict="unknown")
    assert not res.ran and res.skipped_reason and res.observations == []


def test_clean_pool_has_no_frameworks_and_lists_assemblies():
    res = scan(ub.build_metadata(["PlayerController", "Core.HybridCLR", "HybridCLROptimizer", "XLuaX"]))
    assert res.ran and ids(res) == set()
    assert "Assembly-CSharp.dll" in res.assemblies and "mscorlib.dll" in res.assemblies


def test_assemblies_and_protection_hints():
    res = scan(ub.build_metadata(["HybridCLR.Runtime.dll", "EncryptedAssetBundleProvider", "SignatureLoader", "LuaScriptDecrypt"]))
    assert "HybridCLR.Runtime.dll" in res.assemblies and "hybridclr" in ids(res)
    kinds = {(h["id"], h["identifier"]) for h in res.protection_hints}
    assert ("bundle_crypto", "EncryptedAssetBundleProvider") in kinds and ("script_signature", "SignatureLoader") in kinds
    assert ("script_crypto", "LuaScriptDecrypt") in kinds


def test_custom_hotupdate_naming_hint():
    res = scan(ub.build_metadata(["HotFixManager", "HotUpdateConfig", "InitHotFixAsync"]))
    fw = {f["id"]: f for f in detect.merge_frameworks(RULES, res.observations)}
    assert "custom_hotupdate" in fw and fw["custom_hotupdate"]["confidence"] <= 0.45


def test_non_ascii_and_overlong_tokens_are_ignored():
    pool_ids = ["éè".encode("utf-8").decode("latin-1")]
    res = scan(ub.build_metadata(pool_ids + ["A" * 400]))
    assert res.ran


def test_tokens_cross_chunk_boundaries():
    data = b"mscorlib\0" + b"x" * 7 + b"\0HybridCLR\0" + b"y\0" * 300
    fobj = io.BytesIO(data)
    toks = list(ms.iter_pool_tokens(fobj, 0, len(data), chunk=5))
    assert b"HybridCLR" in toks and toks[0] == b"mscorlib"
