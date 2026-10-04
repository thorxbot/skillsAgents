from __future__ import annotations

import json
import re

import pytest

from ipa_analyzer.unity.hotfix import detect
from ipa_analyzer.util.paths import resource_dir

DOC = json.loads((resource_dir("data") / "hotfix.json").read_text(encoding="utf-8"))
RULES = detect.load_rules()


def test_every_signal_has_sources_and_known_type():
    types = {"namespace", "type", "assembly", "native_regex", "native_literal", "file", "pool_regex"}
    ids = set()
    for fw in DOC["frameworks"]:
        assert fw["id"] not in ids
        ids.add(fw["id"])
        assert fw["kind"] in ("csharp", "lua", "js", "resource")
        assert fw["signals"]
        for s in fw["signals"]:
            assert s["type"] in types, (fw["id"], s)
            assert s["sources"], (fw["id"], s)
            assert 0 < s["weight"] <= 1
    for h in DOC["protection_hints"] + DOC["js_backends"]:
        assert h["sources"]
        re.compile(h["regex"])


def test_unverified_signals_are_downweighted():
    sig = next(s for s in RULES.frameworks["slua"].signals if s.type == "namespace")
    assert sig.unverified and RULES.effective_weight(sig) < sig.weight
    ver = next(s for s in RULES.frameworks["xlua"].signals if s.type == "namespace")
    assert not ver.unverified and RULES.effective_weight(ver) == ver.weight


@pytest.mark.parametrize("token,fw", [
    ("HybridCLR", "hybridclr"), ("HybridCLR.Runtime", "hybridclr"), ("XLua", "xlua"), ("XLua.LuaDLL", "xlua"),
    ("ILRuntime.Runtime.Enviorment", "ilruntime"), ("LuaInterface", "tolua"), ("Puerts", "puerts"),
    ("YooAsset", "yooasset"), ("UnityEngine.AddressableAssets.Initialization", "addressables"),
    ("IFix.Core", "ifix"), ("MoonSharp.Interpreter.Debugging", "moonsharp"),
])
def test_namespace_matching_is_segment_wise(token, fw):
    assert fw in {s.framework for s, how in RULES.match_token(token)}


@pytest.mark.parametrize("token", ["Core.HybridCLR", "HybridCLROptimizer", "XLuaX", "MyXLua", "Puertsish", "IFixer",
                                   "UnityEngine.Object", "System.Collections", "Lua", "luaEvaluate"])
def test_lookalikes_do_not_match(token):
    assert not RULES.match_token(token)


def test_merge_confidence_rules():
    sig = RULES.frameworks["slua"].signals[0]
    ob = detect.Observation("slua", "metadata", "namespace", sig.value, sig.weight, unverified=True)
    fw = detect.merge_frameworks(RULES, [ob])
    assert fw and fw[0]["confidence"] < 0.5                       # unverified rule alone stays weak
    strong = [detect.Observation("xlua", "metadata", "namespace", "XLua", 0.75, strong=True),
              detect.Observation("xlua", "native", "native_regex", "xlua_", 0.8)]
    fw = detect.merge_frameworks(RULES, strong)
    assert fw[0]["id"] == "xlua" and fw[0]["confidence"] > 0.9 and fw[0]["version_hint"] is None
    # the same signal reported many times does not stack
    many = [detect.Observation("xlua", "metadata", "namespace", "XLua", 0.75)] * 5
    assert detect.merge_frameworks(RULES, many)[0]["confidence"] == pytest.approx(0.75, abs=0.01)
    assert detect.merge_frameworks(RULES, [detect.Observation("nope", "metadata", "type", "x", 0.9)]) == []


def test_custom_hotupdate_is_capped():
    obs = [detect.Observation("custom_hotupdate", "metadata", "pool_regex", "HotFix%d" % i, 0.3, unverified=True)
           for i in range(20)]
    assert detect.merge_frameworks(RULES, obs)[0]["confidence"] <= 0.45


def test_aot_and_hot_name_helpers():
    assert RULES.is_aot_name("mscorlib") and RULES.is_aot_name("System.Core.dll") and RULES.is_aot_name("UnityEngine.CoreModule")
    assert RULES.is_aot_name("Custom", known_aot=["Custom"])
    assert not RULES.is_aot_name("HotUpdate")
    assert RULES.looks_hot_name("HotUpdate.dll") and RULES.looks_hot_name("Hotfix")
