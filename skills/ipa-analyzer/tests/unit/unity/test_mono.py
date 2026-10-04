"""Mono assemblies: genuine DLL / random non-PE data / PE without CLI metadata."""
from __future__ import annotations

import io

from fixtures.formats_builder import build_pe_cli
from fixtures.unity_builder import mono_samples
from ipa_analyzer.unity import mono as um


def run(files):
    return um.analyze_mono(sorted(files), lambda n: io.BytesIO(files[n]), lambda n: len(files[n]))


def test_genuine_assemblies_are_no():
    s = mono_samples()
    r = run({"Data/Managed/Assembly-CSharp.dll": s["good"], "Data/Managed/UnityEngine.dll": s["good"]})
    assert r["verdict"] == "no" and all(a["valid_pe_cli"] and a["format"] == "pe_cli" for a in r["assemblies"])
    assert r["assemblies"][0]["assembly_name"] == "Assembly-CSharp"


def test_random_main_assembly_is_yes():
    s = mono_samples()
    r = run({"Data/Managed/Assembly-CSharp.dll": s["random"], "Data/Managed/UnityEngine.dll": s["good"]})
    assert r["verdict"] == "yes" and "main_assembly_encrypted" in r["reasons"]
    bad = next(a for a in r["assemblies"] if not a["valid_pe_cli"])
    assert bad["format"] == "encrypted_suspected" and bad["entropy"] > 7


def test_pe_without_bsjb_is_suspected():
    s = mono_samples()
    r = run({"Data/Managed/Assembly-CSharp.dll": s["pe_no_cli"]})
    assert r["verdict"] == "suspected"
    assert r["assemblies"][0]["format"] == "pe_no_cli" and r["assemblies"][0]["valid_pe_cli"] is False


def test_compressed_dll_is_not_called_encrypted():
    gz = b"\x1f\x8b\x08\x00" + bytes(range(200)) * 3
    r = run({"Data/Managed/Assembly-CSharp.dll": gz})
    assert r["assemblies"][0]["format"] == "compressed" and r["verdict"] == "suspected"


def test_no_assemblies_is_na():
    assert um.analyze_mono([], None, None)["verdict"] == "n/a"


def test_unreadable_and_large_are_tolerated():
    def boom(_n):
        raise OSError("no")
    r = um.analyze_mono(["a.dll"], boom, lambda n: 10)
    assert r["verdict"] == "unknown" and r["assemblies"][0]["format"] == "unreadable"
    r = um.analyze_mono(["big.dll"], boom, lambda n: um.MAX_ASSEMBLY_READ + 1)
    assert r["assemblies"][0]["format"] == "skipped_large"


def test_obfuscator_markers_are_low_confidence_hints():
    dll = build_pe_cli("Assembly-CSharp", ["mscorlib"], 3) + b"\x00ConfusedByAttribute\x00"
    r = run({"Data/Managed/Assembly-CSharp.dll": dll})
    assert r["assemblies"][0]["obfuscator_hints"] == ["confuserex"] and r["verdict"] == "no"
    assert r["obfuscator_hints"] == ["confuserex"]


def test_select_assemblies_orders_main_first_and_filters():
    pairs = [("A/Data/Managed/System.dll", "Data/Managed/System.dll"),
             ("A/Data/Managed/Assembly-CSharp.dll", "Data/Managed/Assembly-CSharp.dll"),
             ("A/Data/Managed/Resources/x.dll", "Data/Managed/Resources/x.dll"),
             ("A/Frameworks/x.dll", "Frameworks/x.dll")]
    assert um.select_assemblies(pairs) == ["A/Data/Managed/Assembly-CSharp.dll", "A/Data/Managed/System.dll"]
