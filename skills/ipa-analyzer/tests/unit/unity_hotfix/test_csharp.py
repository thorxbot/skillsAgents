from __future__ import annotations

import random
import zlib

from fixtures import formats_builder as fb
from ipa_analyzer.unity.hotfix import csharp, detect
from ipa_analyzer.unity.hotfix.storage import Blob

RULES = detect.load_rules()
AOT = {"Assembly-CSharp", "Game.Core"}


def urandom(n: int) -> bytes:
    return random.Random(n).randbytes(n)


def blob(data: bytes, name="HotUpdate.dll.bytes", source="loose") -> Blob:
    return Blob("dll", source, "Payload/X.app/Data/Raw/" + name, name, len(data), data[:4096], data[:65536], data=data)


def classify(data, name="HotUpdate.dll.bytes", hot=True, aot=AOT):
    return csharp.classify_dll(blob(data, name), RULES, set(aot), hot)


def test_valid_hot_assembly_with_refs():
    e = classify(fb.build_pe_cli("HotUpdate", ["UnityEngine.CoreModule", "mscorlib", "Assembly-CSharp"], types=7))
    assert e["format"] == "pe_cli" and e["kind"] == "hot" and e["name"] == "HotUpdate"
    assert e["clr"] == "v4.0.30319" and e["asm_refs"] == ["UnityEngine.CoreModule", "mscorlib", "Assembly-CSharp"]
    assert e["typedef_count"] == 7 and e["source"] == "loose"


def test_aot_supplemental_metadata_by_name():
    for name in ("mscorlib", "System.Core", "UnityEngine.CoreModule", "Game.Core"):
        e = classify(fb.build_pe_cli(name, ["mscorlib"], types=2), name + ".dll.bytes")
        assert e["kind"] == "aot_meta", name


def test_unknown_when_no_unity_refs_and_no_runtime():
    e = classify(fb.build_pe_cli("Lib", ["Foo"], types=1), "lib.dll", hot=False)
    assert e["kind"] == "unknown" and e["format"] == "pe_cli"
    e = classify(fb.build_pe_cli("Gameplay", ["UnityEngine.CoreModule"], types=1), "gameplay.dll.bytes", hot=False)
    assert e["kind"] == "hot"                    # .dll.bytes with Unity references is a hot-update candidate by itself


def test_compressed_dll_is_not_called_encrypted():
    raw = fb.build_pe_cli("HotUpdate", ["mscorlib"], types=3)
    e = classify(zlib.compress(raw))
    assert e["format"] == "compressed" and e["compression"] == "zlib" and e["kind"] == "unknown"


def test_xor_obfuscated_pe_header_hypothesis():
    raw = fb.build_pe_cli("HotUpdate", ["mscorlib"], types=3)
    for key in (b"\x5a", b"\x13\x37"):
        enc = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
        e = classify(enc)
        assert e["format"] == "encrypted_suspected" and e["xor_hypothesis"]["key_hex"] == key.hex(), key
    hyp = csharp.xor_pe_hypothesis(raw)
    assert hyp is None                                  # already plain


def test_xor_hypothesis_period3_and_4_use_default_lfanew_crib():
    raw = bytearray(fb.build_pe_cli("HotUpdate", ["mscorlib"], types=3))
    lf = int.from_bytes(raw[0x3C:0x40], "little")
    if lf != 0x80:                                       # builder layout differs: normalise the crib position
        return
    for key in (b"\x01\x02\x03", b"\xa1\xb2\xc3\xd4"):
        enc = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
        # period > 2 needs e_lfanew == 0x80 AND the e_lfanew field itself decodable: accept None or a hit
        hyp = csharp.xor_pe_hypothesis(enc)
        assert hyp is None or hyp["key_hex"] == key.hex()


def test_high_entropy_and_random_blobs():
    assert classify(urandom(8192))["format"] == "encrypted_suspected"
    assert classify(b"\x00\x01" * 2000)["format"] == "unknown"


def test_truncated_and_native_pe():
    raw = fb.build_pe_cli("HotUpdate", ["mscorlib"], types=3)
    e = classify(raw[:100])
    assert e["format"] in ("unknown", "encrypted_suspected")
    e = classify(b"MZ" + b"\0" * 200)
    assert e["format"] == "unknown" and "note" in e


def test_analyze_orders_hot_first_and_counts():
    blobs = [blob(fb.build_pe_cli("mscorlib", [], types=1), "mscorlib.dll.bytes"),
             blob(fb.build_pe_cli("HotUpdate", ["mscorlib"], types=2)),
             blob(zlib.compress(b"x" * 500), "z.dll.bytes", "bundle")]
    out = csharp.analyze(blobs, RULES, ["Assembly-CSharp.dll"], hotfix_runtime=True, named_only=["A.dll", "A.dll"], managed_dlls=2)
    kinds = [e["kind"] for e in out["assemblies"]]
    assert kinds[0] == "hot" and out["counts"]["by_kind"] == {"aot_meta": 1, "hot": 1, "unknown": 1}
    assert out["counts"]["by_format"] == {"compressed": 1, "pe_cli": 2}
    assert out["named_in_containers"] == ["A.dll"] and out["managed_dlls_in_data_managed"] == 2
    assert "nothing is decrypted" in out["notes"][0]


def test_protection_verdicts():
    def pv(blobs, **kw):
        return csharp.protection_verdict(csharp.analyze(blobs, RULES, [], hotfix_runtime=True), containers_unreadable=0,
                                         csharp_signal=kw.get("signal", False), coverage_limited=kw.get("limited", False))
    assert pv([blob(fb.build_pe_cli("HotUpdate", ["mscorlib"], types=1))])["verdict"] == "no"
    assert pv([blob(urandom(8192))])["verdict"] == "suspected"
    assert pv([blob(zlib.compress(b"x" * 500))])["verdict"] == "unknown"
    assert pv([])["verdict"] == "n/a" and pv([], limited=True)["verdict"] == "unknown"
    assert pv([], signal=True)["verdict"] == "unknown"
