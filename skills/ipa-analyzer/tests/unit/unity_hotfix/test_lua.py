from __future__ import annotations

import random
import zlib

import pytest

from fixtures import formats_builder as fb
from ipa_analyzer.unity.hotfix import lua
from ipa_analyzer.unity.hotfix.storage import Blob


def urandom(n: int) -> bytes:
    return random.Random(n).randbytes(n)


def blob(data: bytes, name="a.lua", source="loose", kind="lua") -> Blob:
    return Blob(kind, source, "Payload/X.app/Data/Raw/" + name, name, len(data), data[:4096], data[:65536])


def cls(data: bytes) -> lua.LuaClass:
    return lua.classify_blob(blob(data))


@pytest.mark.parametrize("ver,key", [("5.1", "5.1"), ("5.2", "5.2"), ("5.3", "5.3"), ("5.4", "5.4"), ("5.5", "5.5"),
                                     ("luajit2.0", "luajit_2.0"), ("luajit2.1", "luajit_2.1")])
def test_bytecode_versions(ver, key):
    c = cls(fb.build_lua_bytecode(ver))
    assert c.cls == "bytecode" and c.version_key == key and not c.tampered


def test_bits_and_stripped():
    c = cls(fb.build_lua_bytecode("5.3", bits=32))
    assert c.bits == 32
    c = cls(fb.build_lua_bytecode("luajit2.1", bits=64, strip=True))
    assert c.bits == 64 and c.stripped is True


def test_tampered_headers_are_flagged_custom():
    for t in ("luac_data", "luac_int", "sizeof_instruction", "version_byte"):
        c = cls(fb.build_lua_bytecode("5.3", tamper=t))
        assert c.cls == "bytecode" and c.tampered, t
    c = cls(fb.build_lua_bytecode("luajit2.1", tamper="luajit_private_version"))
    assert c.tampered and any("private" in s for s in c.tamper_signals)


def test_xlua_compatible_53_header_is_not_tampered():
    std = bytearray(fb.build_lua_bytecode("5.3"))
    # remove the sizeof(size_t) byte (offset 13): signature(4) version format data(6) -> int at 12, size_t at 13
    compat = bytes(std[:13] + std[14:])
    assert lua._xlua_compat_53(compat)
    c = cls(compat + b"\0" * 8)
    assert c.cls == "bytecode" and not c.tampered and c.variant == "xlua_compat_header" and c.version_key == "5.3"
    assert not lua._xlua_compat_53(bytes(std))


def test_xor_obfuscated_header_is_suspected_with_key_evidence():
    for key in (b"\x5a", b"\x13\x37"):
        plain = fb.build_lua_bytecode("5.3")
        enc = bytes(b ^ key[i % len(key)] for i, b in enumerate(plain))
        c = cls(enc)
        assert c.cls == "encrypted_suspected" and c.variant == "xor_lua_header" and c.tampered
        assert key.hex() in c.reason


def test_plain_source_and_dialect():
    c = cls(b"local t = {}\nfor i = 1, 3 do goto continue\n::continue:: end\nlocal x = 7 // 2\n")
    assert c.cls == "plain" and c.dialect.min_version == "5.3"
    c = cls(b"local x <const> = 1\nprint(x)\n")
    assert c.dialect.min_version == "5.4"
    c = cls(b"setfenv(f, {})\nlocal b = bit.band(1, 3)\nlocal ffi = require('ffi')\n")
    assert c.cls == "plain" and c.dialect.min_version is None and "ffi" in c.dialect.luajit_signals
    assert cls(b"\xef\xbb\xbfprint('hi')\n").cls == "plain"


def test_plain_text_in_strings_and_comments_does_not_inflate_dialect():
    c = cls(b"-- uses // and goto\nlocal s = 'a // b :: c ::'\nprint(s)\n")
    assert c.cls == "plain" and c.dialect.min_version is None


def test_compressed_is_not_encrypted():
    data = zlib.compress(b"print('x')\n" * 200)
    c = cls(data)
    assert c.cls == "compressed" and c.reason == "zlib"
    assert cls(b"\x1f\x8b\x08\x00" + zlib.compress(b"x" * 500)[2:]).cls == "compressed"


def test_high_entropy_and_base64_are_only_suspected():
    assert cls(urandom(4096)).cls == "encrypted_suspected"
    import base64
    b64 = base64.b64encode(urandom(3000))
    c = cls(b64)
    assert c.cls == "encrypted_suspected" and "base64" in c.reason
    assert cls(bytes(range(1, 40)) * 20).cls in ("unknown", "plain", "encrypted_suspected")


def test_low_entropy_binary_is_unknown():
    assert cls(b"\x00\x01\x02\x03" * 300).cls == "unknown"


def analyze(blobs, runtime=(), **kw):
    return lua.analyze(blobs, list(runtime), **kw)


def test_aggregate_versions_bits_stripped_and_files():
    blobs = [blob(fb.build_lua_bytecode("5.1", bits=32)), blob(fb.build_lua_bytecode("5.3")),
             blob(fb.build_lua_bytecode("5.3")), blob(fb.build_lua_bytecode("luajit2.1", bits=64, strip=True)),
             blob(b"print(1)\n"), blob(zlib.compress(b"x" * 900))]
    out = analyze(blobs)
    bc = out["bytecode"]
    assert bc["by_version"] == {"5.1": 1, "5.3": 2, "luajit_2.1": 1}
    assert bc["arch_bits"] == {"32": 1, "64": 3} and bc["stripped_count"] == 1 and bc["invalid"] == 0
    assert out["files"] == {"plain": 1, "bytecode": 4, "compressed": 1, "encrypted_suspected": 0, "unknown": 0, "total": 6}
    assert out["consistency"]["ok"] is False and any("several" in n for n in out["consistency"]["notes"])
    assert out["custom_lua_suspected"] is False
    assert any("customised VM" in n for n in out["notes"])


def rt(flavor, version, conf=0.92, series=None):
    return {"flavor": flavor, "version": version, "series": series or version[:3], "confidence": conf, "source": "native:x"}


def test_consistency_bytecode_vs_runtime():
    ok = analyze([blob(fb.build_lua_bytecode("5.3"))], [rt("puc", "5.3.6")])
    assert ok["consistency"] == {"ok": True, "checked": True, "notes": []}
    bad = analyze([blob(fb.build_lua_bytecode("5.1"))], [rt("puc", "5.3.6")])
    assert bad["consistency"]["ok"] is False and "5.1" in bad["consistency"]["notes"][0] and "mismatch" in bad["consistency"]["notes"][0]
    lj_on_puc = analyze([blob(fb.build_lua_bytecode("luajit2.1"))], [rt("puc", "5.3.6")])
    assert lj_on_puc["consistency"]["ok"] is False
    lj_ok = analyze([blob(fb.build_lua_bytecode("luajit2.1"))], [rt("luajit", "2.1.0-beta3", series="2.1")])
    assert lj_ok["consistency"]["ok"] is True
    weak = analyze([blob(fb.build_lua_bytecode("5.1"))], [rt("puc", "5.3", conf=0.45)])
    assert weak["consistency"]["ok"] is True and weak["consistency"]["checked"] is False


def test_no_runtime_info_with_encrypted_binary_is_noted_not_failed():
    out = analyze([blob(fb.build_lua_bytecode("5.4"))], [], native_limited=True)
    assert out["consistency"]["ok"] is True and "encrypted" in out["consistency"]["notes"][0]


def test_framework_default_conflict_is_written_out():
    hints = {"tolua": [{"flavor": "luajit", "version": "2.1", "verified": True}]}
    out = analyze([blob(fb.build_lua_bytecode("5.3"))], [rt("puc", "5.3.6")], framework_hints=hints)
    assert any("defaults to LuaJIT" in n and "measured data wins" in n for n in out["consistency"]["notes"])


def test_custom_lua_suspected_from_tamper_and_xor():
    out = analyze([blob(fb.build_lua_bytecode("5.3", tamper="luac_num")), blob(fb.build_lua_bytecode("5.3"))])
    assert out["custom_lua_suspected"] and out["bytecode"]["invalid"] == 1 and out["bytecode"]["by_version"] == {"5.3": 1}
    assert out["bytecode"]["tamper_signals"]
    enc = bytes(b ^ 0x21 for b in fb.build_lua_bytecode("5.4"))
    out = analyze([blob(enc)])
    assert out["custom_lua_suspected"] and out["files"]["encrypted_suspected"] == 1
    assert out["bytecode"]["variants"] == {"xor_lua_header": 1}


def test_dialect_hints_aggregate():
    out = analyze([blob(b"local a = 1 // 2\n"), blob(b"x <const> = 3\n"), blob(b"setfenv(f, {})\n")])
    assert any("5.4" in h for h in out["dialect_hints"]) and any("5.1-style" in h for h in out["dialect_hints"])


def test_sources_are_counted():
    out = analyze([blob(b"print(1)", source="loose"), blob(fb.build_lua_bytecode("5.3"), source="bundle"),
                   blob(fb.build_lua_bytecode("5.3"), source="serialized")])
    assert out["storage"]["loose"] == 1 and out["storage"]["in_bundles"] == 1 and out["storage"]["in_serialized"] == 1


def test_protection_verdicts():
    def v(blobs, **kw):
        return lua.protection_verdict(analyze(blobs), containers_unreadable=kw.get("unread", 0),
                                      any_lua_signal=kw.get("signal", False), coverage_limited=kw.get("limited", False))
    assert v([blob(b"print(1)\n")])["verdict"] == "no"
    assert v([blob(fb.build_lua_bytecode("5.3"))])["verdict"] == "no"
    assert v([blob(urandom(4096))])["verdict"] == "suspected"
    assert v([blob(fb.build_lua_bytecode("5.3", tamper="luac_int"))])["verdict"] == "suspected"
    assert v([blob(b"print(1)\n"), blob(urandom(4096))])["verdict"] == "suspected"
    assert v([])["verdict"] == "n/a"
    assert v([], limited=True)["verdict"] == "unknown"
    assert v([], signal=True, unread=3)["verdict"] == "unknown"
    assert v([blob(zlib.compress(b"x" * 900))])["verdict"] == "unknown"
