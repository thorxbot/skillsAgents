from __future__ import annotations

import random

import pytest

from fixtures.formats_builder import build_lua_bytecode
from ipa_analyzer.formats import lua_bytecode as lb

# Real headers captured from `string.dump` (lupa builds of Lua 5.1-5.5) and `luajit -b` (LuaJIT 2.0 /
# 2.1 built from the official v2.0 / v2.1 branches) on a little-endian 64-bit host, source
# "local x = 1 return x", chunk name "=chunk" (or "@../../t.lua" for luajit -bg).
REAL_SAMPLES = {
    "5.1": "1b4c7561510001040804080007000000000000003d6368756e6b0000000000000000000000020203000000010000001e",
    "5.2": "1b4c7561520001040804080019930d0a1a0a000000000000000000010203000000010000001f0000011f008000010000",
    "5.3": "1b4c7561530019930d0a1a0a04080408087856000000000000000000000028774001073d6368756e6b00000000000000",
    "5.3_strip": "1b4c7561530019930d0a1a0a040804080878560000000000000000000000287740010000000000000000000001020300",
    "5.4": "1b4c7561540019930d0a1a0a0408087856000000000000000000000028774001873d6368756e6b808000010284510000",
    "5.4_strip": "1b4c7561540019930d0a1a0a040808785600000000000000000000002877400180808000010284510000000100008046",
    "5.5": "1b4c7561550019930d0a1a0a0488a9ffff04785634120888a9ffffffffffff0800000000002877c00100000001020400",
    "lj20_strip": "1b4c4a01020f02000100000002270001004800020000",
    "lj20_debug": "1b4c4a01000c402e2e2f2e2e2f742e6c7561190200010000000207000227000100480002000101780002010000",
    "lj21_strip": "1b4c4a020a0f02000100000002290001004c00020000",
    "lj21_debug": "1b4c4a02080c402e2e2f2e2e2f742e6c75611902000100000002070002290001004c0002000101780002010000",
}


@pytest.mark.parametrize(
    "name,flavor,version,stripped,bits",
    [
        ("5.1", "puc", "5.1", False, 64),
        ("5.2", "puc", "5.2", None, 64),
        ("5.3", "puc", "5.3", False, 64),
        ("5.3_strip", "puc", "5.3", True, 64),
        ("5.4", "puc", "5.4", False, None),
        ("5.4_strip", "puc", "5.4", True, None),
        ("5.5", "puc", "5.5", None, None),
        ("lj20_strip", "luajit", "2.0", True, None),
        ("lj20_debug", "luajit", "2.0", False, None),
        ("lj21_strip", "luajit", "2.1", True, 64),
        ("lj21_debug", "luajit", "2.1", False, 64),
    ],
)
def test_real_world_headers(name, flavor, version, stripped, bits):
    info = lb.parse_header(bytes.fromhex(REAL_SAMPLES[name]))
    assert info.valid, info.tamper_signals
    assert (info.flavor, info.version, info.stripped, info.bits) == (flavor, version, stripped, bits)
    assert info.endian == "little"
    assert info.tamper_signals == []


def test_real_header_details():
    i51 = lb.parse_header(bytes.fromhex(REAL_SAMPLES["5.1"]))
    assert (i51.size_int, i51.size_t, i51.size_instruction, i51.size_lua_number, i51.integral_flag) == (4, 8, 4, 8, False)
    assert i51.header_size == 12 and i51.chunkname == "=chunk"
    i53 = lb.parse_header(bytes.fromhex(REAL_SAMPLES["5.3"]))
    assert (i53.size_lua_integer, i53.size_lua_number, i53.header_size) == (8, 8, 33)
    i54 = lb.parse_header(bytes.fromhex(REAL_SAMPLES["5.4"]))
    assert (i54.size_t, i54.size_int, i54.header_size) == (None, None, 31)
    assert lb.parse_header(bytes.fromhex(REAL_SAMPLES["5.4"])).chunkname == "=chunk"
    lj = lb.parse_header(bytes.fromhex(REAL_SAMPLES["lj21_debug"]))
    assert lj.luajit_dump_version == 2 and lj.luajit_flag_names == ["FR2"] and lj.chunkname == "@../../t.lua"
    lj0 = lb.parse_header(bytes.fromhex(REAL_SAMPLES["lj20_strip"]))
    assert lj0.luajit_dump_version == 1 and lj0.luajit_flag_names == ["STRIP"]


@pytest.mark.parametrize("version", ["5.1", "5.2", "5.3", "5.4", "5.5", "luajit2.0", "luajit2.1"])
@pytest.mark.parametrize("strip", [False, True])
@pytest.mark.parametrize("endian", ["little", "big"])
def test_builder_samples_parse_back(version, strip, endian):
    info = lb.parse_header(build_lua_bytecode(version, strip=strip, endian=endian))
    assert info.valid, info.tamper_signals
    assert info.endian == endian
    expected = version.replace("luajit", "")
    assert info.version == expected
    assert (info.flavor == "luajit") == version.startswith("luajit")
    if version in ("5.1", "5.3", "5.4", "luajit2.0", "luajit2.1"):
        assert info.stripped is strip


@pytest.mark.parametrize("version,bits", [("5.1", 32), ("5.1", 64), ("5.2", 32), ("5.3", 32), ("5.3", 64)])
def test_bits_from_size_t(version, bits):
    info = lb.parse_header(build_lua_bytecode(version, bits=bits))
    assert info.valid and info.bits == bits and info.size_t == bits // 8


def test_luajit_gc64_flag_gives_bits():
    assert lb.parse_header(build_lua_bytecode("luajit2.1", bits=64)).bits == 64
    assert lb.parse_header(build_lua_bytecode("luajit2.1", bits=32)).bits is None
    assert lb.parse_header(build_lua_bytecode("luajit2.0", bits=64)).bits is None


@pytest.mark.parametrize(
    "version,tamper,expected",
    [
        ("5.3", "luac_data", "luac_data_mismatch"),
        ("5.3", "luac_int", "luac_int_mismatch"),
        ("5.3", "luac_num", "luac_num_mismatch"),
        ("5.3", "sizeof_int", "sizeof_int_unusual:7"),
        ("5.3", "sizeof_instruction", "sizeof_instruction_unusual:8"),
        ("5.3", "version_byte", "version_byte_unknown:0x5f"),
        ("5.3", "format", "format_nonzero:1"),
        ("5.4", "luac_data", "luac_data_mismatch"),
        ("5.4", "luac_int", "luac_int_mismatch"),
        ("5.4", "luac_num", "luac_num_mismatch"),
        ("5.4", "sizeof_instruction", "sizeof_instruction_unusual:8"),
        ("5.2", "luac_data", "luac_data_mismatch"),
        ("5.2", "sizeof_int", "sizeof_int_unusual:7"),
        ("5.1", "sizeof_instruction", "sizeof_instruction_unusual:8"),
        ("5.1", "endian_byte", "endian_byte_invalid:7"),
        ("5.1", "format", "format_nonzero:1"),
        ("5.5", "luac_int", "luac_int_mismatch"),
        ("5.5", "luac_num", "luac_num_mismatch"),
        ("5.5", "luac_data", "luac_data_mismatch"),
        ("luajit2.1", "luajit_private_version", "luajit_private_dump_version:0x81"),
        ("luajit2.1", "luajit_unknown_flags", "luajit_unknown_flag_bits:0x40"),
        ("luajit2.0", "luajit_unknown_flags", "luajit_unknown_flag_bits:0x40"),
    ],
)
def test_tamper_signals(version, tamper, expected):
    info = lb.parse_header(build_lua_bytecode(version, tamper=tamper))
    assert info.signature_ok
    assert not info.valid
    assert expected in info.tamper_signals, info.tamper_signals


def test_tamper_does_not_affect_clean_variants():
    assert lb.parse_header(build_lua_bytecode("5.3")).tamper_signals == []
    multi = lb.parse_header(build_lua_bytecode("5.3", tamper=["luac_data", "luac_int"]))
    assert {"luac_data_mismatch", "luac_int_mismatch"} <= set(multi.tamper_signals)


def test_luajit_20_does_not_know_fr2_bit():
    # FR2 (0x08) exists only from dump version 2 on
    data = bytearray(bytes.fromhex(REAL_SAMPLES["lj20_strip"]))
    data[4] = 0x0A  # STRIP | FR2
    info = lb.parse_header(bytes(data))
    assert "luajit_unknown_flag_bits:0x8" in info.tamper_signals


def _uleb(v: int) -> bytes:
    out = bytearray()
    while True:
        b, v = v & 0x7F, v >> 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


@pytest.mark.parametrize("extra", [0, 0x08, 0x08 | 0x10, 0x08 | 0x04])
def test_luajit_deterministic_flag_is_legitimate(extra):
    # `luajit -d` sets BCDUMP_F_DETERMINISTIC (0x80000000); such bytecode is genuine, not tampered
    flags = 0x80000000 | 0x02 | extra
    info = lb.parse_header(b"\x1bLJ\x02" + _uleb(flags) + b"\x00" * 8)
    assert info.luajit_flags == flags and "DETERMINISTIC" in info.luajit_flag_names
    assert info.tamper_signals == [] and info.valid


def test_luajit_20_rejects_deterministic_bit_and_other_high_bits():
    info = lb.parse_header(b"\x1bLJ\x01" + _uleb(0x80000000 | 0x02) + b"\x00" * 8)
    assert "luajit_unknown_flag_bits:0x80000000" in info.tamper_signals
    info = lb.parse_header(b"\x1bLJ\x02" + _uleb(0x40000000 | 0x02) + b"\x00" * 8)
    assert "luajit_unknown_flag_bits:0x40000000" in info.tamper_signals


@pytest.mark.parametrize(
    "blob",
    [
        b"",
        b"\x1b",
        b"\x1bL",
        b"not lua at all",
        b"\x1bLua",
        b"\x1bLua\x53",
        b"\x1bLJ",
        b"\x1bLJ\x02",
        b"\x1bLJ\x02\xff\xff\xff\xff\xff\xff",
        b"\x00" * 100,
        b"PK\x03\x04" + b"\x00" * 50,
    ],
)
def test_garbage_and_truncated_never_raise(blob):
    info = lb.parse_header(blob)
    assert not info.valid
    if not blob.startswith((b"\x1bLua", b"\x1bLJ")):
        assert info.flavor == "unknown" and not info.signature_ok and info.tamper_signals == []


def test_every_truncation_of_a_valid_header_is_invalid_not_a_crash():
    for version in ("5.1", "5.2", "5.3", "5.4", "5.5", "luajit2.0", "luajit2.1"):
        data = build_lua_bytecode(version)
        info_full = lb.parse_header(data)
        assert info_full.valid
        for cut in range(0, info_full.header_size):
            info = lb.parse_header(data[:cut])
            assert not info.valid, (version, cut)


def test_fuzz_random_headers():
    rng = random.Random(9)
    for _ in range(2000):
        blob = rng.choice([b"\x1bLua", b"\x1bLJ", b""]) + rng.randbytes(rng.randrange(0, 60))
        info = lb.parse_header(blob)
        assert isinstance(info.to_dict(), dict)


def test_luajit_chunkname_length_implausible():
    blob = b"\x1bLJ\x02\x00" + bytes([0xFF, 0xFF, 0x7F]) + b"abc"
    info = lb.parse_header(blob)
    assert not info.valid
    assert any(s.startswith("luajit_chunkname_length_implausible") for s in info.tamper_signals)


# ------------------------------------------------------------------------------ XOR


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


@pytest.mark.parametrize("version", ["5.1", "5.3", "5.4", "luajit2.1", "luajit2.0"])
@pytest.mark.parametrize("key", [b"\x5a", b"\x13\x37", b"\x01\x02\x03"])
def test_xor_key_hypothesis(version, key):
    plain = build_lua_bytecode(version)
    hyp = lb.looks_like_lua_after_xor(_xor(plain, key))
    assert hyp is not None
    assert hyp.key == key
    assert hyp.info.valid and hyp.info.version_key == lb.parse_header(plain).version_key
    assert 0.5 <= hyp.confidence <= 0.9


def test_xor_four_byte_key():
    plain = build_lua_bytecode("5.3")
    hyp = lb.looks_like_lua_after_xor(_xor(plain, b"\x10\x20\x30\x40"))
    assert hyp is not None and hyp.key == b"\x10\x20\x30\x40"


def test_xor_negatives():
    assert lb.looks_like_lua_after_xor(build_lua_bytecode("5.3")) is None  # already plain
    assert lb.looks_like_lua_after_xor(b"") is None
    assert lb.looks_like_lua_after_xor(b"hello world, plain text here") is None
    rng = random.Random(1)
    for _ in range(300):
        assert lb.looks_like_lua_after_xor(rng.randbytes(64)) is None


def test_xor_of_tampered_header_not_reported_as_valid_lua():
    tampered = build_lua_bytecode("5.3", tamper="luac_data")
    assert lb.looks_like_lua_after_xor(_xor(tampered, b"\x5a")) is None


# ---------------------------------------------------------------------------- summarize


def test_summarize():
    infos = [
        lb.parse_header(build_lua_bytecode("5.1")),
        lb.parse_header(build_lua_bytecode("5.1", strip=True)),
        lb.parse_header(build_lua_bytecode("5.3", bits=32)),
        lb.parse_header(build_lua_bytecode("luajit2.1")),
        lb.parse_header(build_lua_bytecode("5.3", tamper="luac_int")),
        lb.parse_header(b"garbage"),
    ]
    s = lb.summarize(infos)
    assert s["by_version"] == {"5.1": 2, "5.3": 1, "luajit_2.1": 1}
    assert s["invalid"] == 2 and s["tampered"] == 1
    assert s["bits"] == {"32": 1, "64": 3}
    assert s["stripped"] == 1  # only the stripped 5.1 chunk (LuaJIT build here keeps its name)
    assert s["total"] == 6
    assert lb.summarize([]) == {"by_version": {}, "invalid": 0, "tampered": 0, "bits": {}, "stripped": 0, "total": 0}


def test_constants_match_sources():
    assert lb.LUA_SIGNATURE == b"\x1bLua" and lb.LUAJIT_SIGNATURE == b"\x1bLJ"
    assert lb.LUAC_DATA == b"\x19\x93\r\n\x1a\n"
    assert lb.LUAC_INT == 0x5678 and lb.LUAC_NUM == 370.5
    assert lb.LUA_VERSION_BYTES[0x53] == "5.3" and lb.LUAJIT_DUMP_VERSIONS == {1: "2.0", 2: "2.1"}
