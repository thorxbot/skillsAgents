from __future__ import annotations

import random
import struct

import pytest

from fixtures.formats_builder import build_pe_cli
from ipa_analyzer.formats import pe_cli


def test_valid_assembly_basic_fields():
    data = build_pe_cli("Assembly-CSharp", refs=["mscorlib", "UnityEngine.CoreModule", "netstandard"], types=3)
    info = pe_cli.parse(data)
    assert info.is_pe and info.is_dotnet and info.error is None and info.warnings == []
    assert info.assembly_name == "Assembly-CSharp"
    assert info.assembly_version == "1.0.0.0"
    assert info.clr_version == "v4.0.30319"
    assert info.cli_runtime_version == "2.5"
    assert info.assembly_refs == ["mscorlib", "UnityEngine.CoreModule", "netstandard"]
    assert info.typedef_count == 3
    assert info.streams == ["#~", "#Strings", "#GUID", "#Blob"]
    assert info.pe32_plus is False and info.machine == 0x14C
    assert pe_cli.is_dotnet_assembly(data)


def test_clr_version_variants_and_assembly_version():
    info = pe_cli.parse(build_pe_cli("Lib", clr="v2.0.50727", assembly_version=(3, 1, 4, 1)))
    assert info.clr_version == "v2.0.50727" and info.assembly_version == "3.1.4.1"
    assert info.assembly_refs == [] and info.typedef_count == 0


def test_pe32_plus_and_other_tables():
    data = build_pe_cli("Big", refs=["a", "b"], types=5, typerefs=7, methods=9, pe32_plus=True)
    info = pe_cli.parse(data)
    assert info.pe32_plus is True and info.machine == 0x8664
    assert (info.typedef_count, info.typeref_count, info.methoddef_count) == (5, 7, 9)
    assert info.assembly_name == "Big" and info.assembly_refs == ["a", "b"]


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(big_strings=True, refs=["x", "y"]),  # 4-byte #Strings indexes
        dict(typerefs=20_000, types=20_000, refs=["wide"]),  # wide coded indexes
        dict(methods=70_000, types=3, refs=["m"]),  # 4-byte MethodDef simple index
    ],
)
def test_wide_index_sizes(kwargs):
    info = pe_cli.parse(build_pe_cli("Wide.Asm", **kwargs))
    assert info.is_dotnet and info.error is None
    assert info.assembly_name == "Wide.Asm"
    assert info.assembly_refs == kwargs.get("refs", [])
    assert info.typedef_count == kwargs.get("types", 0)


def test_unicode_and_obfuscated_names():
    info = pe_cli.parse(build_pe_cli("程序集", refs=["系统", "\u0001\u0002"], types=2))
    assert info.assembly_name == "程序集" and info.assembly_refs[0] == "系统"
    assert info.typedef_name_stats["sampled"] == 2


def test_typedef_name_stats():
    info = pe_cli.parse(build_pe_cli("A", types=50))
    stats = info.typedef_name_stats
    assert stats["sampled"] == 50 and stats["short_ratio"] == 0.0 and stats["non_ascii_ratio"] == 0.0
    assert 5 <= stats["mean_length"] <= 7


def test_assembly_ref_cap():
    refs = [f"R{i}" for i in range(pe_cli._MAX_ASSEMBLY_REFS + 10)]
    info = pe_cli.parse(build_pe_cli("Capped", refs=refs))
    assert len(info.assembly_refs) == pe_cli._MAX_ASSEMBLY_REFS and info.assembly_refs_truncated


# ----------------------------------------------------------------------- non-.NET / hostile


def test_not_pe():
    for blob in (b"", b"M", b"MZ", b"hello" * 100, b"\x7fELF" + b"\x00" * 200, b"\xcf\xfa\xed\xfe" + b"\x00" * 200):
        info = pe_cli.parse(blob)
        assert not info.is_pe and not info.is_dotnet and info.error == "not_pe"
        assert not pe_cli.is_dotnet_assembly(blob)


def test_mz_without_pe_signature():
    blob = bytearray(b"MZ" + b"\x00" * 0x200)
    struct.pack_into("<I", blob, 0x3C, 0x80)
    info = pe_cli.parse(bytes(blob))
    assert not info.is_pe and info.error == "bad_pe_signature"
    struct.pack_into("<I", blob, 0x3C, 0xFFFFFFF0)
    assert pe_cli.parse(bytes(blob)).error == "bad_pe_signature"


def test_native_pe_without_cli_header():
    data = bytearray(build_pe_cli("Native"))
    opt = 0x80 + 4 + 20
    struct.pack_into("<II", data, opt + 96 + 14 * 8, 0, 0)  # clear the CLR data directory
    info = pe_cli.parse(bytes(data))
    assert info.is_pe and not info.is_dotnet and info.error is None
    assert not pe_cli.is_dotnet_assembly(bytes(data))
    # fewer data directories than 15 => also "no CLI"
    struct.pack_into("<I", data, opt + 92, 8)
    assert not pe_cli.parse(bytes(data)).is_dotnet


def test_bad_optional_header_magic():
    data = bytearray(build_pe_cli("X"))
    struct.pack_into("<H", data, 0x80 + 4 + 20, 0x1234)
    info = pe_cli.parse(bytes(data))
    assert info.is_pe and not info.is_dotnet and info.error == "bad_optional_header_magic"


def test_truncated_pe_at_every_point_is_safe():
    data = build_pe_cli("Trunc", refs=["a", "b"], types=2)
    for cut in list(range(0, 0x260, 7)) + [len(data) - 1, len(data) // 2]:
        info = pe_cli.parse(data[:cut])
        assert isinstance(info.to_dict(), dict)
        if cut < 0x200 + 72:
            assert not info.is_dotnet
        pe_cli.is_dotnet_assembly(data[:cut])


def test_malicious_offsets():
    base = build_pe_cli("Evil", refs=["a"], types=2)
    opt = 0x80 + 4 + 20
    cli_off = 0x200
    cases = {
        "cli_header_out_of_file": lambda b: struct.pack_into("<I", b, opt + 96 + 14 * 8, 0x0FFFFF00),
        "metadata_out_of_file": lambda b: struct.pack_into("<I", b, cli_off + 8, 0x0FFFFF00),
        "bad_metadata_signature": lambda b: b.__setitem__(slice(cli_off + 72, cli_off + 76), b"XXXX"),
        "bad_metadata_version_length": lambda b: struct.pack_into("<I", b, cli_off + 72 + 12, 5000),
        "bad_stream_count": lambda b: struct.pack_into("<H", b, cli_off + 72 + 16 + 12 + 2, 9999),
    }
    for expected, mutate in cases.items():
        buf = bytearray(base)
        mutate(buf)
        info = pe_cli.parse(bytes(buf))
        assert not info.is_dotnet, expected
        assert info.error == expected
    assert pe_cli.parse(bytes(bytearray(base))).is_dotnet


def test_huge_section_count_and_row_counts_do_not_hang():
    buf = bytearray(build_pe_cli("Rows", refs=["a"], types=1))
    struct.pack_into("<H", buf, 0x80 + 4 + 2, 0xFFFF)  # NumberOfSections
    info = pe_cli.parse(bytes(buf))
    assert isinstance(info.warnings, list)
    # corrupt the Module/TypeDef row counts inside #~
    buf = bytearray(build_pe_cli("Rows", refs=["a"], types=1))
    tilde = buf.find(b"\x00\x00\x00\x00\x02\x00\x00\x01")  # reserved(4)+major 2+minor 0+heap 0+reserved 1
    assert tilde > 0
    struct.pack_into("<I", buf, tilde + 24 + 4, 0xFFFFFFFF)  # TypeDef rows (second row count)
    info = pe_cli.parse(bytes(buf))
    assert info.typedef_count == 0xFFFFFFFF and info.assembly_name is None
    assert any("implausible" in w for w in info.warnings)


def test_random_mutation_fuzz_never_raises():
    rng = random.Random(21)
    base = build_pe_cli("Fuzz", refs=["a", "b", "c"], types=10, typerefs=5, methods=7)
    for _ in range(600):
        buf = bytearray(base)
        for _ in range(rng.randrange(1, 8)):
            buf[rng.randrange(0, 0x400)] = rng.randrange(256)
        if rng.random() < 0.2:
            buf = buf[: rng.randrange(len(buf))]
        info = pe_cli.parse(bytes(buf))
        assert isinstance(info.to_dict(), dict)
        pe_cli.is_dotnet_assembly(bytes(buf))
