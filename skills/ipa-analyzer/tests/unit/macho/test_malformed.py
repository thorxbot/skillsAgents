"""Hostile / corrupt inputs must neither crash nor hang nor read out of bounds."""
from __future__ import annotations

import random
import struct

import pytest

from fixtures.macho_builder import (LC_LOAD_DYLIB, LC_SEGMENT_64, LC_SYMTAB, build_fat, build_macho,
                                    find_load_commands)
from ipa_analyzer.macho import MachOError, NotMachO, parse

GOOD = build_macho(dylibs=["/usr/lib/libSystem.B.dylib"], strings=["hello world", "another string"],
                   objc_classes=["AppDelegate"], symbols=["_a"], imports=["_b", "_c"], canary=True,
                   code_signature=dict(team_id="ABCDE12345", entitlements={"a": 1}), encrypted=True)
JAVA_CLASS = bytes.fromhex("cafebabe00000034") + bytes(range(256)) * 8


def exercise(mf):
    """Touch every accessor, exhausting the lazy iterators."""
    for sl in mf.slices:
        list(sl.iter_cstrings(1))
        list(sl.objc_class_names())
        list(sl.objc_method_names())
        list(sl.iter_symbols())
        list(sl.iter_imported_symbols())
        sl.imported_symbol_names()
        _ = sl.code_signature
        for attr in ("is_encrypted", "is_pie", "stripped", "symbol_level", "has_objc", "has_swift", "has_cpp",
                     "has_stack_canary", "uses_arc", "platform", "min_os", "sdk", "arch_name", "flags_decoded"):
            getattr(sl, attr)
        sl.read(0, 1 << 20)
        b"".join(sl.iter_bytes(4096))
    _ = mf.all_warnings


@pytest.mark.parametrize("data", [
    b"", b"\xcf", b"\xcf\xfa\xed", b"\x00" * 4096, b"hello, this is not a Mach-O file\n" * 10, b"MZ" + b"\0" * 100,
    b"#!/bin/sh\necho hi\n", b"\x7fELF" + b"\0" * 60, b"!<arch>\n" + b"\0" * 100, JAVA_CLASS,
    bytes.fromhex("cafebabe0000002e") + b"\0" * 200,           # Java 1.2 class
    bytes.fromhex("cafebabe0003002d") + b"\0" * 200,           # minor 3 / major 45
])
def test_non_macho_inputs_raise_notmacho(data):
    with pytest.raises(NotMachO):
        parse(data)


def test_java_class_is_not_a_fat_binary():
    with pytest.raises(NotMachO) as err:
        parse(JAVA_CLASS)
    assert "Java" in str(err.value)


@pytest.mark.parametrize("cut", [4, 7, 12, 20, 27, 31])
def test_truncated_header(cut):
    with pytest.raises(MachOError):
        parse(GOOD[:cut])


def test_truncated_anywhere_never_crashes(within):
    def run():
        for cut in range(4, len(GOOD), 97):
            try:
                with parse(GOOD[:cut]) as mf:
                    exercise(mf)
            except MachOError:
                pass

    within(30, run)


def test_ncmds_huge_does_not_loop(within):
    data = bytearray(GOOD)
    struct.pack_into("<I", data, 16, 0xFFFFFFFF)
    mf = within(10, parse, bytes(data))
    sl = mf.slices[0]
    assert any("truncated" in w or "extends" in w or "invalid cmdsize" in w for w in sl.warnings)
    assert len(sl.load_commands) < 100
    within(10, exercise, mf)


def test_sizeofcmds_huge():
    data = bytearray(GOOD)
    struct.pack_into("<I", data, 20, 0xFFFFFFF0)
    with parse(bytes(data)) as mf:
        assert any("sizeofcmds" in w for w in mf.slices[0].warnings)
        exercise(mf)


def test_cmdsize_zero_stops_walk(within):
    data = bytearray(GOOD)
    off = find_load_commands(GOOD, LC_LOAD_DYLIB)[0][0]
    struct.pack_into("<I", data, off + 4, 0)
    mf = within(10, parse, bytes(data))
    sl = mf.slices[0]
    assert any("invalid cmdsize 0" in w for w in sl.warnings) and not sl.dylibs
    assert sl.segments                       # commands before the broken one are kept
    exercise(mf)


@pytest.mark.parametrize("cmdsize", [1, 7, 0xFFFFFFFF, 0x7FFFFFF8, 1 << 20])
def test_cmdsize_out_of_bounds(cmdsize):
    data = bytearray(GOOD)
    off = find_load_commands(GOOD, LC_SYMTAB)[0][0]
    struct.pack_into("<I", data, off + 4, cmdsize)
    with parse(bytes(data)) as mf:
        assert mf.slices[0].warnings
        exercise(mf)


def test_misaligned_cmdsize_is_tolerated():
    data = bytearray(GOOD)
    off = find_load_commands(GOOD, LC_LOAD_DYLIB)[0][0]
    size = struct.unpack_from("<I", GOOD, off + 4)[0]
    # keep the walk consistent but make the size odd: next command will be garbage -> must degrade gracefully
    struct.pack_into("<I", data, off + 4, size - 3)
    with parse(bytes(data)) as mf:
        assert any("aligned" in w or "cmdsize" in w or "extends" in w for w in mf.slices[0].warnings)
        exercise(mf)


def test_segment_with_absurd_section_count():
    data = bytearray(GOOD)
    off = find_load_commands(GOOD, LC_SEGMENT_64)[1][0]            # __TEXT
    struct.pack_into("<I", data, off + 64, 0xFFFFFF)               # nsects
    with parse(bytes(data)) as mf:
        assert any("sections" in w for w in mf.slices[0].warnings)
        exercise(mf)


def test_dylib_name_offset_invalid():
    data = bytearray(GOOD)
    off = find_load_commands(GOOD, LC_LOAD_DYLIB)[0][0]
    struct.pack_into("<I", data, off + 8, 0xFFFF)
    with parse(bytes(data)) as mf:
        assert mf.slices[0].dylibs[0].path == "" and any("name offset" in w for w in mf.slices[0].warnings)


def test_symtab_pointing_outside_file(within):
    data = bytearray(GOOD)
    off = find_load_commands(GOOD, LC_SYMTAB)[0][0]
    for symoff, nsyms, stroff, strsize in [(len(GOOD) + 10, 50, 0, 10), (0, 0xFFFFFFFF, 0, 0xFFFFFFFF),
                                           (16, 100000, len(GOOD) - 4, 5000), (0xFFFFFFFF, 5, 0xFFFFFFFF, 5)]:
        struct.pack_into("<IIII", data, off + 8, symoff, nsyms, stroff, strsize)
        mf = within(10, parse, bytes(data))
        within(20, exercise, mf)
        mf.close()


def test_section_offsets_outside_file():
    data = bytearray(GOOD)
    off = find_load_commands(GOOD, LC_SEGMENT_64)[1][0]
    sect0 = off + 72
    struct.pack_into("<QI", data, sect0 + 40, 1 << 40, 0xFFFFFFF0)    # size, offset of the first section
    with parse(bytes(data)) as mf:
        exercise(mf)


def test_fat_slice_offset_out_of_bounds():
    data = bytearray(build_fat([build_macho(arch="arm64"), build_macho(arch="arm64e")]))
    struct.pack_into(">I", data, 8 + 8, 0x7FFFFFF0)                   # first slice offset
    with parse(bytes(data)) as mf:                                    # second slice still readable
        assert mf.arch_names == ["arm64e"] and any("outside the file" in w for w in mf.warnings)
    struct.pack_into(">I", data, 8 + 20 + 8, 0x7FFFFFF0)
    with pytest.raises(MachOError) as err:
        parse(bytes(data))
    assert not isinstance(err.value, NotMachO)


def test_fat_slice_truncated_is_clamped():
    thin = [build_macho(arch="arm64"), build_macho(arch="arm64e", strings=["tail-string"])]
    data = build_fat(thin)
    cut = data[:len(data) - 300]
    with parse(cut) as mf:
        assert mf.arch_names == ["arm64", "arm64e"]
        assert any("truncated" in w for w in mf.warnings)
        exercise(mf)


def test_fat_arch_table_truncated():
    data = build_fat([build_macho(), build_macho(arch="arm64e")])
    for cut in (8 + 20, 8 + 20 + 10, 8 + 5):
        with pytest.raises(MachOError):
            parse(data[:cut])                                         # table cut short, no readable slice


def test_fat_nfat_implausible():
    data = bytearray(build_fat([build_macho()]))
    struct.pack_into(">I", data, 4, 0)
    with pytest.raises(MachOError):
        parse(bytes(data))
    struct.pack_into(">I", data, 4, 5000)
    with pytest.raises(NotMachO):
        parse(bytes(data))                                            # 0xCAFEBABE + big count == Java-like
    data64 = bytearray(build_fat([build_macho()], fat64=True))
    struct.pack_into(">I", data64, 4, 5000)
    with pytest.raises(MachOError):
        parse(bytes(data64))


def test_fat_with_non_macho_slices_is_notmacho():
    # e.g. a universal static library: slices are ar archives
    ar = b"!<arch>\n" + b"\0" * 100
    data = bytearray(16384 + len(ar))
    struct.pack_into(">II", data, 0, 0xCAFEBABE, 1)
    struct.pack_into(">iiIII", data, 8, 0x0100000C, 0, 16384, len(ar), 14)
    data[16384:] = ar
    with pytest.raises(NotMachO):
        parse(bytes(data))


def test_fat_overlapping_header_offset():
    data = bytearray(build_fat([build_macho()]))
    struct.pack_into(">I", data, 8 + 8, 4)                            # slice offset inside the fat header
    with pytest.raises(MachOError):
        parse(bytes(data))


def test_zero_sized_everything():
    hdr = struct.pack("<IiiIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0) + b"\0" * 4
    with parse(hdr) as mf:
        sl = mf.slices[0]
        assert sl.load_commands == [] and sl.warnings == []
        exercise(mf)
        assert sl.stripped and sl.symbol_level == "none" and not sl.is_encrypted


def test_random_corruption_fuzz(within):
    rng = random.Random(0xC0FFEE)
    fat = build_fat([GOOD, build_macho(arch="armv7", strings=["x" * 40], dylibs=["/usr/lib/libz.dylib"])])

    def run():
        outcomes = {"ok": 0, "err": 0}
        for base in (GOOD, fat):
            for _ in range(400):
                data = bytearray(base)
                for _ in range(rng.randint(1, 12)):
                    pos = rng.randrange(0, min(len(data), 1500 if rng.random() < 0.6 else len(data)))   # headers, then anywhere
                    data[pos] = rng.randrange(256)
                if rng.random() < 0.2:
                    data = data[:rng.randrange(1, len(data))]
                try:
                    with parse(bytes(data)) as mf:
                        exercise(mf)
                    outcomes["ok"] += 1
                except MachOError:
                    outcomes["err"] += 1
        return outcomes

    outcomes = within(120, run)
    assert outcomes["ok"] > 100 and outcomes["err"] > 0


def test_random_garbage_after_magic(within):
    rng = random.Random(7)

    def run():
        for magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
            for _ in range(100):
                data = magic + bytes(rng.randrange(256) for _ in range(rng.randrange(0, 600)))
                try:
                    with parse(data) as mf:
                        exercise(mf)
                except MachOError:
                    pass

    within(60, run)
