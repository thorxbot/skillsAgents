from __future__ import annotations

import pytest

from fixtures.macho_builder import build_fat, build_macho
from ipa_analyzer.macho import parse, write_thin


def _slices():
    return [build_macho(arch="arm64", strings=["arm64-only"]), build_macho(arch="arm64e", strings=["arm64e-only"])]


@pytest.mark.parametrize("fat64,cigam", [(False, False), (True, False), (False, True), (True, True)])
def test_fat_variants(fat64, cigam):
    thin = _slices()
    with parse(build_fat(thin, fat64=fat64, cigam=cigam)) as mf:
        assert mf.is_fat and mf.fat_bits == (64 if fat64 else 32)
        assert mf.arch_names == ["arm64", "arm64e"] and mf.warnings == []
        for sl, blob in zip(mf.slices, thin):
            assert sl.size == len(blob) and sl.offset % (1 << 14) == 0 and sl.offset > 0
            assert sl.read(0, 4) == blob[:4] and sl.read(0, sl.size) == blob
        assert list(mf.slices[0].iter_cstrings()) == ["arm64-only"]
        assert list(mf.slices[1].iter_cstrings()) == ["arm64e-only"]
        # offsets inside a slice (symtab, strings, signature) are slice-relative
        assert all(sl.warnings == [] for sl in mf.slices)


def test_fat_with_simulator_and_32bit_slices():
    thin = [build_macho(arch="armv7", cryptid=1), build_macho(arch="arm64", encrypted=True),
            build_macho(arch="x86_64", platform="iossimulator"), build_macho(arch="i386", platform="ios", build_version=False)]
    with parse(build_fat(thin)) as mf:
        assert mf.arch_names == ["armv7", "arm64", "x86_64", "i386"]
        assert [s.is_encrypted for s in mf.slices] == [True, True, False, False]
        assert [s.is_simulator for s in mf.slices] == [False, False, True, True]
        assert mf.is_encrypted
        assert [s.is_64 for s in mf.slices] == [False, True, True, False]


def test_selection_helpers():
    thin = [build_macho(arch="x86_64"), build_macho(arch="arm64e"), build_macho(arch="arm64")]
    with parse(build_fat(thin)) as mf:
        assert mf.select_slice().arch_name == "arm64"
        assert mf.select_slice(("arm64e", "arm64")).arch_name == "arm64e"
        assert mf.select_slice(("armv7",)).arch_name == "arm64e"        # falls back to an ARM64-class slice
        assert mf.get_slice("x86_64").arch_name == "x86_64" and mf.get_slice("armv7") is None
    with parse(build_fat([build_macho(arch="x86_64"), build_macho(arch="i386")])) as mf:
        assert mf.select_slice().arch_name == "x86_64"                   # last resort: first slice
    with parse(build_fat([build_macho(arch="arm64v8")])) as mf:
        assert mf.get_slice("arm64").arch_name == "arm64v8"             # v8 counts as arm64 for lookups


def test_fat_header_cputype_mismatch_warns():
    data = bytearray(build_fat(_slices()))
    data[8:12] = (7).to_bytes(4, "big")           # first fat_arch.cputype -> i386, Mach header says arm64
    with parse(bytes(data)) as mf:
        assert mf.slices[0].arch_name == "arm64" and any("disagrees" in w for w in mf.slices[0].warnings)


def test_write_thin_roundtrip_matches_original(tmp_path):
    thin = [build_macho(arch="x86_64", strings=["x"]),
            build_macho(arch="arm64", strings=["findme-string"], encrypted=True, dylibs=["/usr/lib/libz.dylib"],
                        code_signature=dict(team_id="ABCDE12345"))]
    fat = tmp_path / "fat.bin"
    fat.write_bytes(build_fat(thin))
    out = write_thin(fat, tmp_path / "sub" / "arm64.bin")
    assert out == tmp_path / "sub" / "arm64.bin" and out.read_bytes() == thin[1]
    assert not list(tmp_path.rglob("*.part"))
    with parse(fat) as orig, parse(out) as new:
        a, b = orig.get_slice("arm64"), new.slices[0]
        assert not new.is_fat and (a.arch_name, a.filetype, a.flags, a.uuid, a.min_os, a.sdk, a.platform) == \
               (b.arch_name, b.filetype, b.flags, b.uuid, b.min_os, b.sdk, b.platform)
        assert a.is_encrypted == b.is_encrypted is True
        assert [d.path for d in a.dylibs] == [d.path for d in b.dylibs]
        assert list(a.iter_cstrings()) == list(b.iter_cstrings())
        assert a.code_signature.cdhash == b.code_signature.cdhash and a.code_signature.team_id == "ABCDE12345"
        assert [s.name for s in a.iter_symbols()] == [s.name for s in b.iter_symbols()]


def test_write_thin_prefer_and_inputs(tmp_path):
    thin = [build_macho(arch="arm64"), build_macho(arch="arm64e"), build_macho(arch="x86_64")]
    data = build_fat(thin)
    out = write_thin(data, tmp_path / "a.bin", prefer=("arm64e",))
    assert out.read_bytes() == thin[1]
    with parse(data) as mf:
        assert write_thin(mf, tmp_path / "b.bin", prefer=("x86_64",)).read_bytes() == thin[2]
        assert write_thin(mf.slices[0], tmp_path / "c.bin").read_bytes() == thin[0]
        assert mf.slices[0].read(0, 4)                                    # source still open (not closed by writer)
    with pytest.raises(ValueError):
        write_thin(data)                                                  # fat needs a destination


def test_write_thin_of_thin_file(tmp_path):
    p = tmp_path / "thin.bin"
    p.write_bytes(build_macho())
    assert write_thin(p) == p                                             # no copy when no destination given
    copy = write_thin(p, tmp_path / "copy.bin")
    assert copy.read_bytes() == p.read_bytes()
    with pytest.raises(ValueError):
        write_thin(p, p)                                                  # refuses to overwrite its own source
    assert p.read_bytes() == copy.read_bytes()
