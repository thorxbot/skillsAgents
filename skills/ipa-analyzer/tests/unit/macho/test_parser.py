from __future__ import annotations

import io
import os

import pytest

from fixtures.macho_builder import PIE, build_macho, write_macho_file
from ipa_analyzer.macho import NotMachO, parse


def _one(data: bytes, **_):
    mf = parse(data)
    return mf, mf.slices[0]


def test_thin_arm64_execute_basics():
    data = build_macho(strings=["hello", "UnityFramework"], symbols=["_foo"], imports=["_dlopen"])
    with parse(data) as mf:
        assert not mf.is_fat and mf.fat_bits == 0 and len(mf.slices) == 1 and mf.arch_names == ["arm64"]
        sl = mf.slices[0]
        assert sl.is_64 and not sl.is_big_endian and sl.offset == 0 and sl.size == len(data)
        assert sl.cputype == 0x0100000C and sl.filetype_name == "execute"
        assert sl.platform == "ios" and sl.min_os == "12.0" and sl.sdk == "17.0"
        assert sl.uuid and len(sl.uuid) == 36 and sl.uuid == sl.uuid.upper()
        assert [s.name for s in sl.segments] == ["__PAGEZERO", "__TEXT", "__LINKEDIT"]
        text = sl.segments[1]
        assert [s.sectname for s in text.sections] == ["__text", "__cstring"]
        assert sl.find_section("__cstring", "__TEXT").is_cstring
        names = [lc.name for lc in sl.load_commands]
        assert names[:3] == ["LC_SEGMENT_64"] * 3 and "LC_MAIN" in names and "LC_SYMTAB" in names
        assert sl.ncmds == len(sl.load_commands) and sl.warnings == [] and mf.all_warnings == []
        assert sl.entry_offset is not None and sl.dylinker == "/usr/lib/dyld"
        assert sl.build_tools[0].tool == "ld"


def test_deterministic_output():
    assert build_macho(strings=["a"]) == build_macho(strings=["a"])
    assert build_macho(arch="arm64") != build_macho(arch="arm64e")


@pytest.mark.parametrize("arch,is64,big,name", [
    ("arm64", True, False, "arm64"), ("arm64e", True, False, "arm64e"), ("arm64v8", True, False, "arm64v8"),
    ("arm64_32", False, False, "arm64_32"),     # ILP32: 32-bit Mach header (no CPU_ARCH_ABI64)
    ("x86_64", True, False, "x86_64"), ("x86_64h", True, False, "x86_64h"), ("armv7", False, False, "armv7"),
    ("armv7s", False, False, "armv7s"), ("i386", False, False, "i386"),
    ("ppc", False, True, "ppc"), ("ppc64", True, True, "ppc64"),
])
def test_architectures_and_endianness(arch, is64, big, name):
    data = build_macho(arch=arch, big_endian=big, dylibs=["/usr/lib/libSystem.B.dylib"], strings=["abcdef"],
                       objc_classes=["Klass"], symbols=["_x"], imports=["_y"], rpaths=["@rpath"])
    with parse(data) as mf:
        sl = mf.slices[0]
        assert (sl.arch_name, sl.is_64, sl.is_big_endian) == (name, is64, big)
        assert sl.dylibs[0].path == "/usr/lib/libSystem.B.dylib" and sl.rpaths == ["@rpath"]
        assert list(sl.iter_cstrings()) == ["abcdef", "Klass"]
        assert [s.name for s in sl.iter_imported_symbols()] == ["_y"]
        assert sl.min_os == "12.0" and sl.uuid
        assert sl.warnings == []


def test_big_endian_encryption_and_signature():
    data = build_macho(arch="ppc64", big_endian=True, encrypted=True,
                       code_signature=dict(identifier="be.test", team_id="TEAM123456"))
    with parse(data) as mf:
        sl = mf.slices[0]
        assert sl.is_encrypted and sl.encryption[0].cryptid == 1
        assert sl.code_signature.identifier == "be.test" and sl.code_signature.team_id == "TEAM123456"


def test_dylib_kinds_and_install_name():
    data = build_macho(filetype="dylib", install_name="@rpath/Foo.framework/Foo", dylibs=[
        "/usr/lib/libSystem.B.dylib", ("/usr/lib/libz.dylib", "weak"), ("@rpath/Re.dylib", "reexport"),
        ("/System/Library/Frameworks/Lazy.framework/Lazy", "lazy"), ("/opt/up.dylib", "upward")], cpp=True)
    with parse(data) as mf:
        sl = mf.slices[0]
        assert sl.filetype_name == "dylib" and sl.id_dylib.path == "@rpath/Foo.framework/Foo"
        assert sl.is_pie                       # dylibs are always position independent
        got = [(d.path, d.kind, d.load_kind, d.weak) for d in sl.dylibs]
        assert got == [
            ("/usr/lib/libSystem.B.dylib", "system", "load", False), ("/usr/lib/libz.dylib", "system", "weak", True),
            ("@rpath/Re.dylib", "bundled", "reexport", False),
            ("/System/Library/Frameworks/Lazy.framework/Lazy", "system", "lazy", False),
            ("/opt/up.dylib", "other", "upward", False), ("/usr/lib/libc++.1.dylib", "system", "load", False)]
        assert sl.has_cpp and sl.dylibs[0].current_version == "1.2.3"


@pytest.mark.parametrize("kw,expected", [
    (dict(), (False, 0, None)),                                          # no LC_ENCRYPTION_INFO at all
    (dict(encrypted=True), (True, 1, True)),
    (dict(cryptid=1), (True, 1, True)),
    (dict(encryption_info=True), (False, 0, True)),                      # decrypted dump keeps the command
    (dict(encrypted=True, cryptsize=0), (False, 1, True)),               # cryptid set but nothing encrypted
    (dict(cryptid=2), (True, 2, True)),                                  # any non-zero cryptid counts
])
@pytest.mark.parametrize("arch", ["arm64", "armv7"])
def test_encryption_flag(arch, kw, expected):
    enc, cryptid, has_lc = expected
    with parse(build_macho(arch=arch, **kw)) as mf:
        sl = mf.slices[0]
        assert sl.is_encrypted is enc and mf.is_encrypted is enc
        if has_lc is None:
            assert sl.encryption == []
        else:
            assert len(sl.encryption) == 1 and sl.encryption[0].cryptid == cryptid
            assert sl.encryption[0].cmd == (0x2C if arch == "arm64" else 0x21)
            assert sl.encryption[0].cryptoff > 0


def test_cstrings_lazy_and_filtered():
    strings = ["a", "abc", "abcd", "hello world", "Ünïcode ✓"]
    with parse(build_macho(strings=strings, objc_classes=["AppDelegate", "X"], objc_methods=["init", "setFoo:"])) as mf:
        sl = mf.slices[0]
        gen = sl.iter_cstrings()
        assert iter(gen) is gen                      # generator, not a materialised list
        assert list(sl.iter_cstrings(min_len=4)) == ["abcd", "hello world", "Ünïcode ✓", "AppDelegate", "init",
                                                     "setFoo:"]
        assert list(sl.iter_cstrings(min_len=1, section="__cstring")) == strings
        assert list(sl.objc_class_names()) == ["AppDelegate", "X"]
        assert list(sl.objc_method_names()) == ["init", "setFoo:"]
        assert sl.has_objc


def test_cstrings_across_chunk_boundaries():
    from ipa_analyzer.macho.parser import iter_nul_strings

    blob = b"".join(("string-number-%04d" % i).encode() + b"\0" for i in range(500)) + b"unterminated-tail"
    for chunk in (7, 64, 1000, 1 << 20):
        got = list(iter_nul_strings(lambda off, n: blob[off:off + n], 0, len(blob), 4, chunk=chunk))
        assert got[:2] == [b"string-number-0000", b"string-number-0001"]
        assert len(got) == 501 and got[-1] == b"unterminated-tail"


def test_overlong_string_is_cut_not_unbounded():
    from ipa_analyzer.macho.parser import iter_nul_strings

    blob = b"A" * 100_000
    got = list(iter_nul_strings(lambda off, n: blob[off:off + n], 0, len(blob), 4, chunk=4096, max_len=8192))
    assert sum(len(g) for g in got) == 100_000 and max(len(g) for g in got) <= 8192


def test_symbols_and_imports():
    data = build_macho(symbols=["_exported"], local_symbols=["_local_a", "_local_b"], imports=[("_dlopen", 2), "_ptrace"],
                       dylibs=["/usr/lib/libSystem.B.dylib", "/usr/lib/libz.dylib"])
    with parse(data) as mf:
        sl = mf.slices[0]
        syms = list(sl.iter_symbols())
        by = {s.name: s for s in syms}
        assert set(by) == {"_local_a", "_local_b", "__mh_execute_header", "_exported", "_dlopen", "_ptrace"}
        assert by["_local_a"].is_defined and not by["_local_a"].is_external
        assert by["_exported"].is_defined and by["_exported"].is_external
        assert by["_dlopen"].is_undefined and by["_dlopen"].library_ordinal == 2
        assert [s.name for s in sl.iter_imported_symbols()] == ["_dlopen", "_ptrace"]
        assert sl.imported_symbol_names() == {"_dlopen", "_ptrace"}
        assert sl.symtab.nsyms == 6 and sl.dysymtab.nundefsym == 2


def test_imported_symbols_without_dysymtab_falls_back_to_scan():
    data = build_macho(imports=["_a", "_b"], symbols=["_x"], dysymtab=False)
    with parse(data) as mf:
        assert mf.slices[0].dysymtab is None
        assert [s.name for s in mf.slices[0].iter_imported_symbols()] == ["_a", "_b"]


@pytest.mark.parametrize("kw,canary,arc", [
    (dict(), False, False), (dict(canary=True), True, False), (dict(arc=True), False, True),
    (dict(canary=True, arc=True), True, True), (dict(imports=["___stack_chk_fail"]), True, False),
])
def test_canary_and_arc(kw, canary, arc):
    with parse(build_macho(**kw)) as mf:
        sl = mf.slices[0]
        assert (sl.has_stack_canary, sl.uses_arc) == (canary, arc)


@pytest.mark.parametrize("kw,level,stripped", [
    (dict(), "full", False),
    (dict(stripped=True, symbols=["_a", "_b"], imports=["_x"]), "stripped_all", True),
    (dict(stripped="local", symbols=["_s%d" % i for i in range(20)]), "stripped_local", True),
    (dict(debug_stabs=True, stripped="local"), "debug", False),
    (dict(symtab=False), "none", True),
    (dict(dysymtab=False), "full", False),
    (dict(dysymtab=False, stripped=True), "stripped_all", True),
])
def test_symbol_level_and_stripped(kw, level, stripped):
    with parse(build_macho(**kw)) as mf:
        sl = mf.slices[0]
        assert (sl.symbol_level, sl.stripped) == (level, stripped)


def test_few_local_symbols_still_counts_as_stripped_local():
    # Real stripped system binaries keep a few locals (see constants.STRIPPED_*): not "full".
    with parse(build_macho(local_symbols=["_l%d" % i for i in range(10)], symbols=["_e%d" % i for i in range(30)])) as mf:
        assert mf.slices[0].symbol_level == "stripped_local"


@pytest.mark.parametrize("filetype,flags,pie", [("execute", PIE, True), ("execute", 0, False), ("dylib", 0, True),
                                                ("bundle", 0, True)])
def test_pie(filetype, flags, pie):
    with parse(build_macho(filetype=filetype, flags=flags)) as mf:
        sl = mf.slices[0]
        assert sl.is_pie is pie
        assert sl.flags_decoded.pie is (flags == PIE) and "pie" in sl.flags_decoded.to_dict()
        assert sl.flags_decoded.twolevel and not sl.flags_decoded.no_such_flag


def test_language_hints():
    with parse(build_macho(swift=True, objc=True, cpp=True)) as mf:
        sl = mf.slices[0]
        assert (sl.has_swift, sl.has_objc, sl.has_cpp) == (True, True, True)
    with parse(build_macho()) as mf:
        sl = mf.slices[0]
        assert (sl.has_swift, sl.has_objc, sl.has_cpp) == (False, False, False)
    # Swift detected through the runtime dylib alone, ObjC through the runtime import + libobjc.
    with parse(build_macho(dylibs=["/usr/lib/swift/libswiftCore.dylib", "/usr/lib/libobjc.A.dylib"],
                           imports=["_objc_msgSend"])) as mf:
        sl = mf.slices[0]
        assert sl.has_swift and sl.has_objc


def test_version_min_fallback_and_platforms():
    with parse(build_macho(build_version=False, platform="ios", min_os="9.3", sdk="10.2.1")) as mf:
        sl = mf.slices[0]
        assert (sl.platform, sl.min_os, sl.sdk) == ("ios", "9.3", "10.2.1") and sl.build_tools == []
    with parse(build_macho(arch="arm64", platform="iossimulator")) as mf:
        assert mf.slices[0].is_simulator and mf.slices[0].platform == "iossimulator"
    with parse(build_macho(arch="x86_64", platform="ios", build_version=False)) as mf:
        assert mf.slices[0].is_simulator          # legacy x86 simulator slice
    with parse(build_macho(arch="arm64", platform="ios")) as mf:
        assert not mf.slices[0].is_simulator


def test_accepts_all_input_kinds(tmp_path):
    data = build_macho(strings=["xyzzy-string"], encrypted=True)
    p = tmp_path / "bin"
    p.write_bytes(data)

    class NoFileno:                       # a stream that cannot be mmapped
        def __init__(self, b):
            self._b = io.BytesIO(b)

        def seek(self, *a):
            return self._b.seek(*a)

        def read(self, *a):
            return self._b.read(*a)

        def tell(self):
            return self._b.tell()

    with open(p, "rb") as fh:
        sources = [str(p), p, data, bytearray(data), memoryview(data), io.BytesIO(data), fh, NoFileno(data)]
        results = []
        for src in sources:
            with parse(src) as mf:
                sl = mf.slices[0]
                results.append((sl.arch_name, sl.is_encrypted, list(sl.iter_cstrings()), sl.uuid))
    assert len(set(map(repr, results))) == 1 and results[0][2] == ["xyzzy-string"]


def test_parse_missing_and_empty_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        parse(tmp_path / "nope")
    (tmp_path / "empty").write_bytes(b"")
    with pytest.raises(NotMachO):
        parse(tmp_path / "empty")


def test_file_handle_released(tmp_path):
    p = write_macho_file(tmp_path / "bin", strings=["x" * 10])
    with parse(p) as mf:
        assert mf.path == p
    os.remove(p)                          # must not fail on Windows: mapping and handle are closed
    assert not p.exists()


def test_closed_file_reads_nothing(tmp_path):
    p = write_macho_file(tmp_path / "bin", strings=["abcdef"])
    mf = parse(p)
    sl = mf.slices[0]
    mf.close()
    mf.close()                            # idempotent
    assert list(sl.iter_cstrings()) == []


def test_source_version_and_dyld_flags():
    with parse(build_macho()) as mf:
        sl = mf.slices[0]
        assert sl.source_version is None and not sl.has_chained_fixups and not sl.has_dyld_info


def test_encrypted_ranges_and_skip_encrypted_strings():
    kw = dict(strings=["secret-string"], objc_classes=["Klass"])
    with parse(build_macho(encrypted=True, **kw)) as mf:
        sl = mf.slices[0]
        sec = sl.find_section("__cstring")
        assert sl.range_encrypted(sec.offset, sec.size)
        assert list(sl.iter_cstrings(skip_encrypted=True)) == []
        assert list(sl.objc_class_names(skip_encrypted=True)) == []
        assert list(sl.iter_cstrings()) == ["secret-string", "Klass"]       # default: raw, caller decides
        assert not sl.range_encrypted(0, 100)                                 # header/load commands are plain
    with parse(build_macho(encryption_info=True, **kw)) as mf:               # cryptid=0 -> not encrypted
        sl = mf.slices[0]
        assert not sl.range_encrypted(sl.find_section("__cstring").offset, 4)
        assert list(sl.iter_cstrings(skip_encrypted=True)) == ["secret-string", "Klass"]
