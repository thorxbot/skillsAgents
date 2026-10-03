from __future__ import annotations

import pytest

from ipa_analyzer.macho import constants as C


@pytest.mark.parametrize("cputype,sub,name", [
    (C.CPU_TYPE_ARM64, 0, "arm64"), (C.CPU_TYPE_ARM64, 1, "arm64v8"), (C.CPU_TYPE_ARM64, 2, "arm64e"),
    (C.CPU_TYPE_ARM64, 0x80000002, "arm64e"),          # CPU_SUBTYPE_PTRAUTH_ABI feature bit is ignored
    (C.CPU_TYPE_ARM64, 0x01000002, "arm64e"),          # pointer-auth ABI version in the top byte
    (C.CPU_TYPE_ARM64_32, 1, "arm64_32"), (C.CPU_TYPE_ARM, 9, "armv7"), (C.CPU_TYPE_ARM, 11, "armv7s"),
    (C.CPU_TYPE_ARM, 12, "armv7k"), (C.CPU_TYPE_X86_64, 3, "x86_64"), (C.CPU_TYPE_X86_64, 0x80000003, "x86_64"),
    (C.CPU_TYPE_X86_64, 8, "x86_64h"), (C.CPU_TYPE_X86, 3, "i386"), (C.CPU_TYPE_POWERPC, 0, "ppc"),
    (C.CPU_TYPE_POWERPC64, 0, "ppc64"), (99, 5, "cpu99_5"),
])
def test_arch_name(cputype, sub, name):
    assert C.arch_name(cputype, sub) == name


def test_arch_family_collapses_v8():
    assert C.arch_family("arm64v8") == "arm64" and C.arch_family("arm64e") == "arm64e"


@pytest.mark.parametrize("value,text", [(0x000C0000, "12.0"), (0x000D0200, "13.2"), (0x00110201, "17.2.1"), (0, "0.0")])
def test_format_version(value, text):
    assert C.format_version(value) == text


def test_format_source_version():
    packed = (1 << 40) | (2 << 30) | (3 << 20) | (4 << 10) | 5
    assert C.format_source_version(packed) == "1.2.3.4.5"


@pytest.mark.parametrize("path,kind", [
    ("/usr/lib/libSystem.B.dylib", "system"), ("/System/Library/Frameworks/UIKit.framework/UIKit", "system"),
    ("@rpath/UnityFramework.framework/UnityFramework", "bundled"), ("@executable_path/libfoo.dylib", "bundled"),
    ("@loader_path/../x", "bundled"), ("/Library/Frameworks/X.framework/X", "other"), ("libfoo.dylib", "other"),
])
def test_classify_dylib_path(path, kind):
    assert C.classify_dylib_path(path) == kind


def test_lc_values_match_apple_headers():
    # Spot checks against <mach-o/loader.h>.
    assert C.LC_ENCRYPTION_INFO == 0x21 and C.LC_ENCRYPTION_INFO_64 == 0x2C
    assert C.LC_LOAD_WEAK_DYLIB == 0x80000018 and C.LC_REEXPORT_DYLIB == 0x8000001F
    assert C.LC_MAIN == 0x80000028 and C.LC_DYLD_CHAINED_FIXUPS == 0x80000034
    assert C.MH_PIE == 0x200000 and C.FAT_MAGIC == 0xCAFEBABE and C.FAT_MAGIC_64 == 0xCAFEBABF
    assert C.CSMAGIC_EMBEDDED_SIGNATURE == 0xFADE0CC0 and C.CSMAGIC_CODEDIRECTORY == 0xFADE0C02
    assert C.CSMAGIC_EMBEDDED_ENTITLEMENTS == 0xFADE7171 and C.CSMAGIC_EMBEDDED_DER_ENTITLEMENTS == 0xFADE7172


def test_platform_name():
    assert C.platform_name(2) == "ios" and C.platform_name(7) == "iossimulator"
    assert C.platform_name(None) is None and C.platform_name(99) == "platform99"
