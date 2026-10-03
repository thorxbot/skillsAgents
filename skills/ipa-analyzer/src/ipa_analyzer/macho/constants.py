"""Mach-O / fat / code-signing constants and small lookup helpers.

Every block names its source. All values below were cross-checked against the Apple SDK headers
shipped with Xcode (``usr/include/mach-o/{loader,fat,nlist}.h``, ``usr/include/mach/machine.h``,
``Kernel.framework/Headers/kern/cs_blobs.h``) unless a line says ``UNVERIFIED``.
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

# --- Mach-O magic ------------------------------------------------------------------------------
# Source: <mach-o/loader.h>. The *_CIGAM values are what a little-endian reader sees for a
# big-endian file (NXSwapInt(MH_MAGIC)).
MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE

# --- Fat (universal) magic ---------------------------------------------------------------------
# Source: <mach-o/fat.h>. Fat headers are big-endian on disk; FAT_CIGAM* is the byte-swapped form.
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA
FAT_HEADER_SIZE = 8      # struct fat_header {magic, nfat_arch}
FAT_ARCH_SIZE = 20       # struct fat_arch {cputype, cpusubtype, offset, size, align}
FAT_ARCH_64_SIZE = 32    # struct fat_arch_64 {cputype, cpusubtype, offset(u64), size(u64), align, reserved}

# Java class files also start with 0xCAFEBABE; there the next two u16 are minor/major version, so
# the "nfat_arch" a fat parser would read is >= 45 (JDK 1.1 = major 45). Real universal binaries
# carry a handful of slices. Source for the Java layout: JVMS section 4.1 (ClassFile).
# UNVERIFIED: the exact cut-off is a heuristic; ``MAX_FAT_ARCHS`` only has to sit below 45.
MAX_FAT_ARCHS = 30

# --- Mach header sizes -------------------------------------------------------------------------
# Source: <mach-o/loader.h> struct mach_header / mach_header_64.
MACH_HEADER_SIZE = 28
MACH_HEADER_64_SIZE = 32

# --- File types (mach_header.filetype) ---------------------------------------------------------
# Source: <mach-o/loader.h> MH_OBJECT .. MH_GPU_DYLIB.
MH_OBJECT = 0x1
MH_EXECUTE = 0x2
MH_FVMLIB = 0x3
MH_CORE = 0x4
MH_PRELOAD = 0x5
MH_DYLIB = 0x6
MH_DYLINKER = 0x7
MH_BUNDLE = 0x8
MH_DYLIB_STUB = 0x9
MH_DSYM = 0xA
MH_KEXT_BUNDLE = 0xB
MH_FILESET = 0xC
MH_GPU_EXECUTE = 0xD
MH_GPU_DYLIB = 0xE

FILETYPE_NAMES: Dict[int, str] = {
    MH_OBJECT: "object", MH_EXECUTE: "execute", MH_FVMLIB: "fvmlib", MH_CORE: "core",
    MH_PRELOAD: "preload", MH_DYLIB: "dylib", MH_DYLINKER: "dylinker", MH_BUNDLE: "bundle",
    MH_DYLIB_STUB: "dylib_stub", MH_DSYM: "dsym", MH_KEXT_BUNDLE: "kext_bundle",
    MH_FILESET: "fileset", MH_GPU_EXECUTE: "gpu_execute", MH_GPU_DYLIB: "gpu_dylib",
}

# --- Header flags (mach_header.flags) ----------------------------------------------------------
# Source: <mach-o/loader.h> MH_NOUNDEFS .. MH_DYLIB_IN_CACHE.
MH_NOUNDEFS = 0x1
MH_DYLDLINK = 0x4
MH_BINDATLOAD = 0x8
MH_PREBOUND = 0x10
MH_TWOLEVEL = 0x80
MH_FORCE_FLAT = 0x100
MH_SUBSECTIONS_VIA_SYMBOLS = 0x2000
MH_WEAK_DEFINES = 0x8000
MH_BINDS_TO_WEAK = 0x10000
MH_ALLOW_STACK_EXECUTION = 0x20000
MH_NO_REEXPORTED_DYLIBS = 0x100000
MH_PIE = 0x200000
MH_DEAD_STRIPPABLE_DYLIB = 0x400000
MH_HAS_TLV_DESCRIPTORS = 0x800000
MH_NO_HEAP_EXECUTION = 0x1000000
MH_APP_EXTENSION_SAFE = 0x02000000
MH_SIM_SUPPORT = 0x08000000
MH_DYLIB_IN_CACHE = 0x80000000

HEADER_FLAG_NAMES: Tuple[Tuple[str, int], ...] = (
    ("noundefs", MH_NOUNDEFS), ("dyldlink", MH_DYLDLINK), ("bindatload", MH_BINDATLOAD),
    ("prebound", MH_PREBOUND), ("twolevel", MH_TWOLEVEL), ("force_flat", MH_FORCE_FLAT),
    ("subsections_via_symbols", MH_SUBSECTIONS_VIA_SYMBOLS), ("weak_defines", MH_WEAK_DEFINES),
    ("binds_to_weak", MH_BINDS_TO_WEAK), ("allow_stack_execution", MH_ALLOW_STACK_EXECUTION),
    ("no_reexported_dylibs", MH_NO_REEXPORTED_DYLIBS), ("pie", MH_PIE),
    ("dead_strippable_dylib", MH_DEAD_STRIPPABLE_DYLIB), ("has_tlv_descriptors", MH_HAS_TLV_DESCRIPTORS),
    ("no_heap_execution", MH_NO_HEAP_EXECUTION), ("app_extension_safe", MH_APP_EXTENSION_SAFE),
    ("sim_support", MH_SIM_SUPPORT), ("dylib_in_cache", MH_DYLIB_IN_CACHE),
)

# --- Load commands -----------------------------------------------------------------------------
# Source: <mach-o/loader.h>. LC_REQ_DYLD (0x80000000) marks commands dyld must understand.
LC_REQ_DYLD = 0x80000000
LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_SYMSEG = 0x3
LC_THREAD = 0x4
LC_UNIXTHREAD = 0x5
LC_LOADFVMLIB = 0x6
LC_IDFVMLIB = 0x7
LC_IDENT = 0x8
LC_FVMFILE = 0x9
LC_PREPAGE = 0xA
LC_DYSYMTAB = 0xB
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_LOAD_DYLINKER = 0xE
LC_ID_DYLINKER = 0xF
LC_PREBOUND_DYLIB = 0x10
LC_ROUTINES = 0x11
LC_SUB_FRAMEWORK = 0x12
LC_SUB_UMBRELLA = 0x13
LC_SUB_CLIENT = 0x14
LC_SUB_LIBRARY = 0x15
LC_TWOLEVEL_HINTS = 0x16
LC_PREBIND_CKSUM = 0x17
LC_LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLD
LC_SEGMENT_64 = 0x19
LC_ROUTINES_64 = 0x1A
LC_UUID = 0x1B
LC_RPATH = 0x1C | LC_REQ_DYLD
LC_CODE_SIGNATURE = 0x1D
LC_SEGMENT_SPLIT_INFO = 0x1E
LC_REEXPORT_DYLIB = 0x1F | LC_REQ_DYLD
LC_LAZY_LOAD_DYLIB = 0x20
LC_ENCRYPTION_INFO = 0x21
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x22 | LC_REQ_DYLD
LC_LOAD_UPWARD_DYLIB = 0x23 | LC_REQ_DYLD
LC_VERSION_MIN_MACOSX = 0x24
LC_VERSION_MIN_IPHONEOS = 0x25
LC_FUNCTION_STARTS = 0x26
LC_DYLD_ENVIRONMENT = 0x27
LC_MAIN = 0x28 | LC_REQ_DYLD
LC_DATA_IN_CODE = 0x29
LC_SOURCE_VERSION = 0x2A
LC_DYLIB_CODE_SIGN_DRS = 0x2B
LC_ENCRYPTION_INFO_64 = 0x2C
LC_LINKER_OPTION = 0x2D
LC_LINKER_OPTIMIZATION_HINT = 0x2E
LC_VERSION_MIN_TVOS = 0x2F
LC_VERSION_MIN_WATCHOS = 0x30
LC_NOTE = 0x31
LC_BUILD_VERSION = 0x32
LC_DYLD_EXPORTS_TRIE = 0x33 | LC_REQ_DYLD
LC_DYLD_CHAINED_FIXUPS = 0x34 | LC_REQ_DYLD
LC_FILESET_ENTRY = 0x35 | LC_REQ_DYLD

LC_NAMES: Dict[int, str] = {
    LC_SEGMENT: "LC_SEGMENT", LC_SYMTAB: "LC_SYMTAB", LC_SYMSEG: "LC_SYMSEG", LC_THREAD: "LC_THREAD",
    LC_UNIXTHREAD: "LC_UNIXTHREAD", LC_LOADFVMLIB: "LC_LOADFVMLIB", LC_IDFVMLIB: "LC_IDFVMLIB",
    LC_IDENT: "LC_IDENT", LC_FVMFILE: "LC_FVMFILE", LC_PREPAGE: "LC_PREPAGE", LC_DYSYMTAB: "LC_DYSYMTAB",
    LC_LOAD_DYLIB: "LC_LOAD_DYLIB", LC_ID_DYLIB: "LC_ID_DYLIB", LC_LOAD_DYLINKER: "LC_LOAD_DYLINKER",
    LC_ID_DYLINKER: "LC_ID_DYLINKER", LC_PREBOUND_DYLIB: "LC_PREBOUND_DYLIB", LC_ROUTINES: "LC_ROUTINES",
    LC_SUB_FRAMEWORK: "LC_SUB_FRAMEWORK", LC_SUB_UMBRELLA: "LC_SUB_UMBRELLA", LC_SUB_CLIENT: "LC_SUB_CLIENT",
    LC_SUB_LIBRARY: "LC_SUB_LIBRARY", LC_TWOLEVEL_HINTS: "LC_TWOLEVEL_HINTS", LC_PREBIND_CKSUM: "LC_PREBIND_CKSUM",
    LC_LOAD_WEAK_DYLIB: "LC_LOAD_WEAK_DYLIB", LC_SEGMENT_64: "LC_SEGMENT_64", LC_ROUTINES_64: "LC_ROUTINES_64",
    LC_UUID: "LC_UUID", LC_RPATH: "LC_RPATH", LC_CODE_SIGNATURE: "LC_CODE_SIGNATURE",
    LC_SEGMENT_SPLIT_INFO: "LC_SEGMENT_SPLIT_INFO", LC_REEXPORT_DYLIB: "LC_REEXPORT_DYLIB",
    LC_LAZY_LOAD_DYLIB: "LC_LAZY_LOAD_DYLIB", LC_ENCRYPTION_INFO: "LC_ENCRYPTION_INFO",
    LC_DYLD_INFO: "LC_DYLD_INFO", LC_DYLD_INFO_ONLY: "LC_DYLD_INFO_ONLY",
    LC_LOAD_UPWARD_DYLIB: "LC_LOAD_UPWARD_DYLIB", LC_VERSION_MIN_MACOSX: "LC_VERSION_MIN_MACOSX",
    LC_VERSION_MIN_IPHONEOS: "LC_VERSION_MIN_IPHONEOS", LC_FUNCTION_STARTS: "LC_FUNCTION_STARTS",
    LC_DYLD_ENVIRONMENT: "LC_DYLD_ENVIRONMENT", LC_MAIN: "LC_MAIN", LC_DATA_IN_CODE: "LC_DATA_IN_CODE",
    LC_SOURCE_VERSION: "LC_SOURCE_VERSION", LC_DYLIB_CODE_SIGN_DRS: "LC_DYLIB_CODE_SIGN_DRS",
    LC_ENCRYPTION_INFO_64: "LC_ENCRYPTION_INFO_64", LC_LINKER_OPTION: "LC_LINKER_OPTION",
    LC_LINKER_OPTIMIZATION_HINT: "LC_LINKER_OPTIMIZATION_HINT", LC_VERSION_MIN_TVOS: "LC_VERSION_MIN_TVOS",
    LC_VERSION_MIN_WATCHOS: "LC_VERSION_MIN_WATCHOS", LC_NOTE: "LC_NOTE", LC_BUILD_VERSION: "LC_BUILD_VERSION",
    LC_DYLD_EXPORTS_TRIE: "LC_DYLD_EXPORTS_TRIE", LC_DYLD_CHAINED_FIXUPS: "LC_DYLD_CHAINED_FIXUPS",
    LC_FILESET_ENTRY: "LC_FILESET_ENTRY",
}

# Dependency-bearing load commands -> ``DylibRef.load_kind``.
DYLIB_LOAD_KINDS: Dict[int, str] = {
    LC_LOAD_DYLIB: "load", LC_LOAD_WEAK_DYLIB: "weak", LC_REEXPORT_DYLIB: "reexport",
    LC_LAZY_LOAD_DYLIB: "lazy", LC_LOAD_UPWARD_DYLIB: "upward",
}

# Fixed struct sizes (bytes) used for bounds checks. Source: <mach-o/loader.h>.
SEGMENT_COMMAND_SIZE = 56      # struct segment_command
SEGMENT_COMMAND_64_SIZE = 72   # struct segment_command_64
SECTION_SIZE = 68              # struct section
SECTION_64_SIZE = 80           # struct section_64
BUILD_VERSION_COMMAND_SIZE = 24
BUILD_TOOL_VERSION_SIZE = 8

# --- Section types / attributes ----------------------------------------------------------------
# Source: <mach-o/loader.h>.
SECTION_TYPE_MASK = 0xFF
S_REGULAR = 0x0
S_ZEROFILL = 0x1
S_CSTRING_LITERALS = 0x2
S_GB_ZEROFILL = 0xC
S_THREAD_LOCAL_ZEROFILL = 0x12
ZEROFILL_SECTION_TYPES = frozenset({S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL})

# --- Platforms and tools (LC_BUILD_VERSION) ----------------------------------------------------
# Source: <mach-o/loader.h> PLATFORM_* / TOOL_*.
PLATFORM_MACOS = 1
PLATFORM_IOS = 2
PLATFORM_TVOS = 3
PLATFORM_WATCHOS = 4
PLATFORM_BRIDGEOS = 5
PLATFORM_MACCATALYST = 6
PLATFORM_IOSSIMULATOR = 7
PLATFORM_TVOSSIMULATOR = 8
PLATFORM_WATCHOSSIMULATOR = 9
PLATFORM_DRIVERKIT = 10
PLATFORM_VISIONOS = 11
PLATFORM_VISIONOSSIMULATOR = 12

PLATFORM_NAMES: Dict[int, str] = {
    PLATFORM_MACOS: "macos", PLATFORM_IOS: "ios", PLATFORM_TVOS: "tvos", PLATFORM_WATCHOS: "watchos",
    PLATFORM_BRIDGEOS: "bridgeos", PLATFORM_MACCATALYST: "maccatalyst",
    PLATFORM_IOSSIMULATOR: "iossimulator", PLATFORM_TVOSSIMULATOR: "tvossimulator",
    PLATFORM_WATCHOSSIMULATOR: "watchossimulator", PLATFORM_DRIVERKIT: "driverkit",
    PLATFORM_VISIONOS: "visionos", PLATFORM_VISIONOSSIMULATOR: "visionossimulator",
}
SIMULATOR_PLATFORMS = frozenset({PLATFORM_IOSSIMULATOR, PLATFORM_TVOSSIMULATOR,
                                 PLATFORM_WATCHOSSIMULATOR, PLATFORM_VISIONOSSIMULATOR})

# Legacy LC_VERSION_MIN_* -> platform id.
VERSION_MIN_PLATFORMS: Dict[int, int] = {
    LC_VERSION_MIN_MACOSX: PLATFORM_MACOS, LC_VERSION_MIN_IPHONEOS: PLATFORM_IOS,
    LC_VERSION_MIN_TVOS: PLATFORM_TVOS, LC_VERSION_MIN_WATCHOS: PLATFORM_WATCHOS,
}

TOOL_NAMES: Dict[int, str] = {1: "clang", 2: "swift", 3: "ld", 4: "lld", 1024: "metal", 1025: "airlld",
                              1026: "airnt", 1027: "airnt_plugin", 1028: "airpack", 1031: "gpuarchiver",
                              1032: "metal_framework"}

# --- CPU types / subtypes ----------------------------------------------------------------------
# Source: <mach/machine.h>.
CPU_ARCH_MASK = 0xFF000000
CPU_ARCH_ABI64 = 0x01000000
CPU_ARCH_ABI64_32 = 0x02000000
CPU_SUBTYPE_MASK = 0xFF000000
CPU_TYPE_X86 = 7
CPU_TYPE_X86_64 = CPU_TYPE_X86 | CPU_ARCH_ABI64
CPU_TYPE_ARM = 12
CPU_TYPE_ARM64 = CPU_TYPE_ARM | CPU_ARCH_ABI64
CPU_TYPE_ARM64_32 = CPU_TYPE_ARM | CPU_ARCH_ABI64_32
CPU_TYPE_POWERPC = 18
CPU_TYPE_POWERPC64 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64

CPU_SUBTYPE_ARM64_ALL = 0
CPU_SUBTYPE_ARM64_V8 = 1
CPU_SUBTYPE_ARM64E = 2

_ARM_SUBTYPES: Dict[int, str] = {0: "arm", 5: "armv4t", 6: "armv6", 7: "armv5tej", 8: "xscale",
                                 9: "armv7", 10: "armv7f", 11: "armv7s", 12: "armv7k", 13: "armv8"}
_ARM64_SUBTYPES: Dict[int, str] = {0: "arm64", 1: "arm64v8", 2: "arm64e"}
_X86_SUBTYPES: Dict[int, str] = {3: "i386", 4: "i486"}
_X86_64_SUBTYPES: Dict[int, str] = {3: "x86_64", 8: "x86_64h"}


def arch_name(cputype: int, cpusubtype: int) -> str:
    """Canonical architecture name (``arm64``, ``arm64e``, ``x86_64``, ``armv7`` ...).

    Feature bits in the top byte of ``cpusubtype`` (CPU_SUBTYPE_MASK, e.g. ``CPU_SUBTYPE_LIB64`` or
    the arm64e pointer-auth ABI version) are ignored. Unknown pairs give ``cpu<type>_<subtype>``.
    """
    ct = cputype & 0xFFFFFFFF
    sub = cpusubtype & ~CPU_SUBTYPE_MASK & 0xFFFFFFFF
    if ct == CPU_TYPE_ARM64:
        return _ARM64_SUBTYPES.get(sub, "arm64")
    if ct == CPU_TYPE_ARM64_32:
        return "arm64_32"
    if ct == CPU_TYPE_ARM:
        return _ARM_SUBTYPES.get(sub, "arm")
    if ct == CPU_TYPE_X86_64:
        return _X86_64_SUBTYPES.get(sub, "x86_64")
    if ct == CPU_TYPE_X86:
        return _X86_SUBTYPES.get(sub, "i386")
    if ct == CPU_TYPE_POWERPC:
        return "ppc"
    if ct == CPU_TYPE_POWERPC64:
        return "ppc64"
    return "cpu%d_%d" % (ct, sub)


def arch_family(name: str) -> str:
    """Collapse arch variants used for slice selection (``arm64v8`` -> ``arm64``)."""
    return "arm64" if name == "arm64v8" else name


# --- Symbol table ------------------------------------------------------------------------------
# Source: <mach-o/nlist.h>.
N_STAB = 0xE0
N_PEXT = 0x10
N_TYPE = 0x0E
N_EXT = 0x01
N_UNDF = 0x0
N_ABS = 0x2
N_SECT = 0xE
N_PBUD = 0xC
N_INDR = 0xA
# Debugging stab entries (<mach-o/stab.h>): N_GSYM 0x20, N_FUN 0x24, N_STSYM 0x26, N_BNSYM 0x2e,
# N_AST 0x32, N_SLINE 0x44, N_ENSYM 0x4e, N_SO 0x64, N_OSO 0x66. Other stabs such as N_OPT (0x3c, a
# linker marker present even in stripped system binaries) do not indicate debug info.
DEBUG_STAB_TYPES = frozenset({0x20, 0x24, 0x26, 0x2E, 0x32, 0x44, 0x4E, 0x64, 0x66})
NLIST_SIZE = 12      # struct nlist (32-bit)
NLIST_64_SIZE = 16   # struct nlist_64
DYSYMTAB_COMMAND_SIZE = 80

# --- Segment / section names -------------------------------------------------------------------
SEG_TEXT = "__TEXT"
SECT_CSTRING = "__cstring"
SECT_OBJC_CLASSNAME = "__objc_classname"
SECT_OBJC_METHNAME = "__objc_methname"
# Prefix of ObjC metadata sections, e.g. ``__DATA,__objc_classlist``, ``__TEXT,__objc_classname``.
# Source: clang/ld64 section naming (observed with otool on system binaries). Heuristic prefix.
OBJC_SECTION_PREFIX = "__objc_"
# Swift metadata sections: ``__TEXT,__swift5_types`` etc. (older toolchains: ``__swift4_*``/``__swift_ast``).
# Source: observed with otool on Swift binaries; prefix matching is a heuristic.
SWIFT_SECTION_PREFIX = "__swift"

# --- Heuristic symbol sets ---------------------------------------------------------------------
# Stack protector runtime symbols (compiler emits calls/references when -fstack-protector is on).
# Source: clang/gcc stack protector ABI; confirmed on system binaries (nm).
STACK_CANARY_SYMBOLS = frozenset({"___stack_chk_fail", "___stack_chk_guard"})
# ObjC ARC runtime entry points (clang "Automatic Reference Counting" runtime support). Every name
# below was seen as an undefined symbol (``nm -u``) in Xcode.app frameworks and system apps, but
# completeness is UNVERIFIED: newer ``objc_*`` helpers may be missing. Swift's own ``_swift_retain``
# family is deliberately not included: ``uses_arc`` means Objective-C ARC.
ARC_SYMBOLS = frozenset({
    "_objc_retain", "_objc_release", "_objc_autorelease", "_objc_retainAutorelease",
    "_objc_retainAutoreleaseReturnValue", "_objc_retainAutoreleasedReturnValue",
    "_objc_autoreleaseReturnValue", "_objc_unsafeClaimAutoreleasedReturnValue", "_objc_storeStrong",
    "_objc_storeWeak", "_objc_loadWeak", "_objc_loadWeakRetained", "_objc_initWeak",
    "_objc_destroyWeak", "_objc_copyWeak", "_objc_moveWeak", "_objc_retainBlock",
    "_objc_autoreleasePoolPush", "_objc_autoreleasePoolPop",
})
OBJC_RUNTIME_SYMBOL_PREFIXES = ("_objc_msgSend", "_OBJC_CLASS_$_", "_objc_")

# --- Stripped-symbols heuristic (empirical) ----------------------------------------------------
# Calibrated on a handful of macOS system binaries (/bin/ls: 1 local + 1 external defined symbol,
# /usr/bin/true: 0/1, Xcode.app main executable: 10/1) because no iOS corpus ships with the repo.
# UNVERIFIED: thresholds are empirical, not from any Apple documentation.
STRIPPED_ALL_MAX_SYMBOLS = 8      # <= this many defined local AND external symbols => "stripped_all"
STRIPPED_LOCAL_MAX_SYMBOLS = 64   # <= this many defined local symbols => "stripped_local" (strip -x)
STAB_SAMPLE = 4096                # local symbols sampled to detect debug (stab) entries
MAX_SYMBOL_SCAN = 2_000_000       # hard cap on nlist entries visited by heuristics

# --- Dependency classification -----------------------------------------------------------------
SYSTEM_DYLIB_PREFIXES = ("/usr/lib/", "/System/Library/", "/System/iOSSupport/")
BUNDLED_DYLIB_PREFIXES = ("@rpath/", "@executable_path/", "@loader_path/")


def classify_dylib_path(path: str) -> str:
    """``system`` (OS-provided), ``bundled`` (relative to the app via @rpath & co.) or ``other``."""
    if path.startswith(SYSTEM_DYLIB_PREFIXES):
        return "system"
    if path.startswith(BUNDLED_DYLIB_PREFIXES):
        return "bundled"
    return "other"


# --- Code signing ------------------------------------------------------------------------------
# Source: xnu ``osfmk/kern/cs_blobs.h`` as shipped in Kernel.framework/Headers/kern/cs_blobs.h.
# All blob fields are big-endian regardless of the Mach-O byte order.
CSMAGIC_REQUIREMENT = 0xFADE0C00
CSMAGIC_REQUIREMENTS = 0xFADE0C01
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172
CSMAGIC_DETACHED_SIGNATURE = 0xFADE0CC1
CSMAGIC_BLOBWRAPPER = 0xFADE0B01

CSSLOT_CODEDIRECTORY = 0
CSSLOT_INFOSLOT = 1
CSSLOT_REQUIREMENTS = 2
CSSLOT_RESOURCEDIR = 3
CSSLOT_APPLICATION = 4
CSSLOT_ENTITLEMENTS = 5
CSSLOT_DER_ENTITLEMENTS = 7
CSSLOT_ALTERNATE_CODEDIRECTORIES = 0x1000
CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT = 0x1005    # one past the last alternate slot
CSSLOT_SIGNATURESLOT = 0x10000                   # CMS signature

CS_HASHTYPE_SHA1 = 1
CS_HASHTYPE_SHA256 = 2
CS_HASHTYPE_SHA256_TRUNCATED = 3
CS_HASHTYPE_SHA384 = 4
HASH_TYPE_NAMES: Dict[int, str] = {1: "sha1", 2: "sha256", 3: "sha256_truncated", 4: "sha384"}
CS_CDHASH_LEN = 20   # cdhash = first 20 bytes of the digest of the whole CodeDirectory blob

# CodeDirectory.version thresholds (CS_SUPPORTS*). Source: cs_blobs.h.
CS_SUPPORTSSCATTER = 0x20100
CS_SUPPORTSTEAMID = 0x20200
CS_SUPPORTSCODELIMIT64 = 0x20300
CS_SUPPORTSEXECSEG = 0x20400

# CodeDirectory.flags. Source: cs_blobs.h.
CS_ADHOC = 0x2
CS_GET_TASK_ALLOW = 0x4
CS_RUNTIME = 0x10000
CS_LINKER_SIGNED = 0x20000

# Parser safety limits (not format constants).
MAX_LOAD_COMMANDS = 20000        # real binaries have < 500
MAX_LC_BYTES = 16 * 1024 * 1024  # sizeofcmds beyond this is clamped (with a warning)
MAX_SIGNATURE_BYTES = 64 * 1024 * 1024
MAX_SUPERBLOB_ENTRIES = 1024


def format_version(v: int) -> str:
    """Decode a ``xxxx.yy.zz`` nibble-packed version (``0x000D0200`` -> ``13.2``; patch shown if != 0)."""
    major, minor, patch = (v >> 16) & 0xFFFF, (v >> 8) & 0xFF, v & 0xFF
    return "%d.%d.%d" % (major, minor, patch) if patch else "%d.%d" % (major, minor)


def format_source_version(v: int) -> str:
    """Decode LC_SOURCE_VERSION (``A.B.C.D.E`` packed as 24.10.10.10.10 bits)."""
    return "%d.%d.%d.%d.%d" % ((v >> 40) & 0xFFFFFF, (v >> 30) & 0x3FF, (v >> 20) & 0x3FF,
                               (v >> 10) & 0x3FF, v & 0x3FF)


def platform_name(platform: Optional[int]) -> Optional[str]:
    if platform is None:
        return None
    return PLATFORM_NAMES.get(platform, "platform%d" % platform)
