"""Programmatic Mach-O fixtures (WP3). No real app files are ever stored in the repository.

Public API (import with ``from fixtures.macho_builder import ...``)::

    build_macho(*, arch="arm64", filetype="execute", dylibs=(), encrypted=False, cryptid=0,
                strings=(), objc_classes=(), symbols=(), code_signature=None, stripped=False,
                flags=PIE, **extras) -> bytes
    build_fat(slices, *, fat64=False, align=14, cigam=False) -> bytes
    build_code_signature(identifier=..., team_id=..., entitlements=..., ...) -> bytes
    write_macho_file(path, *, big_cstring=0, **build_macho_kwargs) -> Path   # sparse big files
    find_load_commands(data, cmd=None) -> [(offset, cmd, cmdsize)]            # for malformed-file tests

Parameter semantics
-------------------
* ``arch``: ``arm64 arm64e arm64v8 arm64_32 x86_64 x86_64h armv7 armv7s i386 ppc ppc64``.
* ``filetype``: ``execute | dylib | bundle | object`` (or an int).
* ``dylibs``: items are ``"path"`` or ``("path", kind)`` with kind in ``load weak reexport lazy upward``.
* ``encrypted``/``cryptid``: an ``LC_ENCRYPTION_INFO(_64)`` command is emitted when ``encrypted`` is true,
  ``cryptid`` is non-zero, or ``encryption_info=True`` (a decrypted binary that keeps the command with
  ``cryptid=0``). Its ``cryptid`` is ``cryptid`` or, failing that, 1 when ``encrypted``. ``cryptsize``
  defaults to the page-aligned ``__TEXT`` code range; pass ``cryptsize=0`` to test that edge.
* ``flags``: header flag bits OR-ed onto ``MH_NOUNDEFS|MH_DYLDLINK|MH_TWOLEVEL`` (default ``PIE``).
* ``symbols``: defined external symbol names; ``imports``: undefined symbols (``"name"`` or
  ``(name, ordinal)``); ``local_symbols``: defined local names. ``stripped=False`` with no explicit
  ``local_symbols`` generates 80 locals so the heuristic reports ``full``; ``stripped=True`` drops locals
  and defined externals (imports stay); ``stripped="local"`` drops locals only.
* ``code_signature``: ``bytes`` (a ready SuperBlob), ``True`` (ad-hoc default) or a dict of
  ``build_code_signature`` keyword arguments.
* Extras: ``objc_methods objc imports local_symbols debug_stabs swift cpp rpaths uuid platform min_os
  sdk build_version big_endian encryption_info cryptsize install_name entry symtab dysymtab
  canary arc big_cstring``.

Output is deterministic (UUID derived from the parameters unless given).
"""
from __future__ import annotations

import hashlib
import plistlib
import struct
import uuid as _uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

# --- constants (Source: <mach-o/loader.h>, <mach/machine.h>, xnu cs_blobs.h; kept independent of src) ---
PIE = 0x200000
MH_NOUNDEFS, MH_DYLDLINK, MH_TWOLEVEL = 0x1, 0x4, 0x80
BASE_FLAGS = MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL

CPU_ARM, CPU_X86, CPU_PPC = 12, 7, 18
ABI64, ABI64_32 = 0x01000000, 0x02000000
ARCHES: Dict[str, Tuple[int, int]] = {
    "arm64": (CPU_ARM | ABI64, 0), "arm64v8": (CPU_ARM | ABI64, 1), "arm64e": (CPU_ARM | ABI64, 2),
    "arm64_32": (CPU_ARM | ABI64_32, 0), "x86_64": (CPU_X86 | ABI64, 3), "x86_64h": (CPU_X86 | ABI64, 8),
    "armv7": (CPU_ARM, 9), "armv7s": (CPU_ARM, 11), "i386": (CPU_X86, 3),
    "ppc": (CPU_PPC, 0), "ppc64": (CPU_PPC | ABI64, 0),
}
FILETYPES = {"object": 1, "execute": 2, "dylib": 6, "bundle": 8}
PLATFORMS = {"macos": 1, "ios": 2, "tvos": 3, "watchos": 4, "maccatalyst": 6, "iossimulator": 7}
_VERSION_MIN_CMD = {"macos": 0x24, "ios": 0x25, "tvos": 0x2F, "watchos": 0x30}

LC_SEGMENT, LC_SYMTAB, LC_DYSYMTAB, LC_LOAD_DYLIB, LC_ID_DYLIB = 0x1, 0x2, 0xB, 0xC, 0xD
LC_LOAD_DYLINKER, LC_SEGMENT_64, LC_UUID, LC_CODE_SIGNATURE = 0xE, 0x19, 0x1B, 0x1D
LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64, LC_BUILD_VERSION = 0x21, 0x2C, 0x32
LC_REQ_DYLD = 0x80000000
_DYLIB_CMDS = {"load": LC_LOAD_DYLIB, "weak": 0x18 | LC_REQ_DYLD, "reexport": 0x1F | LC_REQ_DYLD,
               "lazy": 0x20, "upward": 0x23 | LC_REQ_DYLD}
LC_RPATH, LC_MAIN, LC_SOURCE_VERSION = 0x1C | LC_REQ_DYLD, 0x28 | LC_REQ_DYLD, 0x2A

PAGE = 0x1000
S_CSTRING_LITERALS, S_REGULAR = 0x2, 0x0
S_ATTR_PURE_INSTRUCTIONS, S_ATTR_SOME_INSTRUCTIONS = 0x80000000, 0x400
N_UNDF, N_EXT, N_SECT = 0x0, 0x1, 0xE
N_SO, N_OSO = 0x64, 0x66

CSMAGIC_REQUIREMENTS, CSMAGIC_CODEDIRECTORY, CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0C01, 0xFADE0C02, 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS, CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, CSMAGIC_BLOBWRAPPER = 0xFADE7171, 0xFADE7172, 0xFADE0B01

DylibSpec = Union[str, Tuple[str, str]]


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def encode_version(text: str) -> int:
    """``"12.0"`` / ``"17.2.1"`` -> nibble-packed ``xxxx.yy.zz``."""
    parts = [int(p) for p in str(text).split(".")] + [0, 0, 0]
    return (parts[0] << 16) | (parts[1] << 8) | parts[2]


def _name16(name: str) -> bytes:
    return name.encode("ascii").ljust(16, b"\0")


# --- code signature -----------------------------------------------------------------------------
def build_code_signature(identifier: str = "com.example.fixture", team_id: Optional[str] = None,
                         entitlements: Optional[Dict[str, Any]] = None, *, hash_type: int = 2,
                         alt_sha1: bool = False, flags: int = 0x2, der_entitlements: bool = False,
                         requirements: bool = True, cms: Union[bool, str, bytes] = False,
                         version: int = 0x20400, n_code_slots: int = 4) -> bytes:
    """A syntactically valid embedded-signature SuperBlob (page hashes are dummy zeros).

    ``cms``: ``False`` (no CMS slot), ``"empty"`` (8-byte wrapper like an ad-hoc signature), ``True`` or
    ``bytes`` (non-empty wrapper). ``alt_sha1`` adds an alternate SHA-1 CodeDirectory.
    """
    def code_directory(htype: int) -> bytes:
        hsize = {1: 20, 2: 32, 3: 20, 4: 48}[htype]
        header_len = {0x20100: 48, 0x20200: 52, 0x20300: 64, 0x20400: 88}.get(version, 88)
        ident = identifier.encode("utf-8") + b"\0"
        team = (team_id.encode("utf-8") + b"\0") if (team_id and version >= 0x20200) else b""
        ident_off = header_len
        team_off = ident_off + len(ident) if team else 0
        n_special = 2
        hash_off = _align(ident_off + len(ident) + len(team), 4) + n_special * hsize
        total = hash_off + n_code_slots * hsize
        head = struct.pack(">IIIIIIIIIBBBBI", CSMAGIC_CODEDIRECTORY, total, version, flags, hash_off, ident_off,
                           n_special, n_code_slots, 0, hsize, htype, 0, 12, 0)
        if version >= 0x20100:
            head += struct.pack(">I", 0)                      # scatterOffset
        if version >= 0x20200:
            head += struct.pack(">I", team_off)
        if version >= 0x20300:
            head += struct.pack(">IQ", 0, 0)                  # spare3, codeLimit64
        if version >= 0x20400:
            head += struct.pack(">QQQ", 0, 0, 0)              # execSegBase / Limit / Flags
        head = head.ljust(header_len, b"\0")[:header_len]
        body = head + ident + team
        body = body.ljust(hash_off, b"\0") + b"\x00" * (n_code_slots * hsize)
        return body

    blobs: List[Tuple[int, bytes]] = [(0, code_directory(hash_type))]
    if requirements:
        blobs.append((2, struct.pack(">III", CSMAGIC_REQUIREMENTS, 12, 0)))
    if entitlements is not None:
        xml = plistlib.dumps(entitlements, fmt=plistlib.FMT_XML)
        blobs.append((5, struct.pack(">II", CSMAGIC_EMBEDDED_ENTITLEMENTS, 8 + len(xml)) + xml))
    if der_entitlements:
        der = b"\x70\x03\x31\x01\x00"
        blobs.append((7, struct.pack(">II", CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, 8 + len(der)) + der))
    if alt_sha1:
        blobs.append((0x1000, code_directory(1)))
    if cms:
        payload = b"" if cms == "empty" else (cms if isinstance(cms, bytes) else b"\x30\x80" + b"\x00" * 14)
        blobs.append((0x10000, struct.pack(">II", CSMAGIC_BLOBWRAPPER, 8 + len(payload)) + payload))
    count = len(blobs)
    off = 12 + count * 8
    index, data = b"", b""
    for slot, blob in blobs:
        index += struct.pack(">II", slot, off + len(data))
        data += blob
    return struct.pack(">III", CSMAGIC_EMBEDDED_SIGNATURE, off + len(data), count) + index + data


# --- the builder --------------------------------------------------------------------------------
class _Sec:
    def __init__(self, seg: str, name: str, parts: List[Tuple[int, bytes]], size: int, flags: int) -> None:
        self.seg, self.name, self.parts, self.size, self.flags = seg, name, parts, size, flags
        self.offset = 0


def _normalize_dylibs(dylibs: Iterable[DylibSpec]) -> List[Tuple[str, str]]:
    out = []
    for d in dylibs:
        out.append((d, "load") if isinstance(d, str) else (d[0], d[1]))
    return out


def _assemble(*, arch: str = "arm64", filetype: Union[str, int] = "execute", dylibs: Sequence[DylibSpec] = (),
              encrypted: bool = False, cryptid: int = 0, strings: Sequence[str] = (),
              objc_classes: Sequence[str] = (), symbols: Sequence[str] = (),
              code_signature: Union[None, bool, bytes, Dict[str, Any]] = None,
              stripped: Union[bool, str] = False, flags: int = PIE,
              objc_methods: Sequence[str] = (), objc: bool = False,
              imports: Sequence[Union[str, Tuple[str, int]]] = (), local_symbols: Sequence[str] = (),
              debug_stabs: bool = False, swift: bool = False, cpp: bool = False, rpaths: Sequence[str] = (),
              uuid: Optional[str] = None, platform: str = "ios", min_os: str = "12.0", sdk: str = "17.0",
              build_version: bool = True, big_endian: bool = False, encryption_info: bool = False,
              cryptsize: Optional[int] = None, install_name: Optional[str] = None, entry: bool = True,
              symtab: bool = True, dysymtab: bool = True, canary: bool = False, arc: bool = False,
              big_cstring: int = 0) -> Tuple[List[Tuple[int, bytes]], int]:
    cputype, cpusub = ARCHES[arch]
    is64 = bool(cputype & ABI64)
    bo = ">" if big_endian else "<"
    ft = FILETYPES[filetype] if isinstance(filetype, str) else int(filetype)
    hsize = 32 if is64 else 28
    dyl = _normalize_dylibs(dylibs)
    if cpp:
        dyl.append(("/usr/lib/libc++.1.dylib", "load"))
    ptr = 8 if is64 else 4
    seg_cmd = LC_SEGMENT_64 if is64 else LC_SEGMENT
    vm_base = 0x100000000 if (is64 and ft == 2) else (0x4000 if ft == 2 else 0)

    def P(fmt: str, *vals: Any) -> bytes:
        return struct.pack(bo + fmt, *vals)

    # --- text/data sections -------------------------------------------------------------------
    text_secs: List[_Sec] = [_Sec("__TEXT", "__text", [(0, b"\x1f\x20\x03\xd5" * 4)], 16,
                                  S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)]
    cstr_head = b"".join(s.encode("utf-8") + b"\0" for s in strings)
    if strings or big_cstring:
        parts = [(0, cstr_head)]
        size = len(cstr_head)
        if big_cstring:
            tail = b"END_OF_BIG_CSTRING\0"
            parts.append((size + big_cstring, tail))
            size += big_cstring + len(tail)
        text_secs.append(_Sec("__TEXT", "__cstring", parts, size, S_CSTRING_LITERALS))
    if objc_classes:
        blob = b"".join(c.encode() + b"\0" for c in objc_classes)
        text_secs.append(_Sec("__TEXT", "__objc_classname", [(0, blob)], len(blob), S_CSTRING_LITERALS))
    if objc_methods:
        blob = b"".join(c.encode() + b"\0" for c in objc_methods)
        text_secs.append(_Sec("__TEXT", "__objc_methname", [(0, blob)], len(blob), S_CSTRING_LITERALS))
    if swift:
        text_secs.append(_Sec("__TEXT", "__swift5_types", [(0, b"\0" * 8)], 8, S_REGULAR))
        text_secs.append(_Sec("__TEXT", "__swift5_protos", [(0, b"\0" * 8)], 8, S_REGULAR))
    data_secs: List[_Sec] = []
    if objc or objc_classes or objc_methods:
        data_secs.append(_Sec("__DATA", "__objc_classlist", [(0, b"\0" * ptr)], ptr, S_REGULAR))
        data_secs.append(_Sec("__DATA", "__objc_imageinfo", [(0, b"\0" * 8)], 8, S_REGULAR))

    # --- symbols --------------------------------------------------------------------------------
    drop_defined = stripped is True
    drop_local = stripped is True or stripped == "local"
    ext_defs = [] if drop_defined else list(symbols)
    locals_ = [] if drop_local else (list(local_symbols) or ["_local_fn_%d" % i for i in range(80)])
    imps: List[Tuple[str, int]] = []
    for item in imports:
        imps.append((item, 1) if isinstance(item, str) else (item[0], item[1]))
    if canary:
        imps += [("___stack_chk_fail", 1), ("___stack_chk_guard", 1)]
    if arc:
        imps += [("_objc_retain", 1), ("_objc_release", 1)]
    mh_header_sym = ["__mh_execute_header"] if ft == 2 else []
    ext_all = mh_header_sym + ext_defs
    stab_names = ["/src/main.c", "/obj/main.o"] if debug_stabs else []

    strtab = b"\0"
    nlist_rows: List[Tuple[int, int, int, int, int]] = []

    def add_name(name: str) -> int:
        nonlocal strtab
        idx = len(strtab)
        strtab += name.encode("utf-8") + b"\0"
        return idx

    text_addr_guess = vm_base
    if debug_stabs:
        nlist_rows.append((add_name(stab_names[0]), N_SO, 0, 0, 0))
        nlist_rows.append((add_name(stab_names[1]), N_OSO, 0, 1, 0))
    for i, n in enumerate(locals_):
        nlist_rows.append((add_name(n), N_SECT, 1, 0, text_addr_guess + i * 4))
    n_stab = 2 if debug_stabs else 0
    n_local = len(locals_) + n_stab
    for i, n in enumerate(ext_all):
        nlist_rows.append((add_name(n), N_SECT | N_EXT, 1, 0, text_addr_guess + i * 4))
    for n, ordinal in imps:
        nlist_rows.append((add_name(n), N_UNDF | N_EXT, 0, (ordinal & 0xFF) << 8, 0))
    nsyms = len(nlist_rows)
    esize = 16 if is64 else 12
    have_symtab = bool(symtab)
    strtab = strtab.ljust(_align(len(strtab), 8), b"\0")

    cs_bytes: Optional[bytes]
    if code_signature is None or code_signature is False:
        cs_bytes = None
    elif code_signature is True:
        cs_bytes = build_code_signature()
    elif isinstance(code_signature, dict):
        cs_bytes = build_code_signature(**code_signature)
    else:
        cs_bytes = bytes(code_signature)

    make_enc = encrypted or bool(cryptid) or encryption_info
    crypt_value = cryptid if cryptid else (1 if encrypted else 0)

    # --- load commands as a function of the final layout ---------------------------------------
    def commands(L: Dict[str, int]) -> List[bytes]:
        cmds: List[bytes] = []

        def sec_bytes(s: _Sec) -> bytes:
            addr = vm_base + s.offset      # file offset == vm offset in these flat fixtures
            if is64:
                return P("16s16sQQIIIIIIII", _name16(s.name), _name16(s.seg), addr, s.size, s.offset, 4, 0, 0,
                         s.flags, 0, 0, 0)
            return P("16s16sIIIIIIIII", _name16(s.name), _name16(s.seg), addr, s.size, s.offset, 4, 0, 0,
                     s.flags, 0, 0)

        def seg(name: str, vmaddr: int, vmsize: int, fileoff: int, filesize: int, prot: int,
                secs: List[_Sec]) -> bytes:
            fixed = 72 if is64 else 56
            sect = 80 if is64 else 68
            size = fixed + sect * len(secs)
            if is64:
                body = P("II16sQQQQiiII", seg_cmd, size, _name16(name), vmaddr, vmsize, fileoff, filesize, prot,
                         prot, len(secs), 0)
            else:
                body = P("II16sIIIIiiII", seg_cmd, size, _name16(name), vmaddr, vmsize, fileoff, filesize, prot,
                         prot, len(secs), 0)
            return body + b"".join(sec_bytes(s) for s in secs)

        if ft == 2:
            cmds.append(seg("__PAGEZERO", 0, vm_base, 0, 0, 0, []))
        cmds.append(seg("__TEXT", vm_base, L["text_filesize"], 0, L["text_filesize"], 5, text_secs))
        if data_secs:
            cmds.append(seg("__DATA", vm_base + L["data_fileoff"], L["data_filesize"], L["data_fileoff"],
                            L["data_filesize"], 3, data_secs))
        cmds.append(seg("__LINKEDIT", vm_base + L["le_fileoff"], _align(max(L["le_size"], 1), PAGE),
                        L["le_fileoff"], L["le_size"], 1, []))
        if have_symtab:
            cmds.append(P("IIIIII", LC_SYMTAB, 24, L["symoff"], nsyms, L["stroff"], len(strtab)))
        if have_symtab and dysymtab:
            n_ext = len(ext_all)
            cmds.append(P("II" + "I" * 18, LC_DYSYMTAB, 80, 0, n_local, n_local, n_ext, n_local + n_ext, len(imps),
                          *([0] * 12)))
        if ft == 2:
            path = b"/usr/lib/dyld\0"
            size = _align(12 + len(path), 8)
            cmds.append(P("III", LC_LOAD_DYLINKER, size, 12) + path.ljust(size - 12, b"\0"))
        u = uuid or str(_uuid.UUID(bytes=hashlib.md5(("%s|%s|%s" % (arch, ft, len(strings))).encode()).digest()))
        cmds.append(P("II", LC_UUID, 24) + _uuid.UUID(u).bytes)
        if build_version:
            cmds.append(P("IIIIIIII", LC_BUILD_VERSION, 32, PLATFORMS[platform], encode_version(min_os),
                          encode_version(sdk), 1, 3, encode_version("1000.0")))
        else:
            cmds.append(P("IIII", _VERSION_MIN_CMD[platform], 16, encode_version(min_os), encode_version(sdk)))
        if ft == 2 and entry:
            cmds.append(P("IIQQ", LC_MAIN, 24, L["text_sec_off"], 0))
        if ft == 6:
            name = (install_name or "@rpath/Fixture.framework/Fixture").encode() + b"\0"
            size = _align(24 + len(name), 8)
            cmds.append(P("IIIIII", LC_ID_DYLIB, size, 24, 2, encode_version("1.0"), encode_version("1.0"))
                        + name.ljust(size - 24, b"\0"))
        for path, kind in dyl:
            name = path.encode() + b"\0"
            size = _align(24 + len(name), 8)
            cmds.append(P("IIIIII", _DYLIB_CMDS[kind], size, 24, 2, encode_version("1.2.3"), encode_version("1.0"))
                        + name.ljust(size - 24, b"\0"))
        for rp in rpaths:
            name = rp.encode() + b"\0"
            size = _align(12 + len(name), 8)
            cmds.append(P("III", LC_RPATH, size, 12) + name.ljust(size - 12, b"\0"))
        if make_enc:
            csize = cryptsize if cryptsize is not None else L["text_filesize"] - L["first_data"]
            if is64:
                cmds.append(P("IIIII", LC_ENCRYPTION_INFO_64, 24, L["first_data"], csize, crypt_value) + P("I", 0))
            else:
                cmds.append(P("IIIII", LC_ENCRYPTION_INFO, 20, L["first_data"], csize, crypt_value))
        if cs_bytes is not None:
            cmds.append(P("IIII", LC_CODE_SIGNATURE, 16, L["cs_off"], len(cs_bytes)))
        return cmds

    zero = {k: 0 for k in ("text_filesize", "data_fileoff", "data_filesize", "le_fileoff", "le_size", "symoff",
                           "stroff", "cs_off", "first_data", "text_sec_off")}
    sizeofcmds = sum(len(c) for c in commands(zero))
    first_data = _align(hsize + sizeofcmds, PAGE)

    pos = first_data
    for s in text_secs:
        pos = _align(pos, 16)
        s.offset = pos
        pos += s.size
    text_filesize = _align(pos, PAGE)
    data_fileoff = text_filesize
    pos = data_fileoff
    for s in data_secs:
        pos = _align(pos, 16)
        s.offset = pos
        pos += s.size
    data_filesize = _align(pos - data_fileoff, PAGE) if data_secs else 0
    le_fileoff = data_fileoff + data_filesize
    symoff = _align(le_fileoff, 8)
    stroff = symoff + nsyms * esize if have_symtab else symoff
    le_end = stroff + (len(strtab) if have_symtab else 0)
    cs_off = _align(le_end, 16)
    total = cs_off + len(cs_bytes) if cs_bytes is not None else le_end
    le_size = total - le_fileoff
    layout = {"text_filesize": text_filesize, "data_fileoff": data_fileoff, "data_filesize": data_filesize,
              "le_fileoff": le_fileoff, "le_size": le_size, "symoff": symoff, "stroff": stroff,
              "cs_off": cs_off, "first_data": first_data, "text_sec_off": text_secs[0].offset}
    cmds = commands(layout)
    assert sum(len(c) for c in cmds) == sizeofcmds

    magic = (0xFEEDFACF if is64 else 0xFEEDFACE)
    header = P("IiiIIII", magic, cputype, cpusub, ft, len(cmds), sizeofcmds, BASE_FLAGS | flags)
    if is64:
        header += P("I", 0)
    pieces: List[Tuple[int, bytes]] = [(0, header + b"".join(cmds))]
    for s in text_secs + data_secs:
        for rel, blob in s.parts:
            pieces.append((s.offset + rel, blob))
    if have_symtab:
        rows = b"".join(P("IBBHQ" if is64 else "IBBHI", strx, t, sect, desc, val) for strx, t, sect, desc, val in nlist_rows)
        pieces.append((symoff, rows))
        pieces.append((stroff, strtab))
    if cs_bytes is not None:
        pieces.append((cs_off, cs_bytes))
    return pieces, total


def build_macho(*, arch: str = "arm64", filetype: Union[str, int] = "execute", dylibs: Sequence[DylibSpec] = (),
                encrypted: bool = False, cryptid: int = 0, strings: Sequence[str] = (),
                objc_classes: Sequence[str] = (), symbols: Sequence[str] = (),
                code_signature: Union[None, bool, bytes, Dict[str, Any]] = None,
                stripped: Union[bool, str] = False, flags: int = PIE, **extras: Any) -> bytes:
    """Build a thin Mach-O image (see module docstring)."""
    pieces, total = _assemble(arch=arch, filetype=filetype, dylibs=dylibs, encrypted=encrypted, cryptid=cryptid,
                              strings=strings, objc_classes=objc_classes, symbols=symbols,
                              code_signature=code_signature, stripped=stripped, flags=flags, **extras)
    if extras.get("big_cstring"):
        raise ValueError("big_cstring needs write_macho_file() (it would allocate the whole file)")
    buf = bytearray(total)
    for off, blob in pieces:
        buf[off:off + len(blob)] = blob
    return bytes(buf)


def write_macho_file(path: Union[str, Path], *, big_cstring: int = 0, **kwargs: Any) -> Path:
    """Write a Mach-O whose ``__cstring`` is ``big_cstring`` bytes larger (sparse zero gap).

    The gap is never materialised in memory; the file is created sparse where the OS supports it.
    A final string ``END_OF_BIG_CSTRING`` sits after the gap.
    """
    pieces, total = _assemble(big_cstring=big_cstring, **kwargs)
    path = Path(path)
    with open(path, "wb") as fh:
        for off, blob in sorted(pieces):
            fh.seek(off)
            fh.write(blob)
        fh.truncate(total)
    return path


def build_fat(slices: Sequence[bytes], *, fat64: bool = False, align: int = 14, cigam: bool = False) -> bytes:
    """Wrap thin images into a universal binary (big-endian header unless ``cigam``)."""
    bo = "<" if cigam else ">"
    esize = 32 if fat64 else 20
    entries = []
    pos = _align(8 + len(slices) * esize, 1 << align)
    for blob in slices:
        magic_le = struct.unpack("<I", blob[:4])[0]
        sbo = "<" if magic_le in (0xFEEDFACE, 0xFEEDFACF) else ">"
        cputype, cpusub = struct.unpack(sbo + "ii", blob[4:12])
        entries.append((cputype, cpusub, pos, len(blob)))
        pos = _align(pos + len(blob), 1 << align)
    magic = 0xCAFEBABF if fat64 else 0xCAFEBABE
    out = struct.pack(bo + "II", magic, len(slices))
    for cputype, cpusub, off, size in entries:
        if fat64:
            out += struct.pack(bo + "iiQQII", cputype, cpusub, off, size, align, 0)
        else:
            out += struct.pack(bo + "iiIII", cputype, cpusub, off, size, align)
    buf = bytearray(out.ljust(entries[0][2] if entries else len(out), b"\0"))
    for (_, _, off, _size), blob in zip(entries, slices):
        buf.extend(b"\0" * (off - len(buf)))
        buf.extend(blob)
    return bytes(buf)


def find_load_commands(data: bytes, cmd: Optional[int] = None) -> List[Tuple[int, int, int]]:
    """``[(file_offset, cmd, cmdsize)]`` of a thin 32/64-bit image (either byte order); for malformed-file tests."""
    magic_le = struct.unpack("<I", data[:4])[0]
    bo = "<" if magic_le in (0xFEEDFACE, 0xFEEDFACF) else ">"
    hsize = 32 if magic_le in (0xFEEDFACF, 0xCFFAEDFE) else 28
    ncmds = struct.unpack(bo + "I", data[16:20])[0]
    pos, out = hsize, []
    for _ in range(ncmds):
        c, size = struct.unpack(bo + "II", data[pos:pos + 8])
        if cmd is None or c == cmd:
            out.append((pos, c, size))
        pos += size
    return out
