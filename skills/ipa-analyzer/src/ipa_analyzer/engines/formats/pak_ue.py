"""Unreal Engine ``.pak`` footer and IoStore ``.utoc`` header (read-only).

Pak footer (Source: the open-source ``repak`` reader/writer, ``repak/src/footer.rs`` and ``Version::size`` in
``lib.rs`` -- an independent re-implementation of ``FPakInfo::Serialize``; magic ``FPakInfo::PakFile_Magic`` =
``0x5A6F12E1``).  The footer sits at the very end of the file, little-endian::

    [u128 encryption key guid]      only when version >= 7
    [u8  index encrypted]           only when version >= 4
    u32 magic 0x5A6F12E1
    u32 version
    u64 index offset, u64 index size
    u8  index hash[20]
    [u8 frozen index]               only when version == 9
    [4 or 5 compression method names, 32 bytes each]   version >= 8 (4 names for 8a, 5 for 8b and later)

So the footer is 44 bytes, +16 (v>=7), +1 (v>=4), +1 (v==9), +128 / +160 (v>=8).  Versions 1..11 exist.

IoStore ``.utoc`` header (Source: ``retoc`` ``FIoStoreTocHeader`` and ``EIoContainerFlags``): 16 byte magic
``-==--==--==--==-``, u8 toc version, ..., header size 0x90, container flags (u8) at offset 80
(``Compressed = 1``, ``Encrypted = 2``, ``Signed = 4``, ``Indexed = 8``), key guid (16 bytes) at offset 64.

UNVERIFIED against Epic's own source (not publicly browsable without a licence).  Only the *index* encryption
flag is read here; individual entries can be encrypted while the index is not.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

PAK_MAGIC = 0x5A6F12E1
PAK_MAGIC_BYTES = struct.pack("<I", PAK_MAGIC)
TOC_MAGIC = b"-==--==--==--==-"
TOC_HEADER_SIZE = 0x90
TOC_FLAG_NAMES = ((1, "compressed"), (2, "encrypted"), (4, "signed"), (8, "indexed"))
MAX_FOOTER = 221 + 16   # generous: largest known footer (v9 with guid, flag, frozen byte, 5 names) is 221 bytes
TAIL_BYTES = 320


def footer_size(version: int, compression_names: int = 5) -> int:
    size = 4 + 4 + 8 + 8 + 20
    if version >= 7:
        size += 16
    if version >= 4:
        size += 1
    if version == 9:
        size += 1
    if version >= 8:
        size += 32 * (4 if compression_names == 4 else 5)
    return size


@dataclass
class PakInfo:
    valid: bool = False
    truncated: bool = False
    version: Optional[int] = None
    index_encrypted: Optional[bool] = None     # None: the version has no such flag (< 4) or the file is unreadable
    index_offset: Optional[int] = None
    index_size: Optional[int] = None
    index_in_bounds: Optional[bool] = None
    encryption_key_guid_nonzero: Optional[bool] = None
    compression_methods: Optional[List[str]] = None
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {k: getattr(self, k) for k in (
            "valid", "truncated", "version", "index_encrypted", "index_offset", "index_size", "index_in_bounds",
            "encryption_key_guid_nonzero", "compression_methods", "note")}


def parse_footer(tail: bytes, file_size: int) -> PakInfo:
    """Parse the footer from the last bytes (``tail``) of a pak of ``file_size`` bytes.  Never raises."""
    info = PakInfo()
    tail = bytes(tail)
    if file_size < 44 or len(tail) < 44:
        info.truncated = True
        info.note = "file too small for a pak footer"
        return info
    cands = []
    start = 0
    while True:
        i = tail.find(PAK_MAGIC_BYTES, start)
        if i < 0:
            break
        cands.append(i)
        start = i + 1
    for pos in reversed(cands):
        if pos + 8 > len(tail):
            continue
        version = struct.unpack_from("<I", tail, pos + 4)[0]
        if not 1 <= version <= 11:
            continue
        for names in ((5, 4) if version >= 8 else (5,)):
            fs = footer_size(version, names)
            lead = (16 if version >= 7 else 0) + (1 if version >= 4 else 0)
            if len(tail) - pos + lead != fs or fs > len(tail):
                continue
            body = pos + 8
            off, size = struct.unpack_from("<QQ", tail, body)
            info.valid = True
            info.version = version
            info.index_offset, info.index_size = off, size
            info.index_in_bounds = off + size <= file_size and off < file_size
            if version >= 4:
                info.index_encrypted = bool(tail[pos - 1])
            if version >= 7:
                info.encryption_key_guid_nonzero = any(tail[pos - lead:pos - 1])
            if version >= 8:
                base = body + 16 + 20
                base += 1 if version == 9 else 0
                info.compression_methods = [
                    tail[base + 32 * k: base + 32 * (k + 1)].split(b"\0", 1)[0].decode("ascii", "replace")
                    for k in range(names) if tail[base + 32 * k: base + 32 * (k + 1)].strip(b"\0")]
            if not info.index_in_bounds:
                info.note = "index offset/size points outside the file (truncated or corrupt)"
            return info
    info.truncated = True
    info.note = "pak footer magic not found at the expected place" if not cands else "pak footer inconsistent"
    return info


@dataclass
class TocInfo:
    valid: bool = False
    version: Optional[int] = None
    flags: Optional[int] = None
    flag_names: Optional[List[str]] = None
    encrypted: Optional[bool] = None
    key_guid_nonzero: Optional[bool] = None
    truncated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {k: getattr(self, k) for k in ("valid", "version", "flags", "flag_names", "encrypted",
                                              "key_guid_nonzero", "truncated")}


def parse_utoc_header(head: bytes) -> TocInfo:
    info = TocInfo()
    head = bytes(head)
    if head[:16] != TOC_MAGIC:
        return info
    if len(head) < 81:
        info.truncated = True
        return info
    info.version = head[16]
    info.flags = head[80]
    info.flag_names = [n for bit, n in TOC_FLAG_NAMES if info.flags & bit]
    info.encrypted = bool(info.flags & 2)
    info.key_guid_nonzero = any(head[64:80])
    info.valid = len(head) < 24 or struct.unpack_from("<I", head, 20)[0] == TOC_HEADER_SIZE
    return info
