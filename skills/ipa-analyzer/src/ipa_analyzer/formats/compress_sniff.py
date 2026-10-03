"""Compression-container sniffing from the first bytes of a blob.

Returns a best guess with a confidence that reflects how distinctive the magic is.  Long magics
(xz, zstd, bzip2, LZ4 frame, gzip) are reliable; a bare zlib header is only two bytes and is
validated with its FCHECK rule; raw/"LZMA alone" streams have no magic at all and are reported
at low confidence.  This is a hint for classification ("compressed" vs "encrypted-looking"), never
proof, and nothing is decompressed.

Sources:
  * zlib: RFC 1950 (CMF/FLG; CM=8, CINFO<=7, (CMF*256+FLG) % 31 == 0, FDICT bit 0x20);
    the usual FLG values after CMF 0x78 are 01 / 5E / 9C / DA.
  * gzip: RFC 1952 (ID1=0x1F, ID2=0x8B, CM=8).
  * LZ4 frame: lz4_Frame_format.md (magic 0x184D2204 little-endian => 04 22 4D 18); the frame
    descriptor FLG byte must carry version bits 01.
  * Zstandard: RFC 8878 (magic 0xFD2FB528 little-endian => 28 B5 2F FD).
  * bzip2: "BZh" + level '1'..'9'; the first block header is 0x314159265359 (de-facto format).
  * xz: tukaani.org/xz/xz-file-format.txt (FD 37 7A 58 5A 00).
  * LZMA-alone (.lzma): properties byte (usually 0x5D = lc3 lp0 pb2), u32 LE dictionary size,
    u64 uncompressed size or all-ones.  UNVERIFIED as a *classifier*: there is no magic, so this
    can only suggest and is deliberately capped at 0.5.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List

__all__ = ["CompressionGuess", "sniff"]


@dataclass
class CompressionGuess:
    kind: str  # zlib | gzip | lz4_frame | zstd | bzip2 | xz | lzma | none
    confidence: float
    note: str = ""
    alternatives: List["CompressionGuess"] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "confidence": self.confidence, "note": self.note}


_NONE = CompressionGuess("none", 0.0, "no known compression magic")
_ZLIB_COMMON_FLG = {0x01, 0x5E, 0x9C, 0xDA}
# UNVERIFIED: LZMA has no magic; the heuristics at the end of sniff() are shape guesses only.


def _is_pow2_or_3x(n: int) -> bool:
    return n > 0 and (n & (n - 1) == 0 or (n % 3 == 0 and (n // 3) & (n // 3 - 1) == 0))


def sniff(data: bytes) -> CompressionGuess:
    """Guess the compression container of ``data`` from its leading bytes."""
    head = bytes(data[:32])
    n = len(head)
    if n < 2:
        return _NONE

    if head[:6] == b"\xfd7zXZ\x00":
        return CompressionGuess("xz", 0.98, "xz stream header")
    if head[:4] == b"\x28\xb5\x2f\xfd":
        return CompressionGuess("zstd", 0.97, "Zstandard frame magic")
    if head[:4] == b"\x04\x22\x4d\x18":
        flg = head[4] if n > 4 else None
        if flg is not None and (flg >> 6) != 1:
            return CompressionGuess("lz4_frame", 0.6, "LZ4 frame magic but unexpected version bits")
        return CompressionGuess("lz4_frame", 0.97, "LZ4 frame magic")
    if head[:3] == b"BZh" and n >= 4 and 0x31 <= head[3] <= 0x39:
        if head[4:10] == b"\x31\x41\x59\x26\x53\x59":
            return CompressionGuess("bzip2", 0.98, "bzip2 header and first block magic")
        return CompressionGuess("bzip2", 0.85, "bzip2 stream header")
    if head[:2] == b"\x1f\x8b":
        if n >= 3 and head[2] == 8:
            return CompressionGuess("gzip", 0.95, "gzip header, deflate method")
        return CompressionGuess("gzip", 0.5, "gzip ID bytes but unusual method byte")

    cmf, flg = head[0], head[1]
    if (
        cmf & 0x0F == 8
        and cmf >> 4 <= 7
        and (cmf * 256 + flg) % 31 == 0
        and not flg & 0x20
    ):
        if cmf == 0x78 and flg in _ZLIB_COMMON_FLG:
            conf, note = 0.85, "zlib header (78 xx, common FLG)"
        elif cmf == 0x78:
            conf, note = 0.6, "zlib header with uncommon FLG"
        else:
            conf, note = 0.45, "zlib-shaped 2-byte header with a small window size"
        return CompressionGuess("zlib", conf, note)

    if n >= 13 and head[0] < 225:
        (dict_size,) = struct.unpack_from("<I", head, 1)
        size_field = head[5:13]
        size = struct.unpack("<Q", size_field)[0]
        size_ok = size_field == b"\xff" * 8 or size < (1 << 40)
        if head[0] == 0x5D and _is_pow2_or_3x(dict_size) and 1 << 12 <= dict_size <= 1 << 30 and size_ok:
            return CompressionGuess("lzma", 0.5, "LZMA-alone header shape (no magic; weak evidence)")
    if n >= 5 and head[0] == 0x5D:
        (dict_size,) = struct.unpack_from("<I", head, 1)
        if _is_pow2_or_3x(dict_size) and 1 << 12 <= dict_size <= 1 << 30:
            return CompressionGuess("lzma", 0.3, "5D + power-of-two dictionary: possibly Unity-style raw LZMA (weak evidence)")
    return _NONE
