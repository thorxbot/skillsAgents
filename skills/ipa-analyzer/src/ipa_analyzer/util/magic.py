"""Header-only file type sniffing.

``sniff(head)`` identifies a file from its first bytes; signature checks look at the first 64 bytes
only, the text / XML / PE heuristics may use up to ``TEXT_SNIFF_BYTES`` (callers should pass what
they have, never the whole file). The result is ``(type_id, confidence)``; confidence is
0..1 and signatures below ``STRONG_CONFIDENCE`` are "weak" hints that callers should not let
override a trustworthy file extension. This module never classifies content as encrypted: it only
names formats.

Type ids are lower-case ``[a-z0-9_]``. Unknown content yields ``("unknown", 0.0)``.
"""
from __future__ import annotations

import re
import struct
from typing import Callable, Dict, List, Optional, Tuple

__all__ = ["sniff", "sniff_tail", "SNIFF_BYTES", "TEXT_SNIFF_BYTES", "STRONG_CONFIDENCE", "MAGIC_IDS",
           "macho_header_info", "is_texty"]

SNIFF_BYTES = 64
TEXT_SNIFF_BYTES = 512
STRONG_CONFIDENCE = 0.6

Result = Tuple[str, float]

# --- fixed signatures at offset 0: (signature, type id, confidence) ---------------------------------
# Sources are given per group. Facts marked UNVERIFIED were written from memory of the respective
# format and were not re-checked against a primary source / real sample.
_FIXED: List[Tuple[bytes, str, float]] = [
    # Source: PNG spec (RFC 2083 / W3C PNG) 8-byte signature.
    (b"\x89PNG\r\n\x1a\n", "png", 0.99),
    # Source: JPEG/JFIF: SOI marker FFD8 followed by a marker FF.
    (b"\xff\xd8\xff", "jpeg", 0.97),
    # Source: GIF89a spec.
    (b"GIF87a", "gif", 0.99), (b"GIF89a", "gif", 0.99),
    # Source: TIFF 6.0 spec byte-order marks.
    (b"II*\x00", "tiff", 0.9), (b"MM\x00*", "tiff", 0.9),
    # Source: Apple icns format (OSType 'icns').
    (b"icns", "icns", 0.9),
    # Source: Khronos KTX 1.1 / KTX2 file identifiers (the 12-byte identifier starts with these bytes).
    (b"\xabKTX 11\xbb\r\n\x1a\n", "ktx", 0.99), (b"\xabKTX 20\xbb\r\n\x1a\n", "ktx2", 0.99),
    # UNVERIFIED (from memory of the PVR v3 header, version field 0x03525650 little-endian).
    (b"PVR\x03", "pvr", 0.85),
    # Source: DDS file magic "DDS ".
    (b"DDS ", "dds", 0.95),
    # UNVERIFIED (from memory): ASTC file header magic 0x5CA1AB13 (little-endian).
    (b"\x13\xab\xa1\x5c", "astc", 0.9),
    # Source: cocos-engine ZipUtils.h CCZHeader.sig "CCZ!".
    # and ZipUtils.cpp: sig[3] == '!' (plain) or 'p' (encrypted CCZ).
    (b"CCZ!", "ccz", 0.9), (b"CCZp", "ccz", 0.9),
    # Source: ID3v2 tag header; Ogg (RFC 3533) "OggS"; FLAC "fLaC"; CAF spec "caff"; AMR "#!AMR"; SMF "MThd".
    (b"ID3", "mp3", 0.85), (b"OggS", "ogg", 0.97), (b"fLaC", "flac", 0.97), (b"caff", "caf", 0.97),
    (b"#!AMR", "amr", 0.95), (b"MThd", "midi", 0.95),
    # Source: Matroska/WebM EBML header 1A45DFA3; FLV "FLV\x01"; MPEG program stream pack header 000001BA.
    (b"\x1a\x45\xdf\xa3", "matroska", 0.9), (b"FLV\x01", "flv", 0.9), (b"\x00\x00\x01\xba", "mpeg_ps", 0.8),
    # UNVERIFIED (from memory): ASF header object GUID 75B22630-668E-11CF-A6D9-00AA0062CE6C.
    (b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c", "asf", 0.95),
    # Source: OpenType spec: 'OTTO' (CFF), 'ttcf' (collection), Apple 'true'; WOFF 'wOFF', WOFF2 'wOF2'.
    (b"OTTO", "otf", 0.97), (b"ttcf", "ttc", 0.97), (b"true", "ttf", 0.9),
    (b"wOFF", "woff", 0.97), (b"wOF2", "woff2", 0.97),
    # Source: SQLite file format doc: header string "SQLite format 3\0".
    (b"SQLite format 3\x00", "sqlite", 0.99),
    # Source: Apple binary property list header "bplist" + 2-digit version (observed: "bplist00").
    (b"bplist00", "bplist", 0.97),
    # Source: Unity UnityFS/UnityWeb/UnityRaw/UnityArchive signatures (NUL-terminated strings).
    (b"UnityFS\x00", "unityfs", 0.99), (b"UnityWeb\x00", "unityweb", 0.99),
    (b"UnityRaw\x00", "unityraw", 0.99), (b"UnityArchive\x00", "unityarchive", 0.99),
    # Source: Godot file_access_pack.h PACK_HEADER_MAGIC 0x43504447 (little-endian "GDPC").
    (b"GDPC", "gdpc", 0.9),
    # Source: Il2CppDumper Metadata.cs sanity 0xFAB11BAF (little-endian AF 1B B1 FA).
    (b"\xaf\x1b\xb1\xfa", "il2cpp_metadata", 0.97),
    # Source: Apple Bill of Materials store header "BOMStore" (Assets.car).
    (b"BOMStore", "bomstore", 0.99),
    # Source: compiled nib archive header "NIBArchive" (checked against system .nib files on macOS).
    (b"NIBArchive", "nib_archive", 0.95),
    # Source: Metal library header "MTLB" (checked against system .metallib files on macOS).
    (b"MTLB", "metallib", 0.9),
    # Source: gzip RFC 1952 (1F 8B 08); bzip2 "BZh"; xz "FD 37 7A 58 5A 00"; 7z; zstd RFC 8478 28B52FFD;
    # LZ4 frame format 04224D18; RAR "Rar!\x1a\x07".
    (b"\x1f\x8b\x08", "gzip", 0.95), (b"\xfd7zXZ\x00", "xz", 0.97), (b"7z\xbc\xaf\x27\x1c", "7z", 0.97),
    (b"\x28\xb5\x2f\xfd", "zstd", 0.9), (b"\x04\x22\x4d\x18", "lz4_frame", 0.9), (b"Rar!\x1a\x07", "rar", 0.97),
    # Source: PKWARE APPNOTE local header / end of central directory / spanning marker.
    (b"PK\x03\x04", "zip", 0.95), (b"PK\x05\x06", "zip", 0.9), (b"PK\x07\x08", "zip", 0.6),
    # Source: Lua / LuaJIT precompiled chunk signatures ESC "Lua" / ESC "LJ".
    (b"\x1bLua", "lua_bytecode", 0.97), (b"\x1bLJ", "lua_bytecode", 0.95),
    # Source: facebook/hermes BytecodeFileFormat.h MAGIC = 0x1F1903C103BC1FC6, stored little-endian.
    (b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f", "hermes_bytecode", 0.9),
    # Source: ELF e_ident; WebAssembly "\0asm"; DEX "dex\n"; PDF "%PDF-".
    (b"\x7fELF", "elf", 0.97), (b"\x00asm", "wasm", 0.9), (b"dex\n", "dex", 0.9), (b"%PDF-", "pdf", 0.97),
    # UNVERIFIED (from memory): Unreal package tag 0x9E2A83C1 (little-endian); Live2D Cubism 3 "MOC3";
    # FMOD sample bank "FSB5"; Wwise soundbank "BKHD" and file package "AKPK".
    (b"\xc1\x83\x2a\x9e", "uasset", 0.8), (b"MOC3", "moc3", 0.85), (b"FSB5", "fsb", 0.9),
    (b"BKHD", "wwise_bank", 0.75), (b"AKPK", "wwise_pck", 0.75),
]

_BY_FIRST: Dict[int, List[Tuple[bytes, str, float]]] = {}
for _sig, _t, _c in _FIXED:
    _BY_FIRST.setdefault(_sig[0], []).append((_sig, _t, _c))
for _lst in _BY_FIRST.values():          # longest signature first so specific ones win
    _lst.sort(key=lambda x: -len(x[0]))

# Mach-O. Source: Apple mach-o/loader.h (MH_MAGIC 0xfeedface, MH_MAGIC_64 0xfeedfacf and their CIGAM
# byte-swapped forms) and mach-o/fat.h (FAT_MAGIC 0xcafebabe, FAT_MAGIC_64 0xcafebabf), verified against
# the macOS SDK headers. Little-endian files therefore start with CE FA ED FE / CF FA ED FE.
_MACHO_THIN = {
    b"\xfe\xed\xfa\xce": (">", 32), b"\xfe\xed\xfa\xcf": (">", 64),
    b"\xce\xfa\xed\xfe": ("<", 32), b"\xcf\xfa\xed\xfe": ("<", 64),
}
_FAT = {b"\xca\xfe\xba\xbe": 32, b"\xca\xfe\xba\xbf": 64}
# cputype values: CPU_TYPE_X86=7, ARM=12, POWERPC=18, plus CPU_ARCH_ABI64 (0x01000000) / ABI64_32 (0x02000000).
_CPU_BASE = {7, 12, 18}
_CPU_ABI = {0, 0x01000000, 0x02000000}


def _plausible_cpu(v: int) -> bool:
    return (v & 0x00FFFFFF) in _CPU_BASE and (v & 0xFF000000) in _CPU_ABI


def macho_header_info(head: bytes) -> Optional[Dict[str, object]]:
    """Describe a Mach-O / fat header: ``{"fat": bool, "bits": 32|64, "endian": "<"|">", "nfat": int}``.

    Returns ``None`` when ``head`` is not a Mach-O or fat file (Java class files share ``CAFEBABE`` and
    are rejected through the fat arch count, which must be 1..30).
    """
    if len(head) < 8:
        return None
    m = bytes(head[:4])
    if m in _MACHO_THIN:
        endian, bits = _MACHO_THIN[m]
        return {"fat": False, "bits": bits, "endian": endian, "nfat": 0}
    if m in _FAT:
        nfat = struct.unpack(">I", head[4:8])[0]
        if 1 <= nfat <= 30:
            return {"fat": True, "bits": _FAT[m], "endian": ">", "nfat": nfat}
    return None


def _macho(head: bytes) -> Optional[Result]:
    info = macho_header_info(head)
    if info is None:
        return None
    if info["fat"]:
        if len(head) >= 12 and _plausible_cpu(struct.unpack(">I", head[8:12])[0]):
            return "macho", 0.98
        return "macho", 0.75
    if len(head) >= 16:
        ftype = struct.unpack(str(info["endian"]) + "I", head[12:16])[0]
        if 1 <= ftype <= 12:   # MH_OBJECT .. MH_FILESET range in loader.h
            return "macho", 0.98
        return "macho", 0.7
    return "macho", 0.8


def _java_class(head: bytes) -> Optional[Result]:
    if head[:4] == b"\xca\xfe\xba\xbe" and len(head) >= 8:
        nfat = struct.unpack(">I", head[4:8])[0]
        if nfat > 30:
            return "java_class", 0.8
    return None


def _riff(head: bytes) -> Optional[Result]:
    # Source: Microsoft RIFF container: "RIFF" <size> <form type>.
    if head[:4] != b"RIFF" or len(head) < 12:
        return None
    form = bytes(head[8:12])
    table = {b"WEBP": ("webp", 0.99), b"WAVE": ("wav", 0.97), b"AVI ": ("avi", 0.95),
             b"FEV ": ("fmod_bank", 0.8)}  # UNVERIFIED: FMOD bank form type "FEV " from memory
    return table.get(form, ("riff", 0.5))


def _form(head: bytes) -> Optional[Result]:
    # Source: IFF/AIFF: "FORM" <size> "AIFF" | "AIFC".
    if head[:4] == b"FORM" and len(head) >= 12 and bytes(head[8:12]) in (b"AIFF", b"AIFC"):
        return "aiff", 0.95
    return None


_HEIC_BRANDS = {b"heic", b"heix", b"hevc", b"hevx", b"heim", b"heis", b"hevm", b"hevs", b"mif1", b"msf1"}


def _ftyp(head: bytes) -> Optional[Result]:
    # Source: ISO/IEC 14496-12 (ISOBMFF) "ftyp" box at offset 4 with a major brand at offset 8;
    # brand registry from MP4RA (qt  = QuickTime, M4A = iTunes audio, heic/mif1 = HEIF, avif = AVIF).
    if len(head) < 12 or head[4:8] != b"ftyp":
        return None
    brand = bytes(head[8:12])
    if brand == b"qt  ":
        return "mov", 0.97
    if brand in (b"M4A ", b"M4B ", b"M4P "):
        return "m4a", 0.95
    if brand in _HEIC_BRANDS:
        return "heic", 0.95
    if brand in (b"avif", b"avis"):
        return "avif", 0.95
    if brand[:2] == b"3g":
        return "3gp", 0.9
    return "mp4", 0.95


def _bzip2(head: bytes) -> Optional[Result]:
    # Source: bzip2 format: "BZh" + block size digit '1'..'9' (+ block magic 0x314159265359 "1AY&SY").
    if head[:3] == b"BZh" and len(head) >= 4 and 0x31 <= head[3] <= 0x39:
        return "bzip2", 0.9 if head[4:10] == b"1AY&SY" else 0.7
    return None


def _bmp(head: bytes) -> Optional[Result]:
    # Source: BMP file header: "BM", reserved fields (6..10) are zero, DIB header size at offset 14.
    if head[:2] != b"BM":
        return None
    if len(head) >= 18 and head[6:10] == b"\x00\x00\x00\x00" and \
            struct.unpack("<I", head[14:18])[0] in (12, 40, 52, 56, 64, 108, 124):
        return "bmp", 0.9
    return "bmp", 0.3


def _ico(head: bytes) -> Optional[Result]:
    # Source: ICO/CUR directory header: reserved 0, type 1 (icon) or 2 (cursor), image count.
    if len(head) >= 6 and head[:2] == b"\x00\x00" and head[2:4] in (b"\x01\x00", b"\x02\x00"):
        count = struct.unpack("<H", head[4:6])[0]
        if 1 <= count <= 64:
            return ("ico" if head[2] == 1 else "cur"), 0.5
    return None


def _ttf(head: bytes) -> Optional[Result]:
    # Source: OpenType/TrueType sfnt header: version 0x00010000 followed by numTables.
    if head[:4] == b"\x00\x01\x00\x00" and len(head) >= 6:
        num = struct.unpack(">H", head[4:6])[0]
        return ("ttf", 0.85) if 4 <= num <= 64 else ("ttf", 0.3)
    return None


def _mpeg_audio(head: bytes) -> Optional[Result]:
    # Source: MPEG audio frame header: 11 sync bits, version != reserved, layer != reserved.
    if len(head) >= 4 and head[0] == 0xFF and (head[1] & 0xE0) == 0xE0:
        layer = (head[1] >> 1) & 3
        version = (head[1] >> 3) & 3
        bitrate = head[2] >> 4
        rate = (head[2] >> 2) & 3
        if layer == 0 and head[1] in (0xF1, 0xF9):   # ADTS (AAC): layer bits are 00, protection absent
            return "aac_adts", 0.5
        if layer != 0 and version != 1 and bitrate not in (0, 15) and rate != 3:
            return "mp3", 0.5
    return None


def _pe(head: bytes) -> Optional[Result]:
    # Source: Microsoft PE format: "MZ" DOS header, e_lfanew at 0x3C points to "PE\0\0".
    if head[:2] != b"MZ":
        return None
    if len(head) >= 64:
        off = struct.unpack("<I", head[0x3C:0x40])[0]
        if 0 < off <= len(head) - 4:
            return ("pe", 0.95) if head[off:off + 4] == b"PE\x00\x00" else ("pe", 0.35)
        if 0 < off < 0x10000:
            return "pe", 0.6
    return "pe", 0.5


def _plist_xml(head: bytes) -> Optional[Result]:
    # Source: Apple property list XML form: <?xml ...?> + <!DOCTYPE plist ...> + <plist version="1.0">.
    h = head
    if h.startswith(b"\xef\xbb\xbf"):
        h = h[3:]
    lead = h.lstrip()
    if lead.startswith(b"<?xml") or lead.startswith(b"<plist"):
        if b"<plist" in h:
            return "plist_xml", 0.95
        if lead.startswith(b"<?xml"):
            return "xml", 0.65
    if lead[:14].lower() == b"<!doctype html" or lead[:5].lower() == b"<html":
        return "html", 0.85
    return None


def _shebang(head: bytes) -> Optional[Result]:
    return ("shebang", 0.8) if head.startswith(b"#!") and b"\n" in head[:128] and is_texty(head[:128]) else None


def is_texty(data: bytes) -> bool:
    """Heuristic: mostly printable ASCII / valid UTF-8 with no NUL bytes."""
    if not data:
        return False
    if b"\x00" in data:
        # UTF-16 text: BOM FF FE / FE FF
        return data[:2] in (b"\xff\xfe", b"\xfe\xff") and len(data) >= 4
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        if exc.start < len(data) - 4:      # a truncated multi-byte sequence at the very end is fine
            return False
        text = data[:exc.start].decode("utf-8", "replace")
    if not text:
        return False
    bad = sum(1 for ch in text if (ord(ch) < 0x20 and ch not in "\t\n\r\f\b") or ch == "\x7f")
    return bad == 0


_JSON_START = re.compile(rb"^\s*[\[{]\s*[\"\]}\[{\d\-tfn]")


def _text(head: bytes) -> Optional[Result]:
    if not is_texty(head):
        return None
    if head[:3] == b"\xef\xbb\xbf":
        body = head[3:]
    else:
        body = head
    if _JSON_START.match(body):
        return "json", 0.6
    return "text", 0.5


_SPECIAL_BY_FIRST: Dict[int, List[Callable[[bytes], Optional[Result]]]] = {
    0xCA: [_macho, _java_class], 0xFE: [_macho], 0xCE: [_macho], 0xCF: [_macho],
    ord("R"): [_riff], ord("F"): [_form], ord("B"): [_bzip2, _bmp], 0x00: [_ico, _ttf], 0xFF: [_mpeg_audio],
    ord("M"): [_pe],
}
_GENERIC: List[Callable[[bytes], Optional[Result]]] = [_ftyp, _plist_xml, _shebang, _text]

MAGIC_IDS = frozenset(
    {t for _s, t, _c in _FIXED}
    | {"macho", "java_class", "webp", "wav", "avi", "fmod_bank", "riff", "aiff", "mov", "m4a", "heic", "avif",
       "3gp", "mp4", "bmp", "ico", "cur", "ttf", "mp3", "aac_adts", "pe", "plist_xml", "xml", "html", "shebang",
       "json", "text", "empty", "unknown", "ue_pak", "bzip2"}
)


def sniff(head: bytes) -> Result:
    """Identify a file from its leading bytes. See the module docstring for the contract."""
    if not head:
        return "empty", 1.0
    head = bytes(head[:TEXT_SNIFF_BYTES])
    b0 = head[0]
    for sig, t, c in _BY_FIRST.get(b0, ()):
        if head.startswith(sig):
            return t, c
    for fn in _SPECIAL_BY_FIRST.get(b0, ()):
        r = fn(head)
        if r is not None:
            return r
    for fn in _GENERIC:
        r = fn(head)
        if r is not None:
            return r
    return "unknown", 0.0


# Source: Unreal Engine FPakInfo::PakFile_Magic == 0x5A6F12E1, stored little-endian in the footer.
# UNVERIFIED: footer size/layout varies with the pak version (44..221 bytes); only the magic is searched.
_UE_PAK_MAGIC = struct.pack("<I", 0x5A6F12E1)


def sniff_tail(tail: bytes) -> Result:
    """Identify formats that carry their signature at the end of the file (currently UE ``.pak``).

    ``tail`` should be the last ~256 bytes. Needs a seek, so callers decide when it is affordable.
    """
    if _UE_PAK_MAGIC in tail[-256:]:
        return "ue_pak", 0.6
    return "unknown", 0.0
