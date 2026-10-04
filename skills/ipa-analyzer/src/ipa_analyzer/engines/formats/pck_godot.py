"""Godot ``.pck`` header / directory and compiled / encrypted script markers.

Facts (Source: godotengine/godot ``core/io/file_access_pack.{h,cpp}`` on branches 3.5, 4.2, 4.3 and ``master``;
``core/io/file_access_encrypted.{h,cpp}``; ``modules/gdscript/gdscript_tokenizer_buffer.cpp``):

* ``PACK_HEADER_MAGIC = 0x43504447`` ("GDPC" on disk), then u32 pack format version, u32 engine major / minor / patch.
* format 1 (3.x): 16 reserved u32, u32 file count, entries ``u32 pathlen, path, u64 offset, u64 size, md5[16]``.
* format 2 (4.x): after the engine version u32 pack flags (``PACK_DIR_ENCRYPTED = 1<<0``, ``PACK_REL_FILEBASE =
  1<<1``), u64 file base, 16 reserved u32, u32 file count; entries gain a trailing u32 file flags
  (``PACK_FILE_ENCRYPTED = 1<<0``).  The directory is AES-encrypted when ``PACK_DIR_ENCRYPTED`` is set.
* formats 3 / 4 (``master``): flags (+ ``PACK_SPARSE_BUNDLE = 1<<2``), u64 file base, u64 directory offset; the
  directory (u32 count + entries, per-file flags may include ``PACK_FILE_REMOVAL = 1<<1`` / ``PACK_FILE_DELTA``)
  lives at that offset.
* encrypted file container magic ``ENCRYPTED_HEADER_MAGIC = 0x43454447`` ("GDEC"); compiled GDScript starts with
  "GDSC" + u32 tokenizer version + u32 decompressed size (0 = not compressed).

UNVERIFIED: that format 2 of Godot 4.0 / 4.1 shares the 4.3 layout, and that iOS exports ship a standalone
``<name>.pck`` in the app bundle.  Only the header and the (unencrypted) directory are read; nothing is decrypted.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

PCK_MAGIC = b"GDPC"
GDEC_MAGIC = b"GDEC"
GDSC_MAGIC = b"GDSC"
PACK_DIR_ENCRYPTED = 1 << 0
PACK_REL_FILEBASE = 1 << 1
PACK_SPARSE_BUNDLE = 1 << 2
PACK_FILE_ENCRYPTED = 1 << 0
PACK_FILE_REMOVAL = 1 << 1
SUPPORTED_FORMATS = (1, 2, 3, 4)


@dataclass
class PckInfo:
    valid: bool = False
    pack_format: Optional[int] = None
    engine_version: Optional[str] = None
    flags: Optional[int] = None
    dir_encrypted: Optional[bool] = None
    sparse_bundle: Optional[bool] = None
    file_count: Optional[int] = None
    truncated: bool = False
    warnings: List[str] = field(default_factory=list)
    # directory scan (only when the directory is readable)
    entries_read: int = 0
    file_encrypted_count: int = 0
    exts: Dict[str, int] = field(default_factory=dict)
    script_files: Dict[str, int] = field(default_factory=dict)   # gd / gdc / gde counts
    directory_status: str = "not_read"   # not_read | read | encrypted | truncated | malformed

    def to_dict(self) -> Dict[str, Any]:
        return {k: getattr(self, k) for k in (
            "valid", "pack_format", "engine_version", "flags", "dir_encrypted", "sparse_bundle", "file_count",
            "truncated", "warnings", "entries_read", "file_encrypted_count", "exts", "script_files",
            "directory_status")}


def parse_header(head: bytes) -> PckInfo:
    """Parse the fixed header from the first bytes of a ``.pck``."""
    info = PckInfo()
    head = bytes(head)
    if head[:4] != PCK_MAGIC:
        return info
    if len(head) < 20:
        info.truncated = True
        return info
    fmt, major, minor, patch = struct.unpack_from("<IIII", head, 4)
    info.pack_format = fmt
    info.engine_version = "%d.%d.%d" % (major, minor, patch)
    if fmt not in SUPPORTED_FORMATS:
        info.warnings.append("unknown pack format %d" % fmt)
        return info
    if fmt == 1:
        info.dir_encrypted = False
        info.flags = 0
        info.valid = True
        if len(head) >= 88:
            info.file_count = struct.unpack_from("<I", head, 84)[0]
        else:
            info.truncated = True
        return info
    if len(head) < 32:
        info.truncated = True
        return info
    info.flags = struct.unpack_from("<I", head, 20)[0]
    info.dir_encrypted = bool(info.flags & PACK_DIR_ENCRYPTED)
    info.sparse_bundle = bool(info.flags & PACK_SPARSE_BUNDLE)
    info.valid = True
    return info


def read_directory(info: PckInfo, read_at: Callable[[int, int], bytes], file_size: int, *, max_entries: int = 5000,
                   max_path: int = 4096) -> PckInfo:
    """Read up to ``max_entries`` directory entries when the directory is not encrypted.

    ``read_at(offset, n)`` returns bytes.  Fills ``entries_read``, ``file_encrypted_count`` (per-file flag, format
    >= 2), ``exts`` and ``script_files``.  Stops quietly on anything inconsistent.
    """
    if not info.valid or info.pack_format is None:
        return info
    fmt = info.pack_format
    if info.dir_encrypted:
        info.directory_status = "encrypted"
        return info
    head = read_at(0, 128)
    if fmt == 1:
        pos, count = 88, struct.unpack_from("<I", head, 84)[0] if len(head) >= 88 else 0
    elif fmt == 2:
        if len(head) < 100:
            info.directory_status = "truncated"
            return info
        pos, count = 100, struct.unpack_from("<I", head, 96)[0]
    else:
        if len(head) < 40:
            info.directory_status = "truncated"
            return info
        dir_off = struct.unpack_from("<Q", head, 32)[0]
        if dir_off <= 0 or dir_off + 4 > file_size:
            info.directory_status = "malformed"
            return info
        count = struct.unpack("<I", read_at(dir_off, 4).ljust(4, b"\0"))[0]
        pos = dir_off + 4
    info.file_count = count
    flags_size = 0 if fmt == 1 else 4
    for _ in range(min(count, max_entries)):
        raw = read_at(pos, 4)
        if len(raw) < 4:
            info.directory_status = "truncated"
            return info
        plen = struct.unpack("<I", raw)[0]
        if plen == 0 or plen > max_path:
            info.directory_status = "malformed"
            return info
        blob = read_at(pos + 4, plen + 8 + 8 + 16 + flags_size)
        if len(blob) < plen + 32 + flags_size:
            info.directory_status = "truncated"
            return info
        path = blob[:plen].split(b"\0", 1)[0].decode("utf-8", "replace")
        if flags_size:
            fflags = struct.unpack_from("<I", blob, plen + 32)[0]
            if fflags & PACK_FILE_ENCRYPTED:
                info.file_encrypted_count += 1
        ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
        info.exts[ext] = info.exts.get(ext, 0) + 1
        if ext in ("gd", "gdc", "gde"):
            info.script_files[ext] = info.script_files.get(ext, 0) + 1
        info.entries_read += 1
        pos += 4 + plen + 32 + flags_size
    info.directory_status = "read" if info.directory_status == "not_read" else info.directory_status
    return info


def classify_script_head(head: bytes) -> str:
    """``gdc`` (compiled GDScript, "GDSC"), ``gde`` (encrypted, "GDEC") or ``other``."""
    if head[:4] == GDSC_MAGIC:
        return "gdc"
    if head[:4] == GDEC_MAGIC:
        return "gde"
    return "other"
