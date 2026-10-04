"""Hermes bytecode (``.hbc`` / React Native ``main.jsbundle`` built for Hermes) header reader.

Layout (Source: facebook/hermes ``include/hermes/BCGen/HBC/BytecodeFileFormat.h``, ``BytecodeFileHeader``,
read from ``main``; all integers little-endian)::

    u64 magic = 0x1F1903C103BC1FC6          offset 0   -> bytes C6 1F BC 03 C1 03 19 1F
    u32 version                             offset 8   (``BYTECODE_VERSION`` was 96 on ``main``)
    u8  sourceHash[20]                      offset 12
    u32 fileLength                          offset 32  (until the end of the footer)
    u32 globalCodeIndex                     offset 36
    u32 functionCount                       offset 40
    u32 stringKindCount, identifierCount    offset 44, 48
    u32 stringCount                         offset 52

``DELTA_MAGIC`` (``~MAGIC``) marks the delta form, which is not executable.  The field order up to
``stringCount`` is the one of the header on ``main``; UNVERIFIED for much older bytecode versions, so the
counts are only reported, never used for decisions.  Bytecode is compiled code, not encryption.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Dict, Optional

MAGIC = 0x1F1903C103BC1FC6
MAGIC_BYTES = struct.pack("<Q", MAGIC)
DELTA_MAGIC_BYTES = struct.pack("<Q", (~MAGIC) & 0xFFFFFFFFFFFFFFFF)
HEADER_PREFIX_SIZE = 56


@dataclass
class HermesInfo:
    valid: bool = False
    delta_form: bool = False
    version: Optional[int] = None
    file_length: Optional[int] = None
    file_length_matches: Optional[bool] = None
    function_count: Optional[int] = None
    string_count: Optional[int] = None
    truncated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {"valid": self.valid, "delta_form": self.delta_form, "version": self.version,
                "file_length": self.file_length, "file_length_matches": self.file_length_matches,
                "function_count": self.function_count, "string_count": self.string_count,
                "truncated": self.truncated}


def parse_header(head: bytes, file_size: Optional[int] = None) -> HermesInfo:
    """Parse the Hermes header.  Never raises; non-Hermes input gives ``valid=False``."""
    info = HermesInfo()
    head = bytes(head)
    if head[:8] == DELTA_MAGIC_BYTES:
        info.delta_form = True
    elif head[:8] != MAGIC_BYTES:
        return info
    if len(head) < 12:
        info.truncated = True
        return info
    info.version = struct.unpack_from("<I", head, 8)[0]
    if len(head) >= 36:
        info.file_length = struct.unpack_from("<I", head, 32)[0]
        if file_size is not None:
            info.file_length_matches = info.file_length == file_size
    if len(head) >= HEADER_PREFIX_SIZE:
        info.function_count = struct.unpack_from("<I", head, 40)[0]
        info.string_count = struct.unpack_from("<I", head, 52)[0]
    else:
        info.truncated = True
    info.valid = not info.delta_form and info.version is not None and info.version > 0 and not info.truncated
    return info
