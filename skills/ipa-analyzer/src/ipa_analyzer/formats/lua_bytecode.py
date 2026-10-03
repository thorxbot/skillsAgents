"""Lua / LuaJIT precompiled-chunk header parser with tamper signals.

Reads only the header (plus, where cheap and unambiguous, the main function's source name to
tell whether debug info was stripped).  It identifies the flavour (PUC-Rio Lua vs LuaJIT), the
version, endianness, build word sizes and anything in the header that deviates from the
official format.  It cannot see opcode re-mapping -- a custom VM with a re-ordered instruction
set still has a perfectly standard header -- so a clean header never proves "stock Lua".
Nothing is decoded, decrypted or run.

Header layouts, each checked against the official sources fetched during WP3b:

* Lua 5.1  (lundump.h 1.37.1.1, lundump.c ``luaU_header``) -- 12 bytes::
      1B 4C 75 61 | version 0x51 | format 0 | endian (1 = little) | sizeof(int) |
      sizeof(size_t) | sizeof(Instruction) | sizeof(lua_Number) | integral-number flag
* Lua 5.2  (lundump.h 1.39.1.1, lundump.c) -- the same 12 bytes (version 0x52) followed by
  ``LUAC_TAIL`` = 19 93 0D 0A 1A 0A  (18 bytes).
* Lua 5.3  (lundump.h 1.45.1.1, lundump.c ``checkHeader`` / ldump.c ``DumpHeader``)::
      signature | 0x53 | format 0 | LUAC_DATA(6) | sizeof(int) | sizeof(size_t) |
      sizeof(Instruction) | sizeof(lua_Integer) | sizeof(lua_Number) |
      LUAC_INT (lua_Integer 0x5678, native order) | LUAC_NUM (lua_Number 370.5, native order)
* Lua 5.4  (lundump.h 5.4.9, lundump.c ``checkHeader``) -- no sizeof(int)/size_t any more::
      signature | 0x54 | format 0 | LUAC_DATA(6) | sizeof(Instruction) | sizeof(lua_Integer) |
      sizeof(lua_Number) | LUAC_INT 0x5678 | LUAC_NUM 370.5
* Lua 5.5  (lundump.h 5.5.1, ldump.c ``dumpHeader`` / ``dumpNumInfo``) -- every numeric check
  value is preceded by its own size byte::
      signature | 0x55 | format 0 | LUAC_DATA(6) | 04 int(-0x5678) | 04 Instruction(0x12345678) |
      08 lua_Integer(-0x5678) | 08 lua_Number(-370.5)
  Version byte = (major << 4) | minor, ``LUAC_FORMAT`` is 0 for the official format in all of them.
* LuaJIT (lj_bcdump.h, v2.0 branch: ``BCDUMP_VERSION 1``; v2.1 branch: ``BCDUMP_VERSION 2``;
  lj_bcwrite.c ``bcwrite_header``, lj_bcread.c ``bcread_header``)::
      1B 4C 4A | dump version | flags (ULEB128) | [chunkname length (ULEB128) + bytes, absent when STRIP]
  flags: 0x01 BE, 0x02 STRIP, 0x04 FFI, 0x08 FR2 (GC64 frame layout), 0x10 BITOP; 2.0 knows
  only the first three.  The header comment in lj_bcdump.h requires private format changes to
  use a dump version >= 0x80, which is reported as a tamper signal.

Every layout above was also confirmed against real dumps produced by ``lupa`` (Lua 5.1-5.5) and
LuaJIT 2.0 / 2.1 builds on a little-endian 64-bit host during development.
UNVERIFIED: dump versions of LuaJIT 2.1 betas older than the current v2.1 branch (assumed 2);
big-endian and 32-bit layouts are derived from the sources, not from real dumps.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

__all__ = [
    "LUA_SIGNATURE",
    "LUAJIT_SIGNATURE",
    "LUAC_DATA",
    "LUAC_FORMAT",
    "LUAC_INT",
    "LUAC_NUM",
    "LUA_VERSION_BYTES",
    "LUAJIT_DUMP_VERSIONS",
    "LuaBytecodeInfo",
    "XorHypothesis",
    "parse_header",
    "looks_like_lua_after_xor",
    "summarize",
]

#: lua.h ``LUA_SIGNATURE`` ("\033Lua"), every PUC-Rio version.
LUA_SIGNATURE = b"\x1bLua"
#: lj_bcdump.h ``BCDUMP_HEAD1..3`` (ESC 'L' 'J').
LUAJIT_SIGNATURE = b"\x1bLJ"
#: lundump.h ``LUAC_DATA`` (5.3+) / ``LUAC_TAIL`` (5.2): "\x19\x93\r\n\x1a\n".
LUAC_DATA = b"\x19\x93\r\n\x1a\n"
#: lundump.h ``LUAC_FORMAT`` -- the official format.
LUAC_FORMAT = 0
#: lundump.h ``LUAC_INT`` for 5.3 / 5.4 (5.5 uses -0x5678, see below).
LUAC_INT = 0x5678
#: lundump.h ``LUAC_NUM`` for 5.3 / 5.4 (5.5 uses -370.5).
LUAC_NUM = 370.5
LUAC_INT_55 = -0x5678
LUAC_INST_55 = 0x12345678
LUAC_NUM_55 = -370.5

#: ``LUAC_VERSION`` = major * 16 + minor.
LUA_VERSION_BYTES: Dict[int, str] = {0x51: "5.1", 0x52: "5.2", 0x53: "5.3", 0x54: "5.4", 0x55: "5.5"}

#: lj_bcdump.h ``BCDUMP_VERSION``: 1 on the v2.0 branch, 2 on the v2.1 branch.
# UNVERIFIED: dump version 2 for 2.1 betas older than the current v2.1 branch (only HEAD was read).
LUAJIT_DUMP_VERSIONS: Dict[int, str] = {1: "2.0", 2: "2.1"}

LJ_F_BE = 0x01
LJ_F_STRIP = 0x02
LJ_F_FFI = 0x04
LJ_F_FR2 = 0x08
LJ_F_BITOP = 0x10
_LJ_FLAG_NAMES = ((LJ_F_BE, "BE"), (LJ_F_STRIP, "STRIP"), (LJ_F_FFI, "FFI"), (LJ_F_FR2, "FR2"), (LJ_F_BITOP, "BITOP"))
_LJ_KNOWN_FLAGS = {1: LJ_F_BE | LJ_F_STRIP | LJ_F_FFI, 2: LJ_F_BE | LJ_F_STRIP | LJ_F_FFI | LJ_F_FR2 | LJ_F_BITOP}
_LJ_PRIVATE_VERSION_MIN = 0x80

# UNVERIFIED: the "usual" sizeof sets below are a plausibility heuristic, not part of any spec.
_ALLOWED_SIZES = {
    "int": (4, 8),
    "size_t": (4, 8),
    "instruction": (4,),
    "lua_integer": (4, 8),
    "lua_number": (4, 8),
}
_MAX_NAME = 256


@dataclass
class LuaBytecodeInfo:
    """Result of parsing one chunk header.

    ``signature_ok``: the magic bytes are Lua / LuaJIT.  ``valid``: additionally the whole header
    matches the official layout for its version (no tamper signals, not truncated).
    """

    valid: bool = False
    signature_ok: bool = False
    flavor: str = "unknown"  # puc | luajit | unknown
    version: Optional[str] = None  # "5.1".."5.5" or LuaJIT series "2.0" / "2.1"
    version_byte: Optional[int] = None
    format: Optional[int] = None
    endian: Optional[str] = None  # little | big
    size_int: Optional[int] = None
    size_t: Optional[int] = None
    size_instruction: Optional[int] = None
    size_lua_integer: Optional[int] = None
    size_lua_number: Optional[int] = None
    integral_flag: Optional[bool] = None
    bits: Optional[int] = None  # 32 / 64 from sizeof(size_t) (5.1-5.3) or the LuaJIT FR2/GC64 flag
    luajit_dump_version: Optional[int] = None
    luajit_flags: Optional[int] = None
    luajit_flag_names: List[str] = field(default_factory=list)
    stripped: Optional[bool] = None
    chunkname: Optional[str] = None
    header_size: int = 0
    tamper_signals: List[str] = field(default_factory=list)

    @property
    def version_key(self) -> Optional[str]:
        """Aggregation key: ``"5.3"`` or ``"luajit_2.1"``."""
        if self.version is None:
            return None
        return f"luajit_{self.version}" if self.flavor == "luajit" else self.version

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "signature_ok": self.signature_ok,
            "flavor": self.flavor,
            "version": self.version,
            "version_key": self.version_key,
            "version_byte": self.version_byte,
            "format": self.format,
            "endian": self.endian,
            "size_int": self.size_int,
            "size_t": self.size_t,
            "size_instruction": self.size_instruction,
            "size_lua_integer": self.size_lua_integer,
            "size_lua_number": self.size_lua_number,
            "integral_flag": self.integral_flag,
            "bits": self.bits,
            "luajit_dump_version": self.luajit_dump_version,
            "luajit_flags": self.luajit_flags,
            "luajit_flag_names": list(self.luajit_flag_names),
            "stripped": self.stripped,
            "chunkname": self.chunkname,
            "header_size": self.header_size,
            "tamper_signals": list(self.tamper_signals),
        }


# ------------------------------------------------------------------------- helpers


def _finish(info: LuaBytecodeInfo) -> LuaBytecodeInfo:
    info.valid = info.signature_ok and not info.tamper_signals
    return info


def _check_size(info: LuaBytecodeInfo, name: str, value: int) -> None:
    if value not in _ALLOWED_SIZES[name]:
        info.tamper_signals.append(f"sizeof_{name}_unusual:{value}")


def _decode_name(raw: bytes) -> str:
    return raw[:_MAX_NAME].decode("utf-8", "replace")


def _uleb128(data: bytes, pos: int):
    """Return (value, next_pos) or None when truncated / longer than 5 bytes."""
    value = 0
    shift = 0
    for i in range(5):
        if pos + i >= len(data):
            return None
        b = data[pos + i]
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, pos + i + 1
        shift += 7
    return None


def _read_int(raw: bytes, endian: str) -> int:
    return int.from_bytes(raw, endian, signed=True)


def _match_int(raw: bytes, expected: int):
    """Return the endianness for which ``raw`` equals ``expected`` (little preferred), else None."""
    for e in ("little", "big"):
        if _read_int(raw, e) == expected:
            return e
    return None


def _match_num(raw: bytes, expected: float):
    fmt = {4: "f", 8: "d"}.get(len(raw))
    if fmt is None:
        return None
    for e, prefix in (("little", "<"), ("big", ">")):
        if struct.unpack(prefix + fmt, raw)[0] == expected:
            return e
    return None


def _set_endian(info: LuaBytecodeInfo, e: Optional[str]) -> None:
    if e is not None and info.endian is None:
        info.endian = e


# ------------------------------------------------------------------- PUC-Rio parsers


def _parse_51_52(data: bytes, info: LuaBytecodeInfo) -> None:
    is52 = info.version == "5.2"
    want = 18 if is52 else 12
    info.header_size = want
    if len(data) < want:
        info.tamper_signals.append("truncated_header")
        return
    info.format = data[5]
    if info.format != LUAC_FORMAT:
        info.tamper_signals.append(f"format_nonzero:{info.format}")
    e = data[6]
    if e in (0, 1):
        info.endian = "little" if e == 1 else "big"
    else:
        info.tamper_signals.append(f"endian_byte_invalid:{e}")
    info.size_int, info.size_t, info.size_instruction, info.size_lua_number = data[7], data[8], data[9], data[10]
    _check_size(info, "int", data[7])
    _check_size(info, "size_t", data[8])
    _check_size(info, "instruction", data[9])
    _check_size(info, "lua_number", data[10])
    if data[11] in (0, 1):
        info.integral_flag = bool(data[11])
    else:
        info.tamper_signals.append(f"integral_flag_invalid:{data[11]}")
    if info.size_t in (4, 8):
        info.bits = info.size_t * 8
    if is52 and data[12:18] != LUAC_DATA:
        info.tamper_signals.append("luac_data_mismatch")
    if not is52 and info.endian and info.size_t in (4, 8) and len(data) >= 12 + info.size_t:
        # 5.1: the main function starts with its source name; size 0 means debug info was stripped.
        n = int.from_bytes(data[12 : 12 + info.size_t], info.endian)
        info.stripped = n == 0
        if 0 < n <= _MAX_NAME + 1 and len(data) >= 12 + info.size_t + n:
            info.chunkname = _decode_name(data[12 + info.size_t : 12 + info.size_t + n - 1])


def _parse_53(data: bytes, info: LuaBytecodeInfo) -> None:
    fixed = 17  # sig 4 + ver + fmt + data 6 + five sizeof bytes
    info.header_size = fixed
    if len(data) < fixed:
        info.tamper_signals.append("truncated_header")
        return
    info.format = data[5]
    if info.format != LUAC_FORMAT:
        info.tamper_signals.append(f"format_nonzero:{info.format}")
    if data[6:12] != LUAC_DATA:
        info.tamper_signals.append("luac_data_mismatch")
    info.size_int, info.size_t, info.size_instruction, info.size_lua_integer, info.size_lua_number = data[12:17]
    _check_size(info, "int", info.size_int)
    _check_size(info, "size_t", info.size_t)
    _check_size(info, "instruction", info.size_instruction)
    _check_size(info, "lua_integer", info.size_lua_integer)
    _check_size(info, "lua_number", info.size_lua_number)
    if info.size_t in (4, 8):
        info.bits = info.size_t * 8
    si, sn = info.size_lua_integer, info.size_lua_number
    info.header_size = fixed + si + sn
    if si not in (4, 8) or sn not in (4, 8):
        return
    if len(data) < info.header_size:
        info.tamper_signals.append("truncated_header")
        return
    int_raw = data[fixed : fixed + si]
    num_raw = data[fixed + si : fixed + si + sn]
    e = _match_int(int_raw, LUAC_INT)
    if e is None:
        info.tamper_signals.append("luac_int_mismatch")
    else:
        info.endian = e
    n = _match_num(num_raw, LUAC_NUM)
    if n is None:
        info.tamper_signals.append("luac_num_mismatch")
    else:
        _set_endian(info, n)
        if e is not None and n != e:
            info.tamper_signals.append("luac_num_endian_differs_from_luac_int")
    _guess_stripped_53(data, info)


def _guess_stripped_53(data: bytes, info: LuaBytecodeInfo) -> None:
    # After the header: byte sizeupvalues, then the main function's source string (size byte, 0 = NULL).
    pos = info.header_size + 1
    if info.endian is None or len(data) <= pos:
        return
    size = data[pos]
    if size == 0:
        info.stripped = True
        return
    info.stripped = False
    if size == 0xFF:
        return
    n = size - 1
    if len(data) >= pos + 1 + n:
        info.chunkname = _decode_name(data[pos + 1 : pos + 1 + n])


def _parse_54(data: bytes, info: LuaBytecodeInfo) -> None:
    fixed = 15  # sig 4 + ver + fmt + data 6 + three sizeof bytes
    info.header_size = fixed
    if len(data) < fixed:
        info.tamper_signals.append("truncated_header")
        return
    info.format = data[5]
    if info.format != LUAC_FORMAT:
        info.tamper_signals.append(f"format_nonzero:{info.format}")
    if data[6:12] != LUAC_DATA:
        info.tamper_signals.append("luac_data_mismatch")
    info.size_instruction, info.size_lua_integer, info.size_lua_number = data[12:15]
    _check_size(info, "instruction", info.size_instruction)
    _check_size(info, "lua_integer", info.size_lua_integer)
    _check_size(info, "lua_number", info.size_lua_number)
    si, sn = info.size_lua_integer, info.size_lua_number
    info.header_size = fixed + si + sn
    if si not in (4, 8) or sn not in (4, 8):
        return
    if len(data) < info.header_size:
        info.tamper_signals.append("truncated_header")
        return
    e = _match_int(data[fixed : fixed + si], LUAC_INT)
    if e is None:
        info.tamper_signals.append("luac_int_mismatch")
    else:
        info.endian = e
    n = _match_num(data[fixed + si : fixed + si + sn], LUAC_NUM)
    if n is None:
        info.tamper_signals.append("luac_num_mismatch")
    else:
        _set_endian(info, n)
        if e is not None and n != e:
            info.tamper_signals.append("luac_num_endian_differs_from_luac_int")
    # Main function: byte sizeupvalues, then source as a size+1 varint (high bit marks the last
    # byte; the single byte 0x80 is the NULL string, i.e. stripped), then the name bytes.
    pos = info.header_size + 1
    if len(data) > pos:
        first = data[pos]
        if first == 0x80:
            info.stripped = True
        else:
            info.stripped = False
            if first & 0x80 and 0x81 <= first <= 0xFF:
                n_name = (first & 0x7F) - 1
                if len(data) >= pos + 1 + n_name:
                    info.chunkname = _decode_name(data[pos + 1 : pos + 1 + n_name])


def _parse_55(data: bytes, info: LuaBytecodeInfo) -> None:
    pos = 12
    info.header_size = pos
    checks = (
        ("int", LUAC_INT_55, "size_int"),
        ("instruction", LUAC_INST_55, "size_instruction"),
        ("lua_integer", LUAC_INT_55, "size_lua_integer"),
    )
    if len(data) < pos:
        info.tamper_signals.append("truncated_header")
        return
    info.format = data[5]
    if info.format != LUAC_FORMAT:
        info.tamper_signals.append(f"format_nonzero:{info.format}")
    if data[6:12] != LUAC_DATA:
        info.tamper_signals.append("luac_data_mismatch")
    endians = []
    for name, expected, attr in checks:
        if len(data) < pos + 1:
            info.tamper_signals.append("truncated_header")
            return
        size = data[pos]
        setattr(info, attr, size)
        _check_size(info, name, size)
        pos += 1
        if size not in _ALLOWED_SIZES[name] or len(data) < pos + size:
            if size in _ALLOWED_SIZES[name]:
                info.tamper_signals.append("truncated_header")
            return
        raw = data[pos : pos + size]
        pos += size
        if name == "instruction":
            e = None
            for en in ("little", "big"):
                if int.from_bytes(raw, en) == expected:
                    e = en
                    break
        else:
            e = _match_int(raw, expected)
        if e is None:
            info.tamper_signals.append(f"luac_{name}_mismatch")
        else:
            endians.append(e)
    if len(data) < pos + 1:
        info.tamper_signals.append("truncated_header")
        info.header_size = pos
        return
    size = data[pos]
    info.size_lua_number = size
    _check_size(info, "lua_number", size)
    pos += 1
    if size in (4, 8):
        if len(data) < pos + size:
            info.tamper_signals.append("truncated_header")
        else:
            n = _match_num(data[pos : pos + size], LUAC_NUM_55)
            if n is None:
                info.tamper_signals.append("luac_num_mismatch")
            else:
                endians.append(n)
            pos += size
    info.header_size = pos
    if endians:
        info.endian = endians[0]
        if len(set(endians)) > 1:
            info.tamper_signals.append("mixed_endianness_in_header")


def _parse_puc(data: bytes, info: LuaBytecodeInfo) -> None:
    if len(data) < 5:
        info.tamper_signals.append("truncated_header")
        return
    info.version_byte = data[4]
    version = LUA_VERSION_BYTES.get(data[4])
    if version is None:
        info.tamper_signals.append(f"version_byte_unknown:0x{data[4]:02x}")
        return
    info.version = version
    if version in ("5.1", "5.2"):
        _parse_51_52(data, info)
    elif version == "5.3":
        _parse_53(data, info)
    elif version == "5.4":
        _parse_54(data, info)
    else:
        _parse_55(data, info)


# ----------------------------------------------------------------------- LuaJIT


def _parse_luajit(data: bytes, info: LuaBytecodeInfo) -> None:
    if len(data) < 4:
        info.tamper_signals.append("truncated_header")
        return
    dump_version = data[3]
    info.luajit_dump_version = dump_version
    info.version_byte = dump_version
    series = LUAJIT_DUMP_VERSIONS.get(dump_version)
    if series is not None:
        info.version = series
    elif dump_version >= _LJ_PRIVATE_VERSION_MIN:
        info.tamper_signals.append(f"luajit_private_dump_version:0x{dump_version:02x}")
    else:
        info.tamper_signals.append(f"luajit_dump_version_unknown:{dump_version}")
    got = _uleb128(data, 4)
    if got is None:
        info.tamper_signals.append("truncated_header" if len(data) < 9 else "luajit_flags_malformed")
        info.header_size = len(data)
        return
    flags, pos = got
    info.luajit_flags = flags
    info.luajit_flag_names = [name for bit, name in _LJ_FLAG_NAMES if flags & bit]
    known = _LJ_KNOWN_FLAGS.get(dump_version, _LJ_KNOWN_FLAGS[2])
    if flags & ~known:
        info.tamper_signals.append(f"luajit_unknown_flag_bits:0x{flags & ~known:x}")
    info.endian = "big" if flags & LJ_F_BE else "little"
    info.stripped = bool(flags & LJ_F_STRIP)
    if flags & LJ_F_FR2:
        info.bits = 64
    info.header_size = pos
    if not flags & LJ_F_STRIP:
        got = _uleb128(data, pos)
        if got is None:
            info.tamper_signals.append("truncated_header")
            return
        n, pos = got
        if n > 65536:
            info.tamper_signals.append(f"luajit_chunkname_length_implausible:{n}")
            return
        if len(data) < pos + n:
            info.tamper_signals.append("truncated_header")
            return
        info.chunkname = _decode_name(data[pos : pos + n])
        info.header_size = pos + n


# ------------------------------------------------------------------------- API


def parse_header(data: bytes) -> LuaBytecodeInfo:
    """Parse the header of a Lua / LuaJIT chunk.  Never raises; non-Lua input gives ``valid=False``."""
    data = bytes(data[:512])
    info = LuaBytecodeInfo()
    if data.startswith(LUA_SIGNATURE):
        info.signature_ok = True
        info.flavor = "puc"
        _parse_puc(data, info)
    elif data.startswith(LUAJIT_SIGNATURE):
        info.signature_ok = True
        info.flavor = "luajit"
        _parse_luajit(data, info)
    return _finish(info)


@dataclass
class XorHypothesis:
    """A short repeating XOR key that turns the start of ``data`` into a valid Lua header."""

    flavor: str
    key: bytes
    confidence: float
    info: LuaBytecodeInfo

    def to_dict(self) -> dict:
        return {
            "flavor": self.flavor,
            "key_hex": self.key.hex(),
            "confidence": self.confidence,
            "version": self.info.version_key,
        }


_XOR_CONF = {1: 0.9, 2: 0.8, 3: 0.7, 4: 0.6}


def looks_like_lua_after_xor(data: bytes) -> Optional[XorHypothesis]:
    """Look for a 1..4 byte repeating XOR key that makes the header a *valid* Lua header.

    Returns evidence only (never the decoded file).  Data that is already a Lua chunk, or whose
    decoded header would not pass the strict validity check, returns ``None``.
    """
    data = bytes(data[:128])
    if len(data) < 12 or data.startswith((LUA_SIGNATURE, LUAJIT_SIGNATURE)):
        return None
    for flavor, sig in (("puc", LUA_SIGNATURE), ("luajit", LUAJIT_SIGNATURE)):
        base = bytes(a ^ b for a, b in zip(data, sig))
        if not any(base):
            continue
        for period in range(1, 5):
            if period > len(sig):
                continue
            if period < len(sig) and not all(base[i] == base[i % period] for i in range(len(sig))):
                continue
            key = bytes(base[i] for i in range(period))
            decoded = bytes(c ^ key[i % period] for i, c in enumerate(data))
            info = parse_header(decoded)
            if info.valid and info.flavor == flavor:
                conf = _XOR_CONF[period]
                if info.header_size > len(data):
                    conf -= 0.1
                return XorHypothesis(flavor, key, conf, info)
    return None


def summarize(infos: Iterable[LuaBytecodeInfo]) -> dict:
    """Aggregate headers into ``{by_version, invalid, bits, stripped, tampered, total}``.

    ``by_version`` counts only fully valid headers (keys like ``"5.3"`` / ``"luajit_2.1"``);
    ``invalid`` counts everything else, ``tampered`` the subset whose signature was Lua-like.
    """
    by_version: Dict[str, int] = {}
    bits: Dict[str, int] = {}
    invalid = tampered = stripped = total = 0
    for info in infos:
        total += 1
        if not info.valid:
            invalid += 1
            if info.signature_ok:
                tampered += 1
            continue
        key = info.version_key or "unknown"
        by_version[key] = by_version.get(key, 0) + 1
        if info.bits:
            bits[str(info.bits)] = bits.get(str(info.bits), 0) + 1
        if info.stripped:
            stripped += 1
    return {
        "by_version": dict(sorted(by_version.items())),
        "invalid": invalid,
        "tampered": tampered,
        "bits": dict(sorted(bits.items())),
        "stripped": stripped,
        "total": total,
    }
