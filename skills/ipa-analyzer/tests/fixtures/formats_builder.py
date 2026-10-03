"""Programmatic samples for the ``ipa_analyzer.formats`` parsers (no real app data anywhere).

Stable entry points used across work packages::

    build_unityfs(blocks, *, compression="lz4"|"lzma"|"none", blocks_info_at_end=False, ...) -> bytes
    build_unityfs_ex(...)                      -> BuiltBundle (bytes + field offsets, for tamper tests)
    build_unityfs_variants(blocks, ...)        -> {"standard", "offset_prefix", "xor_single",
                                                   "xor_repeating", "high_entropy"} : bytes
    build_lua_bytecode(version, *, bits=64, endian="little", strip=False, tamper=None) -> bytes
    build_pe_cli(assembly_name, refs=(), types=0, clr="v4.0.30319") -> bytes
    lz4_compress_block(data) -> bytes          (small greedy encoder)
    lzma_compress_unity(data) -> bytes         (5-byte props header + raw LZMA1 stream)

The Lua samples have *header-accurate* chunks (verified against real ``string.dump`` / ``luajit -b``
output, see test_lua_bytecode.py) followed by a stub body: they are meant for header parsing and are
not loadable by a real VM.  Everything here is deterministic.
"""
from __future__ import annotations

import lzma
import random
import struct
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

# --------------------------------------------------------------------------- compression


def _lz4_len_ext(out: bytearray, n: int) -> None:
    while n >= 255:
        out.append(255)
        n -= 255
    out.append(n)


def lz4_compress_block(data: bytes) -> bytes:
    """A small greedy LZ4 block encoder honouring the end-of-block rules (spec lz4_Block_format.md)."""
    data = bytes(data)
    n = len(data)
    out = bytearray()
    anchor = 0
    ip = 0
    table: Dict[bytes, int] = {}
    mflimit = n - 12
    matchlimit = n - 5
    while ip < mflimit:
        key = data[ip : ip + 4]
        cand = table.get(key)
        table[key] = ip
        if cand is not None and ip - cand <= 65535:
            ml = 4
            while ip + ml < matchlimit and data[cand + ml] == data[ip + ml]:
                ml += 1
            lit = ip - anchor
            token = (min(lit, 15) << 4) | min(ml - 4, 15)
            out.append(token)
            if lit >= 15:
                _lz4_len_ext(out, lit - 15)
            out += data[anchor:ip]
            out += struct.pack("<H", ip - cand)
            if ml - 4 >= 15:
                _lz4_len_ext(out, ml - 4 - 15)
            ip += ml
            anchor = ip
        else:
            ip += 1
    lit = n - anchor
    out.append(min(lit, 15) << 4)
    if lit >= 15:
        _lz4_len_ext(out, lit - 15)
    out += data[anchor:]
    return bytes(out)


def lzma_compress_unity(data: bytes, *, dict_size: int = 1 << 20) -> bytes:
    """Unity-style LZMA: props byte (lc3/lp0/pb2 = 0x5D) + u32 LE dictionary size + raw LZMA1 stream."""
    filters = [{"id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": 3, "lp": 0, "pb": 2}]
    comp = lzma.LZMACompressor(format=lzma.FORMAT_RAW, filters=filters)
    body = comp.compress(bytes(data)) + comp.flush()
    return struct.pack("<BI", 0x5D, dict_size) + body


# ------------------------------------------------------------------------------ UnityFS

_COMP_FLAGS = {"none": 0, "lzma": 1, "lz4": 2, "lz4hc": 3}


def _compress(kind: str, data: bytes) -> bytes:
    if kind == "none":
        return bytes(data)
    if kind == "lzma":
        return lzma_compress_unity(data)
    if kind in ("lz4", "lz4hc"):
        return lz4_compress_block(data)
    raise ValueError(f"unknown compression {kind!r}")


def _align16(n: int) -> int:
    return (n + 15) & ~15


@dataclass
class BuiltBundle:
    data: bytes
    size_field_offset: int
    csize_field_offset: int
    usize_field_offset: int
    flags_field_offset: int
    header_end: int
    blocks_info_offset: int
    blocks_info_length: int
    data_offset: int
    data_length: int

    def patched(self, offset: int, fmt: str, value: int) -> bytes:
        """Return a copy of the bundle with ``struct.pack(fmt, value)`` written at ``offset``."""
        buf = bytearray(self.data)
        packed = struct.pack(fmt, value)
        buf[offset : offset + len(packed)] = packed
        return bytes(buf)


def build_unityfs_ex(
    blocks: Sequence[bytes],
    *,
    compression: Union[str, Sequence[str]] = "lz4",
    blocks_info_compression: Optional[str] = None,
    blocks_info_at_end: bool = False,
    format_version: int = 6,
    player_version: str = "5.x.x",
    engine_version: str = "2018.4.36f1",
    nodes: Optional[Sequence[Tuple]] = None,
    padding_at_start: bool = False,
    flags_extra: int = 0,
    declared_size: Optional[int] = None,
    signature: str = "UnityFS",
) -> BuiltBundle:
    """Build a UnityFS bundle.  ``blocks`` are the *uncompressed* storage blocks.

    ``nodes`` = [(path, offset, size[, flags])]; default is one node covering all data.
    ``format_version >= 7`` aligns the stream to 16 bytes after the header.  ``padding_at_start``
    sets flag 0x200 and aligns the data start (use an ``engine_version`` >= 2021.3.2 so that the
    flag is read as padding rather than as the old encryption bit).
    """
    blocks = [bytes(b) for b in blocks]
    kinds = [compression] * len(blocks) if isinstance(compression, str) else list(compression)
    if len(kinds) != len(blocks):
        raise ValueError("one compression per block")
    bi_kind = blocks_info_compression or (kinds[0] if kinds else "lz4")

    stored = [_compress(k, b) for k, b in zip(kinds, blocks)]
    total_u = sum(len(b) for b in blocks)
    if nodes is None:
        nodes = [("CAB-0123456789abcdef0123456789abcdef", 0, total_u, 4)]

    table = bytearray(b"\x00" * 16)
    table += struct.pack(">i", len(blocks))
    for k, raw, st in zip(kinds, blocks, stored):
        table += struct.pack(">IIH", len(raw), len(st), _COMP_FLAGS[k])
    table += struct.pack(">i", len(nodes))
    for node in nodes:
        path, off, size = node[0], node[1], node[2]
        nflags = node[3] if len(node) > 3 else 4
        table += struct.pack(">qqI", off, size, nflags) + path.encode("utf-8") + b"\x00"
    bi_raw = bytes(table)
    bi_stored = _compress(bi_kind, bi_raw)

    head = (
        signature.encode("ascii")
        + b"\x00"
        + struct.pack(">I", format_version)
        + player_version.encode()
        + b"\x00"
        + engine_version.encode()
        + b"\x00"
    )
    size_off = len(head)
    header_end = size_off + 20
    flags = _COMP_FLAGS[bi_kind] | (0x80 if blocks_info_at_end else 0x40) | (0x200 if padding_at_start else 0)
    flags |= flags_extra

    pos = header_end
    pad0 = b""
    if format_version >= 7:
        pad0 = b"\x00" * (_align16(pos) - pos)
        pos += len(pad0)
    payload = b"".join(stored)
    if blocks_info_at_end:
        bi_off = -1
        data_off = pos
        pad1 = b""
        if padding_at_start:
            pad1 = b"\x00" * (_align16(data_off) - data_off)
            data_off += len(pad1)
        body = pad0 + pad1 + payload
        file_len = header_end + len(body) + len(bi_stored)
        bi_off = file_len - len(bi_stored)
        body += bi_stored
    else:
        bi_off = pos
        data_off = pos + len(bi_stored)
        pad1 = b""
        if padding_at_start:
            pad1 = b"\x00" * (_align16(data_off) - data_off)
            data_off += len(pad1)
        body = pad0 + bi_stored + pad1 + payload
        file_len = header_end + len(body)
    size_value = file_len if declared_size is None else declared_size
    fixed = struct.pack(">qIII", size_value, len(bi_stored), len(bi_raw), flags)
    data = head + fixed + body
    return BuiltBundle(
        data=data,
        size_field_offset=size_off,
        csize_field_offset=size_off + 8,
        usize_field_offset=size_off + 12,
        flags_field_offset=size_off + 16,
        header_end=header_end,
        blocks_info_offset=bi_off,
        blocks_info_length=len(bi_stored),
        data_offset=data_off,
        data_length=len(payload),
    )


def build_unityfs(blocks: Sequence[bytes], **kwargs) -> bytes:
    """Bytes-only convenience wrapper around :func:`build_unityfs_ex`."""
    return build_unityfs_ex(blocks, **kwargs).data


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def build_unityfs_variants(blocks: Sequence[bytes], *, seed: int = 7, **kwargs) -> Dict[str, bytes]:
    """The standard bundle plus the non-standard shapes WP5 must classify."""
    base = build_unityfs(blocks, **kwargs)
    rng = random.Random(seed)
    prefix = bytes(rng.randrange(1, 256) for _ in range(37))
    while b"Unity" in prefix:  # keep the prefix free of accidental signatures
        prefix = bytes(rng.randrange(1, 256) for _ in range(37))
    return {
        "standard": base,
        "offset_prefix": prefix + base,
        "xor_single": _xor(base, b"\x5a"),
        "xor_repeating": _xor(base, b"\x13\x37\xab"),
        "high_entropy": rng.randbytes(len(base)),
    }


# ----------------------------------------------------------------------------------- Lua

LUAC_DATA = b"\x19\x93\r\n\x1a\n"


def _uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _tamper_set(tamper) -> set:
    if tamper is None:
        return set()
    if isinstance(tamper, str):
        return {tamper}
    return set(tamper)


def build_lua_bytecode(
    version: str = "5.3",
    *,
    bits: int = 64,
    endian: str = "little",
    strip: bool = False,
    tamper=None,
    chunkname: str = "@test.lua",
) -> bytes:
    """Header-accurate Lua / LuaJIT chunk with a stub body.

    ``version``: "5.1".."5.5", "luajit2.0", "luajit2.1".  ``tamper`` (str or iterable): ``luac_data``,
    ``luac_int``, ``luac_num``, ``sizeof_int``, ``sizeof_instruction``, ``version_byte``, ``format``,
    ``endian_byte`` (5.1/5.2), ``luajit_private_version``, ``luajit_unknown_flags``.
    """
    t = _tamper_set(tamper)
    bo = endian
    name = chunkname.encode()
    if version.startswith("luajit"):
        return _build_luajit(version, bits=bits, endian=endian, strip=strip, tamper=t, name=name)

    size_t = bits // 8
    size_int, size_instr, size_integer, size_number = 4, 4, 8, 8
    if "sizeof_int" in t:
        size_int = 7
    if "sizeof_instruction" in t:
        size_instr = 8
    ver_byte = {"5.1": 0x51, "5.2": 0x52, "5.3": 0x53, "5.4": 0x54, "5.5": 0x55}[version]
    if "version_byte" in t:
        ver_byte = 0x5F
    fmt = 1 if "format" in t else 0
    data_marker = bytearray(LUAC_DATA)
    if "luac_data" in t:
        data_marker[1] ^= 0xFF
    data_marker = bytes(data_marker)
    sig = b"\x1bLua"
    fstruct = "<" if bo == "little" else ">"

    if version in ("5.1", "5.2"):
        e = 1 if bo == "little" else 0
        if "endian_byte" in t:
            e = 7
        head = sig + bytes([ver_byte, fmt, e, size_int, size_t, size_instr, size_number, 0])
        if version == "5.2":
            head += data_marker
            body = b"\x00" * 16
        else:
            src = b"" if strip else name + b"\x00"
            body = int(len(src)).to_bytes(size_t, bo) + src + b"\x00" * 16
        return head + body

    luac_int = 0x5679 if "luac_int" in t else 0x5678
    luac_num = 371.5 if "luac_num" in t else 370.5
    if version == "5.3":
        head = sig + bytes([ver_byte, fmt]) + data_marker + bytes([size_int, size_t, size_instr, size_integer, size_number])
        head += luac_int.to_bytes(8, bo, signed=True) + struct.pack(fstruct + "d", luac_num)
        src = b"" if strip else name
        head += b"\x01" + (b"\x00" if strip else bytes([len(src) + 1]) + src)
        return head + b"\x00" * 16
    if version == "5.4":
        head = sig + bytes([ver_byte, fmt]) + data_marker + bytes([size_instr, size_integer, size_number])
        head += luac_int.to_bytes(8, bo, signed=True) + struct.pack(fstruct + "d", luac_num)
        src = name
        head += b"\x01" + (b"\x80" if strip else bytes([(len(src) + 1) | 0x80]) + src)
        return head + b"\x00" * 16
    # 5.5: every check value is preceded by its own size byte
    n55 = -370.5 if "luac_num" not in t else -371.5
    i55 = -0x5678 if "luac_int" not in t else -0x5679
    head = sig + bytes([ver_byte, fmt]) + data_marker
    head += bytes([size_int]) + i55.to_bytes(size_int if size_int in (4, 8) else 4, bo, signed=True)
    head += bytes([size_instr]) + (0x12345678).to_bytes(size_instr if size_instr in (4, 8) else 4, bo)
    head += bytes([size_integer]) + i55.to_bytes(8, bo, signed=True)
    head += bytes([size_number]) + struct.pack(fstruct + "d", n55)
    return head + b"\x01" + b"\x00" * 16


def _build_luajit(version: str, *, bits: int, endian: str, strip: bool, tamper: set, name: bytes) -> bytes:
    series = {"luajit2.0": 1, "luajit2.1": 2}[version]
    ver_byte = series
    if "luajit_private_version" in tamper:
        ver_byte = 0x81
    flags = 0
    if endian == "big":
        flags |= 0x01
    if strip:
        flags |= 0x02
    if series == 2 and bits == 64:
        flags |= 0x08
    if "luajit_unknown_flags" in tamper:
        flags |= 0x40
    out = bytearray(b"\x1bLJ" + bytes([ver_byte]) + _uleb(flags))
    if not strip:
        out += _uleb(len(name)) + name
    out += _uleb(5) + b"\x00" * 5 + b"\x00"
    return bytes(out)


# ------------------------------------------------------------------------------- PE / CLI


def _round4(n: int) -> int:
    return (n + 3) & ~3


def build_pe_cli(
    assembly_name: str,
    refs: Iterable[str] = (),
    types: int = 0,
    clr: str = "v4.0.30319",
    *,
    typerefs: int = 0,
    methods: int = 0,
    pe32_plus: bool = False,
    big_strings: bool = False,
    assembly_version: Tuple[int, int, int, int] = (1, 0, 0, 0),
) -> bytes:
    """A tiny but structurally valid managed PE: one section holding the CLI header + metadata.

    Tables written: Module, TypeRef (``typerefs``), TypeDef (``types``), MethodDef (``methods``),
    Assembly, AssemblyRef (one per entry of ``refs``).  ``big_strings`` pads #Strings past 64 KiB so
    string indexes become 4 bytes; large ``typerefs`` / ``types`` exercise wide coded indexes.
    """
    refs = list(refs)

    strings = bytearray(b"\x00")
    cache: Dict[str, int] = {}

    def s(text: str) -> int:
        if not text:
            return 0
        if text not in cache:
            cache[text] = len(strings)
            strings.extend(text.encode("utf-8") + b"\x00")
        return cache[text]

    mod_name = s("module.dll")
    asm_name = s(assembly_name)
    ref_names = [s(r) for r in refs]
    type_names = [s(f"Type{i}") for i in range(types)]
    typeref_names = [s(f"Ref{i}") for i in range(typerefs)]
    method_names = [s(f"M{i}") for i in range(methods)]
    if big_strings:
        strings.extend(b"\x01" * (70000 - len(strings)))
    wide_s = len(strings) >= 65536

    def sidx(v: int) -> bytes:
        return struct.pack("<I" if wide_s else "<H", v)

    guid = b"\x11" * 16
    blob = b"\x00\x01\x00\x00"

    n_typeref, n_typedef, n_method = typerefs, types, methods
    # Wide coded indexes: tag bits per coded-index kind (ECMA-335 II.24.2.6).
    resolution_wide = max(1, n_typeref, len(refs)) >= (1 << 14)  # Module, ModuleRef, AssemblyRef, TypeRef: 2 bits
    typedeforref_wide = max(n_typedef, n_typeref) >= (1 << 14)  # TypeDef, TypeRef, TypeSpec -> 2 bits

    def small(v: int, wide: bool) -> bytes:
        return struct.pack("<I" if wide else "<H", v)

    t_module = struct.pack("<H", 0) + sidx(mod_name) + struct.pack("<HHH", 1, 0, 0)
    t_typeref = b"".join(small((1 << 2) | 0, resolution_wide) + sidx(n) + sidx(0) for n in typeref_names)
    t_typedef = b"".join(
        struct.pack("<I", 0) + sidx(n) + sidx(0) + small(0, typedeforref_wide) + struct.pack("<H", 1)
        + struct.pack("<I" if n_method >= 65536 else "<H", 1)
        for n in type_names
    )
    t_method = b"".join(
        struct.pack("<IHH", 0, 0, 0) + sidx(n) + struct.pack("<H", 1) + struct.pack("<H", 1) for n in method_names
    )
    t_assembly = (
        struct.pack("<I", 0x8004)
        + struct.pack("<HHHH", *assembly_version)
        + struct.pack("<I", 0)
        + struct.pack("<H", 0)
        + sidx(asm_name)
        + sidx(0)
    )
    t_asmref = b"".join(
        struct.pack("<HHHH", 4, 0, 0, 0) + struct.pack("<I", 0) + struct.pack("<H", 0) + sidx(n) + sidx(0) + struct.pack("<H", 0)
        for n in ref_names
    )

    tables: List[Tuple[int, int, bytes]] = [(0x00, 1, t_module)]
    if n_typeref:
        tables.append((0x01, n_typeref, t_typeref))
    if n_typedef:
        tables.append((0x02, n_typedef, t_typedef))
    if n_method:
        tables.append((0x06, n_method, t_method))
    tables.append((0x20, 1, t_assembly))
    if refs:
        tables.append((0x23, len(refs), t_asmref))

    valid = 0
    for idx, _, _ in tables:
        valid |= 1 << idx
    heap_sizes = 0x01 if wide_s else 0x00
    tilde = struct.pack("<IBBBBQQ", 0, 2, 0, heap_sizes, 1, valid, 0)
    tilde += b"".join(struct.pack("<I", rows) for _, rows, _ in tables)
    tilde += b"".join(blob_ for _, _, blob_ in tables)
    tilde = tilde + b"\x00" * (_round4(len(tilde)) - len(tilde))

    strings_b = bytes(strings) + b"\x00" * (_round4(len(strings)) - len(strings))
    guid_b = guid
    blob_b = blob

    clr_b = clr.encode("ascii") + b"\x00"
    vlen = _round4(len(clr_b))
    stream_defs = [("#~", tilde), ("#Strings", strings_b), ("#GUID", guid_b), ("#Blob", blob_b)]
    hdr_len = 16 + vlen + 4 + sum(8 + _round4(len(n) + 1) for n, _ in stream_defs)
    root = bytearray(struct.pack("<IHHII", 0x424A5342, 1, 1, 0, vlen) + clr_b + b"\x00" * (vlen - len(clr_b)))
    root += struct.pack("<HH", 0, len(stream_defs))
    off = hdr_len
    for name, blob_data in stream_defs:
        nb = name.encode("ascii") + b"\x00"
        root += struct.pack("<II", off, len(blob_data)) + nb + b"\x00" * (_round4(len(nb)) - len(nb))
        off += len(blob_data)
    for _, blob_data in stream_defs:
        root += blob_data
    metadata = bytes(root)

    text_rva = 0x2000
    cli = struct.pack("<IHHIIIIQQQQQQ", 72, 2, 5, text_rva + 72, len(metadata), 1, 0, 0, 0, 0, 0, 0, 0)
    assert len(cli) == 72, len(cli)
    section = cli + metadata
    raw_size = (len(section) + 0x1FF) & ~0x1FF

    opt_size = 240 if pe32_plus else 224
    dd_off = 112 if pe32_plus else 96
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B if pe32_plus else 0x10B)
    struct.pack_into("<I", opt, 32, 0x2000)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)  # FileAlignment
    struct.pack_into("<I", opt, 56, text_rva + ((len(section) + 0xFFF) & ~0xFFF))  # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)  # SizeOfHeaders
    struct.pack_into("<I", opt, dd_off - 4, 16)  # NumberOfRvaAndSizes
    struct.pack_into("<II", opt, dd_off + 14 * 8, text_rva, 72)  # CLR runtime header

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664 if pe32_plus else 0x14C, 1, 0, 0, 0, opt_size, 0x2022 if pe32_plus else 0x2102)
    sect = struct.pack("<8sIIIIIIHHI", b".text", len(section), text_rva, raw_size, 0x200, 0, 0, 0, 0, 0x60000020)
    headers = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + sect
    headers += b"\x00" * (0x200 - len(headers))
    return headers + section + b"\x00" * (raw_size - len(section))
