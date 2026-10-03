"""Minimal PE / CLI (.NET) metadata reader: assembly name, CLR version, TypeDef count, AssemblyRefs.

Only what a script/hot-update classifier needs is extracted; this is not a full metadata reader.
Every offset is bounds-checked, every count is capped, and malformed input yields a
``PeCliInfo`` with ``error`` set instead of an exception.  Pass the *complete* file (the metadata
can sit anywhere in it).

Layouts and where they were verified:

* PE headers -- Microsoft PE format documentation (learn.microsoft.com/windows/win32/debug/pe-format):
  ``e_lfanew`` at 0x3C; ``PE\\0\\0``; COFF header 20 bytes; optional header magic 0x10B (PE32) /
  0x20B (PE32+); ``NumberOfRvaAndSizes`` at optional-header offset 92 / 108; data directories at
  96 / 112, 8 bytes each, index 14 = CLR runtime header; section headers are 40 bytes
  (VirtualSize +8, VirtualAddress +12, SizeOfRawData +16, PointerToRawData +20).
* CLI header (IMAGE_COR20_HEADER, ECMA-335 II.25.3.3) -- ``cb`` u32 @0, runtime version u16.u16 @4,
  MetaData RVA/size @8, Flags @16, EntryPointToken @20 (72 bytes in total).
* Metadata root (ECMA-335 II.24.2.1) -- ``BSJB`` (0x424A5342), u16 major, u16 minor, u32 reserved,
  u32 version length (padded to 4), version string, u16 flags, u16 stream count, then per stream
  u32 offset, u32 size, NUL-terminated name padded to 4 bytes.
* ``#~`` / ``#-`` tables stream (ECMA-335 II.24.2.6) -- u32 reserved, u8 major, u8 minor, u8 HeapSizes
  (0x01 / 0x02 / 0x04 = wide #Strings / #GUID / #Blob indexes), u8 reserved, u64 Valid, u64 Sorted,
  u32 row count per set Valid bit; ``HeapSizes & 0x40`` adds 4 extra bytes after the row counts
  (dotnet/runtime ``MetadataReader.ReadMetadataTableHeader``).  Table numbers follow
  ``System.Reflection.Metadata.Ecma335.TableIndex``; column layouts follow ECMA-335 II.22 (row sizes
  are all that is needed to skip to the Assembly / AssemblyRef / TypeDef tables).  Index width
  rules: simple index 2 bytes if the table has < 65536 rows else 4; coded index 2 bytes if every
  target table has < 2^(16-tagbits) rows else 4.

UNVERIFIED: portable-PDB tables (0x30+) are not interpreted.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

__all__ = ["PeCliInfo", "parse", "is_dotnet_assembly"]

_MAX_ASSEMBLY_REFS = 4096
_MAX_TYPEDEF_SAMPLE = 512
_MAX_NAME = 512
_MAX_SECTIONS = 96
_MAX_STREAMS = 32
_MAX_ROWS = 1 << 24

# Table numbers (System.Reflection.Metadata.Ecma335.TableIndex).
_T_MODULE, _T_TYPEREF, _T_TYPEDEF = 0x00, 0x01, 0x02
_T_ASSEMBLY, _T_ASSEMBLYREF = 0x20, 0x23
_T_METHODDEF = 0x06

# Coded-index definitions (ECMA-335 II.24.2.6): (tag bits, target tables; None = unused slot).
_CODED: Dict[str, Tuple[int, Tuple[Optional[int], ...]]] = {
    "TypeDefOrRef": (2, (0x02, 0x01, 0x1B)),
    "HasConstant": (2, (0x04, 0x08, 0x17)),
    "HasCustomAttribute": (
        5,
        (0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27,
         0x28, 0x2A, 0x2C, 0x2B),
    ),
    "HasFieldMarshal": (1, (0x04, 0x08)),
    "HasDeclSecurity": (2, (0x02, 0x06, 0x20)),
    "MemberRefParent": (3, (0x02, 0x01, 0x1A, 0x06, 0x1B)),
    "HasSemantics": (1, (0x14, 0x17)),
    "MethodDefOrRef": (1, (0x06, 0x0A)),
    "MemberForwarded": (1, (0x04, 0x06)),
    "Implementation": (2, (0x26, 0x23, 0x27)),
    "CustomAttributeType": (3, (None, None, 0x06, 0x0A, None)),
    "ResolutionScope": (2, (0x00, 0x1A, 0x23, 0x01)),
    "TypeOrMethodDef": (1, (0x02, 0x06)),
}

# Column kinds: int = fixed byte width; "S" #Strings index; "G" #GUID index; "B" #Blob index;
# ("t", n) simple index into table n; ("c", name) coded index.
_Col = object
_SCHEMA: Dict[int, Tuple[_Col, ...]] = {
    0x00: (2, "S", "G", "G", "G"),  # Module
    0x01: (("c", "ResolutionScope"), "S", "S"),  # TypeRef
    0x02: (4, "S", "S", ("c", "TypeDefOrRef"), ("t", 0x04), ("t", 0x06)),  # TypeDef
    0x03: (("t", 0x04),),  # FieldPtr
    0x04: (2, "S", "B"),  # Field
    0x05: (("t", 0x06),),  # MethodPtr
    0x06: (4, 2, 2, "S", "B", ("t", 0x08)),  # MethodDef
    0x07: (("t", 0x08),),  # ParamPtr
    0x08: (2, 2, "S"),  # Param
    0x09: (("t", 0x02), ("c", "TypeDefOrRef")),  # InterfaceImpl
    0x0A: (("c", "MemberRefParent"), "S", "B"),  # MemberRef
    0x0B: (2, ("c", "HasConstant"), "B"),  # Constant (type, pad, parent, value)
    0x0C: (("c", "HasCustomAttribute"), ("c", "CustomAttributeType"), "B"),  # CustomAttribute
    0x0D: (("c", "HasFieldMarshal"), "B"),  # FieldMarshal
    0x0E: (2, ("c", "HasDeclSecurity"), "B"),  # DeclSecurity
    0x0F: (2, 4, ("t", 0x02)),  # ClassLayout
    0x10: (4, ("t", 0x04)),  # FieldLayout
    0x11: ("B",),  # StandAloneSig
    0x12: (("t", 0x02), ("t", 0x14)),  # EventMap
    0x13: (("t", 0x14),),  # EventPtr
    0x14: (2, "S", ("c", "TypeDefOrRef")),  # Event
    0x15: (("t", 0x02), ("t", 0x17)),  # PropertyMap
    0x16: (("t", 0x17),),  # PropertyPtr
    0x17: (2, "S", "B"),  # Property
    0x18: (2, ("t", 0x06), ("c", "HasSemantics")),  # MethodSemantics
    0x19: (("t", 0x02), ("c", "MethodDefOrRef"), ("c", "MethodDefOrRef")),  # MethodImpl
    0x1A: ("S",),  # ModuleRef
    0x1B: ("B",),  # TypeSpec
    0x1C: (2, ("c", "MemberForwarded"), "S", ("t", 0x1A)),  # ImplMap
    0x1D: (4, ("t", 0x04)),  # FieldRVA
    0x1E: (4, 4),  # EncLog
    0x1F: (4,),  # EncMap
    0x20: (4, 2, 2, 2, 2, 4, "B", "S", "S"),  # Assembly
    0x21: (4,),  # AssemblyProcessor
    0x22: (4, 4, 4),  # AssemblyOS
    0x23: (2, 2, 2, 2, 4, "B", "S", "S", "B"),  # AssemblyRef
    0x24: (4, ("t", 0x23)),  # AssemblyRefProcessor
    0x25: (4, 4, 4, ("t", 0x23)),  # AssemblyRefOS
    0x26: (4, "S", "B"),  # File
    0x27: (4, 4, "S", "S", ("c", "Implementation")),  # ExportedType
    0x28: (4, 4, "S", ("c", "Implementation")),  # ManifestResource
    0x29: (("t", 0x02), ("t", 0x02)),  # NestedClass
    0x2A: (2, 2, ("c", "TypeOrMethodDef"), "S"),  # GenericParam
    0x2B: (("c", "MethodDefOrRef"), "B"),  # MethodSpec
    0x2C: (("t", 0x2A), ("c", "TypeDefOrRef")),  # GenericParamConstraint
}
# UNVERIFIED: portable-PDB tables (0x30+) are not interpreted; the walk stops after AssemblyRef (0x23).
_LAST_TABLE_NEEDED = _T_ASSEMBLYREF


@dataclass
class PeCliInfo:
    is_pe: bool = False
    is_dotnet: bool = False
    pe32_plus: Optional[bool] = None
    machine: Optional[int] = None
    cli_runtime_version: Optional[str] = None  # IMAGE_COR20_HEADER major.minor (2.5 typical)
    cli_flags: Optional[int] = None
    clr_version: Optional[str] = None  # metadata version string, e.g. "v4.0.30319"
    streams: List[str] = field(default_factory=list)
    uncompressed_tables: bool = False  # "#-" stream instead of "#~"
    assembly_name: Optional[str] = None
    assembly_version: Optional[str] = None
    typedef_count: Optional[int] = None
    typeref_count: Optional[int] = None
    methoddef_count: Optional[int] = None
    assembly_refs: List[str] = field(default_factory=list)
    assembly_refs_truncated: bool = False
    typedef_name_stats: Optional[dict] = None
    warnings: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "is_pe": self.is_pe,
            "is_dotnet": self.is_dotnet,
            "pe32_plus": self.pe32_plus,
            "machine": self.machine,
            "cli_runtime_version": self.cli_runtime_version,
            "cli_flags": self.cli_flags,
            "clr_version": self.clr_version,
            "streams": list(self.streams),
            "uncompressed_tables": self.uncompressed_tables,
            "assembly_name": self.assembly_name,
            "assembly_version": self.assembly_version,
            "typedef_count": self.typedef_count,
            "typeref_count": self.typeref_count,
            "methoddef_count": self.methoddef_count,
            "assembly_refs": list(self.assembly_refs),
            "assembly_refs_truncated": self.assembly_refs_truncated,
            "typedef_name_stats": self.typedef_name_stats,
            "warnings": list(self.warnings),
            "error": self.error,
        }


class _Bad(Exception):
    pass


def _u16(d: bytes, o: int) -> int:
    if o < 0 or o + 2 > len(d):
        raise _Bad("read past end")
    return struct.unpack_from("<H", d, o)[0]


def _u32(d: bytes, o: int) -> int:
    if o < 0 or o + 4 > len(d):
        raise _Bad("read past end")
    return struct.unpack_from("<I", d, o)[0]


def _rva_to_offset(rva: int, sections: List[Tuple[int, int, int, int]], headers_size: int, size: int) -> Optional[int]:
    for va, vsize, raw_ptr, raw_size in sections:
        span = max(vsize, raw_size)
        if va <= rva < va + span:
            off = raw_ptr + (rva - va)
            return off if off < size else None
    if rva < headers_size and rva < size:
        return rva
    return None


@dataclass
class _Located:
    md_off: int
    md_size: int


def _parse_pe(data: bytes, info: PeCliInfo) -> Optional[_Located]:
    size = len(data)
    if size < 0x40 or data[:2] != b"MZ":
        info.error = "not_pe"
        return None
    try:
        e_lfanew = _u32(data, 0x3C)
        if e_lfanew > size - 24 or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            info.error = "bad_pe_signature"
            return None
        info.is_pe = True
        coff = e_lfanew + 4
        info.machine = _u16(data, coff)
        nsec = _u16(data, coff + 2)
        opt_size = _u16(data, coff + 16)
        opt = coff + 20
        magic = _u16(data, opt)
        if magic == 0x10B:
            info.pe32_plus, dd_off = False, 96
        elif magic == 0x20B:
            info.pe32_plus, dd_off = True, 112
        else:
            info.error = "bad_optional_header_magic"
            return None
        n_dirs = _u32(data, opt + dd_off - 4)
        if n_dirs <= 14 or dd_off + 15 * 8 > opt_size:
            return None  # no CLR data directory => plain native PE
        clr_rva = _u32(data, opt + dd_off + 14 * 8)
        clr_size = _u32(data, opt + dd_off + 14 * 8 + 4)
        if clr_rva == 0 or clr_size == 0:
            return None
        headers_size = _u32(data, opt + 60)

        if nsec > _MAX_SECTIONS:
            info.warnings.append("section count capped")
            nsec = _MAX_SECTIONS
        sect = opt + opt_size
        sections: List[Tuple[int, int, int, int]] = []
        for i in range(nsec):
            o = sect + i * 40
            if o + 40 > size:
                info.warnings.append("section table truncated")
                break
            sections.append((_u32(data, o + 12), _u32(data, o + 8), _u32(data, o + 20), _u32(data, o + 16)))

        cli = _rva_to_offset(clr_rva, sections, headers_size, size)
        if cli is None or cli + 72 > size:
            info.error = "cli_header_out_of_file"
            return None
        cb = _u32(data, cli)
        if cb < 72:
            info.warnings.append(f"cli header size {cb} < 72")
        info.cli_runtime_version = f"{_u16(data, cli + 4)}.{_u16(data, cli + 6)}"
        md_rva = _u32(data, cli + 8)
        md_size = _u32(data, cli + 12)
        info.cli_flags = _u32(data, cli + 16)
        md = _rva_to_offset(md_rva, sections, headers_size, size)
        if md is None or md_size < 16:
            info.error = "metadata_out_of_file"
            return None
        return _Located(md, min(md_size, size - md))
    except _Bad:
        info.error = "truncated_pe"
        return None


def _parse_metadata_root(data: bytes, loc: _Located, info: PeCliInfo) -> Optional[Dict[str, Tuple[int, int]]]:
    md = loc.md_off
    try:
        if _u32(data, md) != 0x424A5342:
            info.error = "bad_metadata_signature"
            return None
        vlen = _u32(data, md + 12)
        if vlen > 255 or md + 16 + vlen > len(data):
            info.error = "bad_metadata_version_length"
            return None
        raw = data[md + 16 : md + 16 + vlen]
        info.clr_version = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
        pos = md + 16 + vlen
        nstreams = _u16(data, pos + 2)
        pos += 4
        if nstreams == 0 or nstreams > _MAX_STREAMS:
            info.error = "bad_stream_count"
            return None
        streams: Dict[str, Tuple[int, int]] = {}
        for _ in range(nstreams):
            off = _u32(data, pos)
            ssize = _u32(data, pos + 4)
            end = data.find(b"\x00", pos + 8, pos + 8 + 33)
            if end < 0:
                info.error = "bad_stream_name"
                return None
            name = data[pos + 8 : end].decode("ascii", "replace")
            pos = pos + 8 + ((end - (pos + 8) + 1 + 3) & ~3)
            abs_off = md + off
            if abs_off > len(data) or ssize > len(data) - abs_off:
                info.warnings.append(f"stream {name} extends past the end of the file")
                ssize = max(0, min(ssize, len(data) - abs_off))
                if abs_off > len(data):
                    continue
            streams[name] = (abs_off, ssize)
            info.streams.append(name)
        return streams
    except _Bad:
        info.error = "truncated_metadata"
        return None


def _read_cstr(data: bytes, start: int, limit: int) -> str:
    end = data.find(b"\x00", start, min(limit, start + _MAX_NAME))
    if end < 0:
        end = min(limit, start + _MAX_NAME)
    return data[start:end].decode("utf-8", "replace")


def _parse_tables(data: bytes, streams: Dict[str, Tuple[int, int]], info: PeCliInfo) -> None:
    tname = "#~" if "#~" in streams else ("#-" if "#-" in streams else None)
    if tname is None:
        info.warnings.append("no #~ / #- metadata tables stream")
        return
    info.uncompressed_tables = tname == "#-"
    t_off, t_size = streams[tname]
    t_end = t_off + t_size
    try:
        if t_size < 24:
            raise _Bad("tables stream too small")
        heap_sizes = data[t_off + 6]
        valid = struct.unpack_from("<Q", data, t_off + 8)[0]
        pos = t_off + 24
        rows: Dict[int, int] = {}
        for t in range(64):
            if valid >> t & 1:
                n = _u32(data, pos)
                pos += 4
                rows[t] = n
        if heap_sizes & 0x40:
            pos += 4
        if pos > t_end:
            raise _Bad("row counts run past the stream")
        info.typedef_count = rows.get(_T_TYPEDEF, 0)
        info.typeref_count = rows.get(_T_TYPEREF, 0)
        info.methoddef_count = rows.get(_T_METHODDEF, 0)
        if any(n > _MAX_ROWS for n in rows.values()):
            info.warnings.append("implausible row count; table walk skipped")
            return

        wide_s, wide_g, wide_b = bool(heap_sizes & 1), bool(heap_sizes & 2), bool(heap_sizes & 4)

        def idx_size(table: int) -> int:
            return 4 if rows.get(table, 0) >= 65536 else 2

        coded_cache: Dict[str, int] = {}

        def coded_size(name: str) -> int:
            if name not in coded_cache:
                bits, targets = _CODED[name]
                limit = 1 << (16 - bits)
                big = any(t is not None and rows.get(t, 0) >= limit for t in targets)
                coded_cache[name] = 4 if big else 2
            return coded_cache[name]

        def col_size(col) -> int:
            if isinstance(col, int):
                return col
            if col == "S":
                return 4 if wide_s else 2
            if col == "G":
                return 4 if wide_g else 2
            if col == "B":
                return 4 if wide_b else 2
            kind, arg = col
            return idx_size(arg) if kind == "t" else coded_size(arg)

        starts: Dict[int, int] = {}
        row_sizes: Dict[int, int] = {}
        for t in sorted(rows):
            if t > _LAST_TABLE_NEEDED:
                break
            schema = _SCHEMA.get(t)
            if schema is None:
                info.warnings.append(f"unknown table 0x{t:02x}; table walk stopped")
                return
            rsize = sum(col_size(c) for c in schema)
            starts[t] = pos
            row_sizes[t] = rsize
            pos += rsize * rows[t]
            if pos > t_end:
                info.warnings.append("tables extend past the #~ stream; table walk stopped")
                if t < _T_ASSEMBLY:
                    return
                break

        strings = streams.get("#Strings")
        if strings is None:
            info.warnings.append("no #Strings stream")
            return
        s_off, s_size = strings
        s_wide = 4 if wide_s else 2

        def get_string(index: int) -> Optional[str]:
            if index >= s_size:
                return None
            return _read_cstr(data, s_off + index, s_off + s_size)

        def row_field(table: int, row: int, col_pos: int, width: int) -> int:
            base = starts[table] + row * row_sizes[table] + col_pos
            return int.from_bytes(data[base : base + width], "little")

        if rows.get(_T_ASSEMBLY, 0) >= 1 and _T_ASSEMBLY in starts and starts[_T_ASSEMBLY] + row_sizes[_T_ASSEMBLY] <= t_end:
            blob_w = 4 if wide_b else 2
            base = starts[_T_ASSEMBLY]
            ver = struct.unpack_from("<HHHH", data, base + 4)
            info.assembly_version = ".".join(str(v) for v in ver)
            name_pos = 4 + 8 + 4 + blob_w
            info.assembly_name = get_string(row_field(_T_ASSEMBLY, 0, name_pos, s_wide))

        if _T_ASSEMBLYREF in starts:
            blob_w = 4 if wide_b else 2
            name_pos = 8 + 4 + blob_w
            count = rows[_T_ASSEMBLYREF]
            if count > _MAX_ASSEMBLY_REFS:
                info.assembly_refs_truncated = True
                count = _MAX_ASSEMBLY_REFS
            for r in range(count):
                if starts[_T_ASSEMBLYREF] + (r + 1) * row_sizes[_T_ASSEMBLYREF] > t_end:
                    break
                nm = get_string(row_field(_T_ASSEMBLYREF, r, name_pos, s_wide))
                if nm is not None:
                    info.assembly_refs.append(nm)

        if _T_TYPEDEF in starts and rows[_T_TYPEDEF]:
            info.typedef_name_stats = _typedef_name_stats(
                rows[_T_TYPEDEF], row_field, get_string, s_wide, starts[_T_TYPEDEF], row_sizes[_T_TYPEDEF], t_end
            )
    except _Bad as exc:
        info.warnings.append(f"tables stream: {exc}")


def _typedef_name_stats(count, row_field, get_string, s_wide, start, row_size, t_end) -> Optional[dict]:
    """Rough obfuscation hints over the first TypeDef names (column 1 = TypeName)."""
    sample = min(count, _MAX_TYPEDEF_SAMPLE)
    lengths: List[int] = []
    non_ascii = short = 0
    for r in range(sample):
        if start + (r + 1) * row_size > t_end:
            break
        nm = get_string(row_field(_T_TYPEDEF, r, 4, s_wide))
        if not nm:
            continue
        lengths.append(len(nm))
        if len(nm) <= 2:
            short += 1
        if any(ord(c) > 127 or (ord(c) < 32) for c in nm):
            non_ascii += 1
    if not lengths:
        return None
    n = len(lengths)
    return {
        "sampled": n,
        "mean_length": round(sum(lengths) / n, 2),
        "short_ratio": round(short / n, 3),
        "non_ascii_ratio": round(non_ascii / n, 3),
    }


def parse(data: bytes) -> PeCliInfo:
    """Parse a PE image and, if it is a .NET assembly, its metadata summary.  Never raises."""
    info = PeCliInfo()
    try:
        data = bytes(data)
        loc = _parse_pe(data, info)
        if loc is None:
            return info
        streams = _parse_metadata_root(data, loc, info)
        if streams is None:
            return info
        info.is_dotnet = True
        _parse_tables(data, streams, info)
    except Exception as exc:  # defensive: parsing hostile input must never crash a scan
        info.error = f"internal_error:{type(exc).__name__}"
    return info


def is_dotnet_assembly(data: bytes) -> bool:
    """Fast check: PE image with a CLR data directory whose metadata root carries the BSJB signature."""
    info = PeCliInfo()
    try:
        data = bytes(data)
        loc = _parse_pe(data, info)
        if loc is None:
            return False
        return _u32(data, loc.md_off) == 0x424A5342
    except (_Bad, ValueError):
        return False
