"""Pure-Python Mach-O / fat reader (struct + mmap, no third-party code).

* ``parse()`` accepts a path, ``bytes``-like object or binary file object and returns a
  :class:`MachOFile` holding one :class:`MachOSlice` per architecture.
* Everything is bounds-checked. Malformed data produces ``warnings`` (and a truncated view) rather
  than exceptions wherever a partial answer is still useful; only an unreadable header raises
  :class:`MachOError`, and non-Mach-O input raises :class:`NotMachO`.
* Strings and symbols are exposed through lazy generators that read small windows, so a 300 MB
  binary never has to be loaded into memory. Offsets inside a slice (``symoff``, ``dataoff``,
  section ``offset`` ...) are relative to the slice start, exactly as in the file format.
* ``MachOFile`` keeps the file/mmap open until ``close()``; use it as a context manager (required on
  Windows before deleting the file).
"""
from __future__ import annotations

import logging
import mmap
import os
import re
import struct
import uuid as _uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import (IO, Any, BinaryIO, Dict, Iterable, Iterator, List, NamedTuple, Optional, Sequence,
                    Set, Tuple, Union)

from . import constants as C
from .codesign import CodeSignature, parse_code_signature
from .errors import MachOError, NotMachO

log = logging.getLogger(__name__)

__all__ = [
    "parse", "MachOFile", "MachOSlice", "Segment", "Section", "DylibRef", "EncryptionInfo", "LoadCommand",
    "SymtabInfo", "DysymtabInfo", "BuildVersion", "BuildTool", "DecodedFlags", "Symbol", "BinarySource",
    "MachOError", "NotMachO",
]

BinarySource = Union[str, "os.PathLike[str]", bytes, bytearray, memoryview, BinaryIO]

_THIN_MAGICS = {C.MH_MAGIC: (False, "<"), C.MH_MAGIC_64: (True, "<"),
                C.MH_CIGAM: (False, ">"), C.MH_CIGAM_64: (True, ">")}
_NONZERO_NAME = re.compile(rb"[^\x00]{%d,}")
_CHUNK = 1 << 20
_MAX_STRING = 1 << 16
_NLIST_BATCH = 4096


# --- random-access byte sources ----------------------------------------------------------------
class _Source:
    """Random-access read-only bytes. ``read`` clamps to the available data and returns ``bytes``."""

    size = 0

    def read(self, off: int, n: int) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:
        return None


class _BufferSource(_Source):
    def __init__(self, buf: Any, size: int, closer: Any = None) -> None:
        self._buf, self.size, self._closer = buf, size, closer

    def read(self, off: int, n: int) -> bytes:
        if n <= 0 or off < 0 or off >= self.size:
            return b""
        return bytes(self._buf[off:min(off + n, self.size)])

    def close(self) -> None:
        closer, self._closer, self._buf = self._closer, None, b""
        self.size = 0
        if closer is not None:
            closer()


class _FileSource(_Source):
    """Fallback for streams that cannot be memory-mapped (reads through seek/read)."""

    def __init__(self, fh: IO[bytes], size: int, owned: bool) -> None:
        self._fh, self.size, self._owned = fh, size, owned

    def read(self, off: int, n: int) -> bytes:
        if n <= 0 or off < 0 or off >= self.size or self._fh is None:
            return b""
        self._fh.seek(off)
        return self._fh.read(min(n, self.size - off))

    def close(self) -> None:
        fh, self._fh = self._fh, None
        if fh is not None and self._owned:
            fh.close()


def _open_source(src: BinarySource) -> Tuple[_Source, Optional[Path]]:
    if isinstance(src, (bytes, bytearray, memoryview)):
        data = src if isinstance(src, bytes) else bytes(src)
        return _BufferSource(data, len(data)), None
    if isinstance(src, (str, os.PathLike)):
        path = Path(src)
        fh = open(path, "rb")
        try:
            size = os.fstat(fh.fileno()).st_size
            if size == 0:
                raise NotMachO("empty file")
            try:
                mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
            except (ValueError, OSError, OverflowError):
                return _FileSource(fh, size, True), path

            def _close(mm: mmap.mmap = mm, fh: IO[bytes] = fh) -> None:
                try:
                    mm.close()
                finally:
                    fh.close()

            return _BufferSource(mm, size, _close), path
        except BaseException:
            fh.close()
            raise
    # file-like object
    fh = src  # type: ignore[assignment]
    getbuffer = getattr(fh, "getbuffer", None)
    if callable(getbuffer):                       # io.BytesIO
        data = bytes(getbuffer())
        return _BufferSource(data, len(data)), None
    try:
        fileno = fh.fileno()
        size = os.fstat(fileno).st_size
        mm = mmap.mmap(fileno, 0, access=mmap.ACCESS_READ)
        return _BufferSource(mm, size, mm.close), None
    except (AttributeError, OSError, ValueError, OverflowError):
        pass
    fh.seek(0, os.SEEK_END)
    size = fh.tell()
    return _FileSource(fh, size, False), None


# --- data model --------------------------------------------------------------------------------
@dataclass
class LoadCommand:
    cmd: int
    cmdsize: int
    offset: int       # relative to the slice start
    name: str

    def to_dict(self) -> Dict[str, Any]:
        return {"cmd": self.cmd, "cmdsize": self.cmdsize, "offset": self.offset, "name": self.name}


@dataclass
class Section:
    sectname: str
    segname: str
    addr: int
    size: int
    offset: int       # relative to the slice start (0 for zero-fill sections)
    align: int
    flags: int

    @property
    def type(self) -> int:
        return self.flags & C.SECTION_TYPE_MASK

    @property
    def is_zerofill(self) -> bool:
        return self.type in C.ZEROFILL_SECTION_TYPES

    @property
    def is_cstring(self) -> bool:
        return self.type == C.S_CSTRING_LITERALS

    @property
    def full_name(self) -> str:
        return "%s,%s" % (self.segname, self.sectname)


@dataclass
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int = 0
    initprot: int = 0
    flags: int = 0
    sections: List[Section] = field(default_factory=list)


@dataclass
class DylibRef:
    path: str
    kind: str                 # system | bundled | other
    load_kind: str            # load | weak | reexport | lazy | upward
    weak: bool
    current_version: str = ""
    compat_version: str = ""
    timestamp: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"path": self.path, "kind": self.kind, "load_kind": self.load_kind, "weak": self.weak,
                "current_version": self.current_version}


@dataclass
class EncryptionInfo:
    cmd: int
    cryptoff: int
    cryptsize: int
    cryptid: int

    @property
    def encrypted(self) -> bool:
        """FairPlay-style encryption is active: ``cryptid != 0 and cryptsize > 0``."""
        return self.cryptid != 0 and self.cryptsize > 0


@dataclass
class SymtabInfo:
    symoff: int
    nsyms: int
    stroff: int
    strsize: int


@dataclass
class DysymtabInfo:
    ilocalsym: int
    nlocalsym: int
    iextdefsym: int
    nextdefsym: int
    iundefsym: int
    nundefsym: int

    def consistent(self, nsyms: int) -> bool:
        return (self.ilocalsym + self.nlocalsym <= nsyms and self.iextdefsym + self.nextdefsym <= nsyms
                and self.iundefsym + self.nundefsym <= nsyms)


@dataclass
class BuildTool:
    tool: str
    tool_id: int
    version: str


@dataclass
class BuildVersion:
    platform_id: int
    platform: str
    min_os: str
    sdk: str
    tools: List[BuildTool] = field(default_factory=list)


@dataclass
class DecodedFlags:
    """``mach_header.flags`` as booleans (``names`` lists every known bit that is set)."""

    raw: int
    names: List[str]

    def __getattr__(self, item: str) -> bool:
        if item.startswith("_") or item in ("raw", "names"):
            raise AttributeError(item)
        return item in self.names

    def to_dict(self) -> Dict[str, bool]:
        return {n: n in self.names for n, _ in C.HEADER_FLAG_NAMES}


class Symbol(NamedTuple):
    name: str
    n_type: int
    n_sect: int
    n_desc: int
    n_value: int

    @property
    def is_stab(self) -> bool:
        return bool(self.n_type & C.N_STAB)

    @property
    def is_external(self) -> bool:
        return bool(self.n_type & C.N_EXT)

    @property
    def is_undefined(self) -> bool:
        return not self.n_type & C.N_STAB and (self.n_type & C.N_TYPE) == C.N_UNDF and self.n_sect == 0

    @property
    def is_debug_stab(self) -> bool:
        return self.n_type in C.DEBUG_STAB_TYPES

    @property
    def is_defined(self) -> bool:
        return not self.n_type & C.N_STAB and (self.n_type & C.N_TYPE) == C.N_SECT

    @property
    def library_ordinal(self) -> int:
        """Two-level-namespace dylib ordinal of an undefined symbol (1-based; 0 = self)."""
        return (self.n_desc >> 8) & 0xFF


@dataclass
class _SymbolStats:
    total: int = 0
    undefined: int = 0
    local_defined: int = 0
    external_defined: int = 0
    stabs: int = 0            # debug stabs (N_SO / N_OSO / N_FUN ...)
    other_stabs: int = 0      # remaining stab entries (e.g. N_OPT)
    basis: str = "none"       # none | dysymtab | scan
    truncated: bool = False


@dataclass
class _ImportInfo:
    count: int = 0
    stack_canary: bool = False
    arc: bool = False
    objc_runtime: bool = False
    truncated: bool = False


def _cstring_at(raw: bytes, off: int, end: Optional[int] = None) -> Optional[str]:
    end = len(raw) if end is None else min(end, len(raw))
    if off < 0 or off >= end:
        return None
    nul = raw.find(b"\0", off, end)
    return raw[off:nul if nul >= 0 else end].decode("utf-8", "replace")


def _fixed_name(raw: bytes) -> str:
    nul = raw.find(b"\0")
    return (raw if nul < 0 else raw[:nul]).decode("latin-1")


def iter_nul_strings(read: Any, start: int, end: int, min_len: int, *, chunk: int = _CHUNK,
                     max_len: int = _MAX_STRING) -> Iterator[bytes]:
    """Yield NUL-delimited byte strings (>= ``min_len``) of ``[start, end)`` using bounded memory.

    ``read(offset, n)`` must return up to ``n`` bytes. A run longer than ``max_len`` without a NUL is
    cut (yielded in pieces) to bound memory.
    """
    pattern = re.compile(b"[^\\x00]{%d,}" % max(1, min_len))
    pos, carry = start, b""
    while pos < end:
        buf = read(pos, min(chunk, end - pos))
        if not buf:
            break
        pos += len(buf)
        buf = carry + buf
        idx = buf.rfind(b"\0")
        if idx < 0:
            carry = buf
        else:
            carry = buf[idx + 1:]
            for m in pattern.finditer(buf, 0, idx):
                yield m.group()
        while len(carry) > max_len:
            yield carry[:max_len]
            carry = carry[max_len:]
    if len(carry) >= max(1, min_len):
        yield carry


# --- the slice ---------------------------------------------------------------------------------
class MachOSlice:
    """One architecture of a Mach-O file (or a thin file)."""

    def __init__(self, src: _Source, offset: int, size: int) -> None:
        self._src = src
        self.offset = offset            # file offset of the slice inside the (fat) file
        self.size = size
        self.warnings: List[str] = []
        self.is_64 = False
        self.byte_order = "<"
        self.cputype = 0
        self.cpusubtype = 0
        self.filetype = 0
        self.ncmds = 0
        self.sizeofcmds = 0
        self.flags = 0
        self.load_commands: List[LoadCommand] = []
        self.segments: List[Segment] = []
        self.dylibs: List[DylibRef] = []
        self.id_dylib: Optional[DylibRef] = None
        self.rpaths: List[str] = []
        self.dylinker: Optional[str] = None
        self.uuid: Optional[str] = None
        self.build_versions: List[BuildVersion] = []
        self.version_min: Optional[BuildVersion] = None
        self.encryption: List[EncryptionInfo] = []
        self.symtab: Optional[SymtabInfo] = None
        self.dysymtab: Optional[DysymtabInfo] = None
        self.source_version: Optional[str] = None
        self.entry_offset: Optional[int] = None
        self.has_unixthread = False
        self.has_dyld_info = False
        self.has_chained_fixups = False
        self._code_sig_loc: Optional[Tuple[int, int]] = None
        self._code_signature: Optional[CodeSignature] = None
        self._code_signature_done = False
        self._symbol_stats: Optional[_SymbolStats] = None
        self._import_info: Optional[_ImportInfo] = None

    # -- raw access --------------------------------------------------------------------------
    def read(self, rel_off: int, n: int) -> bytes:
        """Read up to ``n`` bytes at ``rel_off`` (relative to the slice start), clamped to the slice."""
        if n <= 0 or rel_off < 0 or rel_off >= self.size:
            return b""
        return self._src.read(self.offset + rel_off, min(n, self.size - rel_off))

    def iter_bytes(self, chunk: int = _CHUNK) -> Iterator[bytes]:
        """Stream the whole slice in ``chunk``-sized pieces."""
        pos = 0
        while pos < self.size:
            buf = self.read(pos, chunk)
            if not buf:
                break
            pos += len(buf)
            yield buf

    # -- identity ----------------------------------------------------------------------------
    @property
    def arch_name(self) -> str:
        return C.arch_name(self.cputype, self.cpusubtype)

    @property
    def filetype_name(self) -> str:
        return C.FILETYPE_NAMES.get(self.filetype, "filetype%d" % self.filetype)

    @property
    def is_big_endian(self) -> bool:
        return self.byte_order == ">"

    @property
    def flags_decoded(self) -> DecodedFlags:
        return DecodedFlags(self.flags, [n for n, bit in C.HEADER_FLAG_NAMES if self.flags & bit])

    @property
    def is_pie(self) -> bool:
        """Position-independent: the ``MH_PIE`` flag for executables; dylibs/bundles are always relocatable."""
        if self.filetype in (C.MH_DYLIB, C.MH_BUNDLE):
            return True
        return bool(self.flags & C.MH_PIE)

    # -- platform ----------------------------------------------------------------------------
    @property
    def _primary_build(self) -> Optional[BuildVersion]:
        return self.build_versions[0] if self.build_versions else self.version_min

    @property
    def platform_id(self) -> Optional[int]:
        b = self._primary_build
        return b.platform_id if b else None

    @property
    def platform(self) -> Optional[str]:
        b = self._primary_build
        return b.platform if b else None

    @property
    def min_os(self) -> Optional[str]:
        b = self._primary_build
        return b.min_os if b else None

    @property
    def sdk(self) -> Optional[str]:
        b = self._primary_build
        return b.sdk if b else None

    @property
    def build_tools(self) -> List[BuildTool]:
        b = self.build_versions[0] if self.build_versions else None
        return list(b.tools) if b else []

    @property
    def is_simulator(self) -> bool:
        pid = self.platform_id
        if pid in C.SIMULATOR_PLATFORMS:
            return True
        # Pre-LC_BUILD_VERSION simulator builds were plain x86 slices with an iOS version-min command.
        return pid == C.PLATFORM_IOS and self.cputype in (C.CPU_TYPE_X86, C.CPU_TYPE_X86_64)

    # -- encryption --------------------------------------------------------------------------
    @property
    def is_encrypted(self) -> bool:
        return any(e.encrypted for e in self.encryption)

    def range_encrypted(self, rel_off: int, size: int) -> bool:
        """Whether ``[rel_off, rel_off+size)`` overlaps an active (``cryptid != 0``) encrypted range.

        Content inside it is ciphertext: strings/symbol names read from there are noise.
        """
        end = rel_off + max(size, 0)
        return any(e.encrypted and rel_off < e.cryptoff + e.cryptsize and e.cryptoff < end
                   for e in self.encryption)

    # -- segments / sections -----------------------------------------------------------------
    @property
    def sections(self) -> List[Section]:
        return [s for seg in self.segments for s in seg.sections]

    def find_sections(self, sectname: str, segname: Optional[str] = None) -> List[Section]:
        return [s for s in self.sections if s.sectname == sectname and (segname is None or s.segname == segname)]

    def find_section(self, sectname: str, segname: Optional[str] = None) -> Optional[Section]:
        found = self.find_sections(sectname, segname)
        return found[0] if found else None

    # -- language / runtime hints ------------------------------------------------------------
    @property
    def has_objc(self) -> bool:
        if any(s.sectname.startswith(C.OBJC_SECTION_PREFIX) for s in self.sections):
            return True
        return any(d.path.endswith("libobjc.A.dylib") for d in self.dylibs) and self._imports().objc_runtime

    @property
    def has_swift(self) -> bool:
        if any(s.sectname.startswith(C.SWIFT_SECTION_PREFIX) for s in self.sections):
            return True
        return any("libswift" in d.path.rsplit("/", 1)[-1] for d in self.dylibs)

    @property
    def has_cpp(self) -> bool:
        return any(d.path.rsplit("/", 1)[-1].startswith(("libc++", "libstdc++")) for d in self.dylibs)

    @property
    def has_stack_canary(self) -> bool:
        return self._imports().stack_canary

    @property
    def uses_arc(self) -> bool:
        return self._imports().arc

    # -- code signature ----------------------------------------------------------------------
    @property
    def has_code_signature(self) -> bool:
        return self._code_sig_loc is not None

    @property
    def code_signature(self) -> Optional[CodeSignature]:
        """Parsed ``LC_CODE_SIGNATURE`` payload (``None`` if the command is absent)."""
        if self._code_signature_done:
            return self._code_signature
        self._code_signature_done = True
        if self._code_sig_loc is None:
            return None
        off, length = self._code_sig_loc
        if length > C.MAX_SIGNATURE_BYTES:
            self._code_signature = CodeSignature(parse_error="signature size %d exceeds limit" % length)
        elif off >= self.size or length <= 0:
            self._code_signature = CodeSignature(parse_error="code signature lies outside the file")
        else:
            data = self.read(off, length)
            sig = parse_code_signature(data)
            if len(data) < length:
                sig.warnings.append("code signature truncated (%d of %d bytes present)" % (len(data), length))
            self._code_signature = sig
        return self._code_signature

    # -- strings -----------------------------------------------------------------------------
    def _section_ranges(self, sections: Iterable[Section]) -> Iterator[Tuple[int, int]]:
        for s in sections:
            if s.is_zerofill or s.size <= 0 or s.offset <= 0 or s.offset >= self.size:
                continue
            yield s.offset, min(s.offset + s.size, self.size)

    def iter_section_strings(self, sections: Iterable[Section], min_len: int = 4, *,
                             skip_encrypted: bool = False) -> Iterator[str]:
        for start, end in self._section_ranges(sections):
            if skip_encrypted and self.range_encrypted(start, end - start):
                continue
            for raw in iter_nul_strings(self.read, start, end, min_len):
                yield raw.decode("utf-8", "replace")

    def iter_cstrings(self, min_len: int = 4, *, section: Optional[str] = None,
                      skip_encrypted: bool = False) -> Iterator[str]:
        """Lazily yield C-string literals (``S_CSTRING_LITERALS`` sections: ``__cstring``,
        ``__objc_classname``, ``__objc_methname``, ``__objc_methtype`` ...).

        ``section`` restricts to one section name (e.g. ``"__cstring"``). Sections inside a FairPlay
        encrypted range contain ciphertext; ``skip_encrypted=True`` leaves them out.
        """
        wanted = [s for s in self.sections if s.is_cstring and (section is None or s.sectname == section)]
        return self.iter_section_strings(wanted, min_len, skip_encrypted=skip_encrypted)

    def objc_class_names(self, *, skip_encrypted: bool = False) -> Iterator[str]:
        """Class names from ``__TEXT,__objc_classname`` (lazy)."""
        return self.iter_section_strings(self.find_sections(C.SECT_OBJC_CLASSNAME), 1,
                                         skip_encrypted=skip_encrypted)

    def objc_method_names(self, *, skip_encrypted: bool = False) -> Iterator[str]:
        """Selector names from ``__TEXT,__objc_methname`` (lazy)."""
        return self.iter_section_strings(self.find_sections(C.SECT_OBJC_METHNAME), 1,
                                         skip_encrypted=skip_encrypted)

    # -- symbols -----------------------------------------------------------------------------
    def _nlist_available(self) -> int:
        st = self.symtab
        if st is None or st.nsyms == 0 or st.symoff >= self.size:
            return 0
        esize = C.NLIST_64_SIZE if self.is_64 else C.NLIST_SIZE
        return min(st.nsyms, (self.size - st.symoff) // esize)

    def _symbol_name(self, strx: int) -> str:
        st = self.symtab
        if st is None or strx == 0 or strx >= st.strsize:
            return ""
        limit = st.strsize - strx
        raw = self.read(st.stroff + strx, min(256, limit))
        if b"\0" not in raw and len(raw) < limit:
            raw += self.read(st.stroff + strx + len(raw), min(16384, limit - len(raw)))
        nul = raw.find(b"\0")
        return (raw if nul < 0 else raw[:nul]).decode("utf-8", "replace")

    def _iter_nlist(self, start: int, count: int) -> Iterator[Symbol]:
        st = self.symtab
        avail = self._nlist_available()
        if st is None or start < 0:
            return
        end = min(start + count, avail)
        esize = C.NLIST_64_SIZE if self.is_64 else C.NLIST_SIZE
        fmt = self.byte_order + ("IBBHQ" if self.is_64 else "IBBHI")
        i = start
        while i < end:
            n = min(_NLIST_BATCH, end - i)
            buf = self.read(st.symoff + i * esize, n * esize)
            got = len(buf) // esize
            if got == 0:
                return
            for strx, ntype, nsect, ndesc, nvalue in struct.iter_unpack(fmt, buf[:got * esize]):
                yield Symbol(self._symbol_name(strx), ntype, nsect, ndesc, nvalue)
            i += got

    def iter_symbols(self) -> Iterator[Symbol]:
        """Lazily yield every ``nlist`` entry (including stabs and undefined symbols)."""
        return self._iter_nlist(0, self._nlist_available())

    def iter_imported_symbols(self) -> Iterator[Symbol]:
        """Lazily yield undefined (imported) symbols; uses ``LC_DYSYMTAB`` ranges when consistent."""
        dys, avail = self.dysymtab, self._nlist_available()
        if dys is not None and dys.consistent(avail) and avail:
            return self._iter_nlist(dys.iundefsym, dys.nundefsym)
        return (s for s in self.iter_symbols() if s.is_undefined)

    def imported_symbol_names(self, limit: int = C.MAX_SYMBOL_SCAN) -> Set[str]:
        names: Set[str] = set()
        for n, sym in enumerate(self.iter_imported_symbols()):
            if n >= limit:
                break
            names.add(sym.name)
        return names

    def _imports(self) -> _ImportInfo:
        if self._import_info is not None:
            return self._import_info
        info = _ImportInfo()
        try:
            for sym in self.iter_imported_symbols():
                info.count += 1
                name = sym.name
                if name in C.STACK_CANARY_SYMBOLS:
                    info.stack_canary = True
                elif name in C.ARC_SYMBOLS:
                    info.arc = True
                if name.startswith(C.OBJC_RUNTIME_SYMBOL_PREFIXES):
                    info.objc_runtime = True
                if info.count >= C.MAX_SYMBOL_SCAN:
                    info.truncated = True
                    break
        except (struct.error, MemoryError) as exc:  # pragma: no cover - defensive
            self.warnings.append("symbol table unreadable: %s" % exc)
        self._import_info = info
        return info

    def symbol_stats(self) -> _SymbolStats:
        """Symbol counts used by the ``stripped`` heuristic (computed once, bounded)."""
        if self._symbol_stats is not None:
            return self._symbol_stats
        stats = _SymbolStats()
        avail = self._nlist_available()
        stats.total = avail
        if avail:
            dys = self.dysymtab
            if dys is not None and dys.consistent(avail):
                stats.basis = "dysymtab"
                stats.undefined, stats.external_defined = dys.nundefsym, dys.nextdefsym
                sampled = 0
                for sym in self._iter_nlist(dys.ilocalsym, min(dys.nlocalsym, C.STAB_SAMPLE)):
                    sampled += 1
                    if sym.is_debug_stab:
                        stats.stabs += 1
                    elif sym.is_stab:
                        stats.other_stabs += 1
                # Local range = stabs (first) + real local symbols. Exact when fully sampled.
                stats.local_defined = (max(0, dys.nlocalsym - stats.stabs - stats.other_stabs)
                                       if sampled >= dys.nlocalsym else dys.nlocalsym)
            else:
                stats.basis = "scan"
                for sym in self._iter_nlist(0, min(avail, C.MAX_SYMBOL_SCAN)):
                    if sym.is_debug_stab:
                        stats.stabs += 1
                    elif sym.is_stab:
                        stats.other_stabs += 1
                    elif sym.is_undefined:
                        stats.undefined += 1
                    elif sym.is_defined:
                        if sym.is_external:
                            stats.external_defined += 1
                        else:
                            stats.local_defined += 1
                stats.truncated = avail > C.MAX_SYMBOL_SCAN
        self._symbol_stats = stats
        return stats

    @property
    def symbol_level(self) -> str:
        """``none`` (no defined symbols) / ``stripped_all`` / ``stripped_local`` / ``debug`` / ``full``.

        Empirical heuristic (see ``constants.STRIPPED_*``): stabs mean debug info; otherwise few
        defined local symbols mean ``strip -x`` style stripping.
        """
        st = self.symbol_stats()
        if st.total == 0:
            return "none"
        if st.stabs > 0:
            return "debug"
        local, ext = st.local_defined, st.external_defined
        if local <= C.STRIPPED_ALL_MAX_SYMBOLS and ext <= C.STRIPPED_ALL_MAX_SYMBOLS:
            return "stripped_all"
        if local <= C.STRIPPED_LOCAL_MAX_SYMBOLS:
            return "stripped_local"
        return "full"

    @property
    def stripped(self) -> bool:
        """Best-effort: True when local/debug symbols have been removed (see :attr:`symbol_level`)."""
        return self.symbol_level in ("none", "stripped_all", "stripped_local")


# --- load command parsing ----------------------------------------------------------------------
def _parse_slice(src: _Source, offset: int, size: int, fat_cpu: Optional[Tuple[int, int]] = None) -> MachOSlice:
    sl = MachOSlice(src, offset, size)
    head = sl.read(0, 4)
    if len(head) < 4:
        raise MachOError("truncated Mach-O header (%d bytes)" % len(head))
    magic = struct.unpack("<I", head)[0]
    if magic not in _THIN_MAGICS:
        raise NotMachO("bad Mach-O magic 0x%08x" % magic)
    sl.is_64, sl.byte_order = _THIN_MAGICS[magic]
    hsize = C.MACH_HEADER_64_SIZE if sl.is_64 else C.MACH_HEADER_SIZE
    hdr = sl.read(0, hsize)
    if len(hdr) < hsize:
        raise MachOError("truncated Mach-O header (%d of %d bytes)" % (len(hdr), hsize))
    bo = sl.byte_order
    (_, sl.cputype, sl.cpusubtype, sl.filetype, sl.ncmds, sl.sizeofcmds, sl.flags) = struct.unpack_from(
        bo + "IiiIIII", hdr, 0)
    sl.cputype &= 0xFFFFFFFF
    sl.cpusubtype &= 0xFFFFFFFF
    if fat_cpu is not None and fat_cpu[0] != sl.cputype:
        sl.warnings.append("fat header cputype 0x%x disagrees with Mach header 0x%x" % (fat_cpu[0], sl.cputype))
    _parse_load_commands(sl, hsize)
    return sl


def _lc_str(sl: MachOSlice, body: bytes, str_off: int) -> Optional[str]:
    if str_off < 8 or str_off >= len(body):
        return None
    return _cstring_at(body, str_off)


def _parse_segment(sl: MachOSlice, body: bytes, is64: bool) -> None:
    bo = sl.byte_order
    if is64:
        fixed, sect_size = C.SEGMENT_COMMAND_64_SIZE, C.SECTION_64_SIZE
        segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack_from(
            bo + "16sQQQQiiII", body, 8)
    else:
        fixed, sect_size = C.SEGMENT_COMMAND_SIZE, C.SECTION_SIZE
        segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack_from(
            bo + "16sIIIIiiII", body, 8)
    seg = Segment(_fixed_name(segname), vmaddr, vmsize, fileoff, filesize, maxprot, initprot, flags)
    room = (len(body) - fixed) // sect_size
    if nsects > room:
        sl.warnings.append("segment %s declares %d sections but only %d fit" % (seg.name, nsects, room))
        nsects = room
    sfmt = bo + ("16s16sQQIIIIIIII" if is64 else "16s16sIIIIIIIII")
    for i in range(nsects):
        vals = struct.unpack_from(sfmt, body, fixed + i * sect_size)
        sectname, segn, addr, ssize, soff, align = vals[0], vals[1], vals[2], vals[3], vals[4], vals[5]
        sflags = vals[8]
        seg.sections.append(Section(_fixed_name(sectname), _fixed_name(segn), addr, ssize, soff, align, sflags))
    sl.segments.append(seg)


def _parse_dylib(sl: MachOSlice, cmd: int, body: bytes) -> None:
    bo = sl.byte_order
    str_off, timestamp, cur, compat = struct.unpack_from(bo + "IIII", body, 8)
    path = _lc_str(sl, body, str_off)
    if path is None:
        sl.warnings.append("dylib command %s has an invalid name offset" % C.LC_NAMES.get(cmd, hex(cmd)))
        path = ""
    if cmd == C.LC_ID_DYLIB:
        sl.id_dylib = DylibRef(path, C.classify_dylib_path(path), "id", False, C.format_version(cur),
                               C.format_version(compat), timestamp)
        return
    kind = C.DYLIB_LOAD_KINDS[cmd]
    sl.dylibs.append(DylibRef(path, C.classify_dylib_path(path), kind, kind == "weak",
                              C.format_version(cur), C.format_version(compat), timestamp))


def _parse_build_version(sl: MachOSlice, body: bytes) -> None:
    bo = sl.byte_order
    platform, minos, sdk, ntools = struct.unpack_from(bo + "IIII", body, 8)
    room = (len(body) - C.BUILD_VERSION_COMMAND_SIZE) // C.BUILD_TOOL_VERSION_SIZE
    if ntools > room:
        sl.warnings.append("LC_BUILD_VERSION declares %d tools but only %d fit" % (ntools, room))
        ntools = room
    tools = []
    for i in range(ntools):
        tid, ver = struct.unpack_from(bo + "II", body, C.BUILD_VERSION_COMMAND_SIZE + i * C.BUILD_TOOL_VERSION_SIZE)
        tools.append(BuildTool(C.TOOL_NAMES.get(tid, "tool%d" % tid), tid, C.format_version(ver)))
    sl.build_versions.append(BuildVersion(platform, C.platform_name(platform) or "", C.format_version(minos),
                                          C.format_version(sdk), tools))


def _handle_command(sl: MachOSlice, cmd: int, body: bytes) -> None:
    bo = sl.byte_order
    n = len(body)
    if cmd == C.LC_SEGMENT_64 and n >= C.SEGMENT_COMMAND_64_SIZE:
        _parse_segment(sl, body, True)
    elif cmd == C.LC_SEGMENT and n >= C.SEGMENT_COMMAND_SIZE:
        _parse_segment(sl, body, False)
    elif cmd in C.DYLIB_LOAD_KINDS or cmd == C.LC_ID_DYLIB:
        if n >= 24:
            _parse_dylib(sl, cmd, body)
        else:
            sl.warnings.append("%s too small (%d bytes)" % (C.LC_NAMES.get(cmd, hex(cmd)), n))
    elif cmd == C.LC_RPATH and n >= 12:
        (str_off,) = struct.unpack_from(bo + "I", body, 8)
        path = _lc_str(sl, body, str_off)
        if path is not None:
            sl.rpaths.append(path)
    elif cmd == C.LC_LOAD_DYLINKER and n >= 12:
        (str_off,) = struct.unpack_from(bo + "I", body, 8)
        sl.dylinker = _lc_str(sl, body, str_off)
    elif cmd == C.LC_UUID and n >= 24:
        sl.uuid = str(_uuid.UUID(bytes=body[8:24])).upper()
    elif cmd == C.LC_BUILD_VERSION and n >= C.BUILD_VERSION_COMMAND_SIZE:
        _parse_build_version(sl, body)
    elif cmd in C.VERSION_MIN_PLATFORMS and n >= 16:
        version, sdk = struct.unpack_from(bo + "II", body, 8)
        pid = C.VERSION_MIN_PLATFORMS[cmd]
        if sl.version_min is None:
            sl.version_min = BuildVersion(pid, C.platform_name(pid) or "", C.format_version(version),
                                          C.format_version(sdk))
    elif cmd in (C.LC_ENCRYPTION_INFO, C.LC_ENCRYPTION_INFO_64) and n >= 20:
        cryptoff, cryptsize, cryptid = struct.unpack_from(bo + "III", body, 8)
        sl.encryption.append(EncryptionInfo(cmd, cryptoff, cryptsize, cryptid))
    elif cmd == C.LC_SYMTAB and n >= 24:
        symoff, nsyms, stroff, strsize = struct.unpack_from(bo + "IIII", body, 8)
        sl.symtab = SymtabInfo(symoff, nsyms, stroff, strsize)
    elif cmd == C.LC_DYSYMTAB and n >= 32:
        vals = struct.unpack_from(bo + "IIIIII", body, 8)
        sl.dysymtab = DysymtabInfo(*vals)
    elif cmd == C.LC_CODE_SIGNATURE and n >= 16:
        dataoff, datasize = struct.unpack_from(bo + "II", body, 8)
        if sl._code_sig_loc is None:
            sl._code_sig_loc = (dataoff, datasize)
    elif cmd == C.LC_MAIN and n >= 16:
        (sl.entry_offset,) = struct.unpack_from(bo + "Q", body, 8)
    elif cmd == C.LC_SOURCE_VERSION and n >= 16:
        sl.source_version = C.format_source_version(struct.unpack_from(bo + "Q", body, 8)[0])
    elif cmd == C.LC_UNIXTHREAD:
        sl.has_unixthread = True
    elif cmd in (C.LC_DYLD_INFO, C.LC_DYLD_INFO_ONLY):
        sl.has_dyld_info = True
    elif cmd == C.LC_DYLD_CHAINED_FIXUPS:
        sl.has_chained_fixups = True


def _parse_load_commands(sl: MachOSlice, hsize: int) -> None:
    declared = sl.sizeofcmds
    room = max(0, sl.size - hsize)
    if declared > room:
        sl.warnings.append("sizeofcmds %d exceeds the file (%d bytes available)" % (declared, room))
    area = min(declared, room, C.MAX_LC_BYTES)
    if declared > C.MAX_LC_BYTES:
        sl.warnings.append("sizeofcmds %d exceeds the parser limit %d" % (declared, C.MAX_LC_BYTES))
    data = sl.read(hsize, area)
    align = 8 if sl.is_64 else 4
    pos = 0
    count = 0
    while count < sl.ncmds:
        if count >= C.MAX_LOAD_COMMANDS:
            sl.warnings.append("more than %d load commands; remaining ones ignored" % C.MAX_LOAD_COMMANDS)
            break
        if pos + 8 > len(data):
            sl.warnings.append("load commands truncated: parsed %d of %d" % (count, sl.ncmds))
            break
        cmd, cmdsize = struct.unpack_from(sl.byte_order + "II", data, pos)
        if cmdsize < 8:
            sl.warnings.append("load command #%d (0x%x) has invalid cmdsize %d; stopping" % (count, cmd, cmdsize))
            break
        if pos + cmdsize > len(data):
            sl.warnings.append("load command #%d (0x%x) extends past the load command area; stopping" % (count, cmd))
            break
        if cmdsize % align:
            sl.warnings.append("load command #%d (0x%x) cmdsize %d is not %d-byte aligned" % (count, cmd, cmdsize, align))
        sl.load_commands.append(LoadCommand(cmd, cmdsize, hsize + pos, C.LC_NAMES.get(cmd, "LC_0x%x" % cmd)))
        try:
            _handle_command(sl, cmd, data[pos:pos + cmdsize])
        except (struct.error, ValueError) as exc:
            sl.warnings.append("malformed %s: %s" % (C.LC_NAMES.get(cmd, hex(cmd)), exc))
        pos += cmdsize
        count += 1


# --- the file ----------------------------------------------------------------------------------
class MachOFile:
    """A thin Mach-O or fat file. Close it (or use ``with``) to release the mmap."""

    def __init__(self, src: _Source, path: Optional[Path]) -> None:
        self._src = src
        self.path = path
        self.size = src.size
        self.is_fat = False
        self.fat_bits = 0                  # 32 / 64 for fat headers, 0 for thin
        self.slices: List[MachOSlice] = []
        self.warnings: List[str] = []

    def close(self) -> None:
        self._src.close()

    def __enter__(self) -> "MachOFile":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def __del__(self) -> None:  # best effort; explicit close() is the supported way
        try:
            self.close()
        except Exception:  # noqa: BLE001
            pass

    @property
    def all_warnings(self) -> List[str]:
        out = list(self.warnings)
        for sl in self.slices:
            out.extend("%s: %s" % (sl.arch_name, w) for w in sl.warnings)
        return out

    @property
    def arch_names(self) -> List[str]:
        return [s.arch_name for s in self.slices]

    def get_slice(self, arch: str) -> Optional[MachOSlice]:
        want = C.arch_family(arch)
        for sl in self.slices:
            if sl.arch_name == arch or C.arch_family(sl.arch_name) == want:
                return sl
        return None

    def select_slice(self, prefer: Sequence[str] = ("arm64", "arm64e")) -> Optional[MachOSlice]:
        """First slice matching ``prefer`` in order; else the first ARM64-class slice; else the first."""
        for arch in prefer:
            sl = self.get_slice(arch)
            if sl is not None:
                return sl
        for sl in self.slices:
            if sl.cputype in (C.CPU_TYPE_ARM64, C.CPU_TYPE_ARM64_32):
                return sl
        return self.slices[0] if self.slices else None

    @property
    def is_encrypted(self) -> bool:
        return any(s.is_encrypted for s in self.slices)


def _parse_fat(src: _Source, magic_be: int, mf: MachOFile) -> None:
    is64 = magic_be in (C.FAT_MAGIC_64, C.FAT_CIGAM_64)
    bo = ">" if magic_be in (C.FAT_MAGIC, C.FAT_MAGIC_64) else "<"
    hdr = src.read(0, C.FAT_HEADER_SIZE)
    if len(hdr) < C.FAT_HEADER_SIZE:
        raise NotMachO("truncated fat header")
    nfat = struct.unpack_from(bo + "I", hdr, 4)[0]
    if nfat == 0 or nfat > C.MAX_FAT_ARCHS:
        if magic_be == C.FAT_MAGIC and nfat > C.MAX_FAT_ARCHS:
            raise NotMachO("0xCAFEBABE with %d 'architectures': looks like a Java class file" % nfat)
        raise MachOError("implausible fat architecture count %d" % nfat)
    mf.is_fat, mf.fat_bits = True, 64 if is64 else 32
    esize = C.FAT_ARCH_64_SIZE if is64 else C.FAT_ARCH_SIZE
    table_end = C.FAT_HEADER_SIZE + nfat * esize
    table = src.read(C.FAT_HEADER_SIZE, nfat * esize)
    avail = len(table) // esize
    if avail < nfat:
        mf.warnings.append("fat architecture table truncated: %d of %d entries present" % (avail, nfat))
    fmt = bo + ("iiQQII" if is64 else "iiIII")
    bounds_problem = False
    for i in range(avail):
        vals = struct.unpack_from(fmt, table, i * esize)
        cputype, cpusubtype, off, size = vals[0] & 0xFFFFFFFF, vals[1] & 0xFFFFFFFF, vals[2], vals[3]
        label = C.arch_name(cputype, cpusubtype)
        if size == 0 or off < table_end or off >= src.size:
            mf.warnings.append("fat slice %d (%s): offset %d / size %d outside the file; skipped" % (i, label, off, size))
            bounds_problem = True
            continue
        if off + size > src.size:
            mf.warnings.append("fat slice %d (%s) is truncated: needs %d bytes, file ends at %d" % (
                i, label, off + size, src.size))
            size = src.size - off
        try:
            sl = _parse_slice(src, off, size, (cputype, cpusubtype))
        except NotMachO as exc:
            mf.warnings.append("fat slice %d (%s) is not a Mach-O file (%s); skipped" % (i, label, exc))
            continue
        except MachOError as exc:
            mf.warnings.append("fat slice %d (%s) unreadable: %s; skipped" % (i, label, exc))
            bounds_problem = True
            continue
        mf.slices.append(sl)
    if not mf.slices:
        msg = "fat file without a readable Mach-O slice"
        raise (MachOError if bounds_problem else NotMachO)("%s (%s)" % (msg, "; ".join(mf.warnings[-3:])))


def parse(source: BinarySource) -> MachOFile:
    """Parse a thin or fat Mach-O from a path, bytes-like object or binary file object.

    Raises :class:`NotMachO` for non-Mach-O data and :class:`MachOError` if nothing readable remains.
    The returned object owns the file mapping; close it (``with parse(p) as mf``) when done.
    """
    src, path = _open_source(source)
    mf = MachOFile(src, path)
    try:
        head = src.read(0, 4)
        if len(head) < 4:
            raise NotMachO("file shorter than a Mach-O magic (%d bytes)" % len(head))
        magic_be = struct.unpack(">I", head)[0]
        if magic_be in (C.FAT_MAGIC, C.FAT_MAGIC_64, C.FAT_CIGAM, C.FAT_CIGAM_64):
            _parse_fat(src, magic_be, mf)
        else:
            mf.slices.append(_parse_slice(src, 0, src.size))
        return mf
    except BaseException:
        mf.close()
        raise
