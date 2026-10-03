"""Programmatic zip / IPA construction for tests (no real app content is ever stored).

Public, stable entry point::

    build_ipa(path, files, *, app_name="Test", symlinks=None, zip64=False)

``files`` maps names *relative to the .app bundle* (``"Info.plist"``, ``"Frameworks/X.framework/X"``) to
``bytes`` or ``str``; the entries are written below ``Payload/<app_name>.app/``. A key that already starts
with ``Payload/`` is used as the archive name unchanged. ``symlinks`` maps a name (relative to the .app) to
its link target. ``zip64=True`` writes zip64 central-directory records and end records.

Extra keyword arguments for hostile-input fixtures: ``raw_files`` (``{archive_name: bytes}`` with names used
verbatim, ``str`` or raw ``bytes``), ``payload=False`` (no ``Payload/<app>.app/`` prefix at all),
``compress`` (deflate, default True) and ``prefix_junk`` (bytes written before the zip, like a
self-extractor).

The writer is hand-rolled (not ``zipfile``) so that fixtures can contain things ``zipfile`` refuses to
write: raw non-UTF-8 names without the UTF-8 flag, duplicate names, zip64 records for tiny files.
"""
from __future__ import annotations

import stat as _stat
import struct
import zlib
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Tuple, Union

__all__ = ["build_ipa", "ZipBuilder", "build_zip_bytes"]

Data = Union[bytes, str]


def _b(data: Data) -> bytes:
    return data if isinstance(data, bytes) else str(data).encode("utf-8")


class ZipBuilder:
    """Minimal zip writer supporting stored / deflate, zip64 records and raw names."""

    def __init__(self, *, zip64: bool = False, compress: bool = True) -> None:
        self.zip64 = zip64
        self.compress = compress
        self._buf = bytearray()
        self._cd: List[bytes] = []
        self._count = 0

    def add(self, name: Union[str, bytes], data: bytes = b"", *, compress: Optional[bool] = None, mode: int = 0o100644,
            utf8_flag: Optional[bool] = None, system: int = 3, is_dir: bool = False,
            comp_data: Optional[bytes] = None, method: Optional[int] = None) -> None:
        """Append one entry. ``comp_data`` / ``method`` override the stored payload (for corrupt fixtures)."""
        raw = name.encode("utf-8") if isinstance(name, str) else bytes(name)
        if utf8_flag is None:
            utf8_flag = isinstance(name, str) and not raw.isascii()
        flags = 0x800 if utf8_flag else 0
        if is_dir:
            data, mode = b"", (mode if _stat.S_ISDIR(mode) else 0o040755)
        crc = zlib.crc32(data) & 0xFFFFFFFF
        use = self.compress if compress is None else compress
        if comp_data is not None:
            payload, meth = comp_data, (8 if method is None else method)
        elif use and data:
            co = zlib.compressobj(6, zlib.DEFLATED, -15)
            payload, meth = co.compress(data) + co.flush(), 8
        else:
            payload, meth = data, 0
        offset = len(self._buf)
        usize, csize = len(data), len(payload)
        if self.zip64:
            lextra = struct.pack("<HHQQ", 1, 16, usize, csize)
            lh = struct.pack("<4sHHHHHLLLHH", b"PK\x03\x04", 45, flags, meth, 0, 0x21, crc, 0xFFFFFFFF, 0xFFFFFFFF,
                             len(raw), len(lextra))
            cextra = struct.pack("<HHQQQ", 1, 24, usize, csize, offset)
            cd = struct.pack("<4sBBHHHHHLLLHHHHHLL", b"PK\x01\x02", 45, system, 45, flags, meth, 0, 0x21, crc,
                             0xFFFFFFFF, 0xFFFFFFFF, len(raw), len(cextra), 0, 0, 0, (mode & 0xFFFF) << 16, 0xFFFFFFFF)
            self._buf += lh + raw + lextra + payload
            self._cd.append(cd + raw + cextra)
        else:
            lh = struct.pack("<4sHHHHHLLLHH", b"PK\x03\x04", 20, flags, meth, 0, 0x21, crc, csize, usize, len(raw), 0)
            cd = struct.pack("<4sBBHHHHHLLLHHHHHLL", b"PK\x01\x02", 20, system, 20, flags, meth, 0, 0x21, crc, csize,
                             usize, len(raw), 0, 0, 0, 0, (mode & 0xFFFF) << 16, offset)
            self._buf += lh + raw + payload
            self._cd.append(cd + raw)
        self._count += 1

    def finish(self, *, prefix_junk: bytes = b"", comment: bytes = b"") -> bytes:
        cd_off = len(self._buf)
        cd = b"".join(self._cd)
        out = bytearray(self._buf) + cd
        end = len(out)
        if self.zip64:
            out += struct.pack("<4sQHHLLQQQQ", b"PK\x06\x06", 44, 45, 45, 0, 0, self._count, self._count, len(cd), cd_off)
            out += struct.pack("<4sLQL", b"PK\x06\x07", 0, end, 1)
            out += struct.pack("<4sHHHHLLH", b"PK\x05\x06", 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
                               len(comment))
        else:
            out += struct.pack("<4sHHHHLLH", b"PK\x05\x06", 0, 0, self._count, self._count, len(cd), cd_off,
                               len(comment))
        out += comment
        return prefix_junk + bytes(out)


def build_zip_bytes(entries: Mapping[Union[str, bytes], Data], **kw: object) -> bytes:
    """Zip with the given ``{archive_name: data}`` entries (names verbatim; a trailing ``/`` makes a directory)."""
    zb = ZipBuilder(zip64=bool(kw.pop("zip64", False)), compress=bool(kw.pop("compress", True)))
    for n, d in entries.items():
        is_dir = (n.endswith("/") if isinstance(n, str) else n.endswith(b"/"))
        zb.add(n, b"" if is_dir else _b(d), is_dir=is_dir)
    return zb.finish(**kw)  # type: ignore[arg-type]


def build_ipa(path: Union[str, Path], files: Mapping[str, Data], *, app_name: str = "Test",
              symlinks: Optional[Mapping[str, str]] = None, zip64: bool = False,
              raw_files: Optional[Mapping[Union[str, bytes], Data]] = None, payload: bool = True,
              compress: bool = True, prefix_junk: bytes = b"") -> Path:
    """Write an IPA-like zip at ``path`` and return it. See the module docstring."""
    prefix = "Payload/%s.app/" % app_name if payload else ""
    zb = ZipBuilder(zip64=zip64, compress=compress)
    if payload:
        zb.add("Payload/", is_dir=True)
        zb.add(prefix, is_dir=True)
    for name, data in files.items():
        full = name if name.startswith("Payload/") else prefix + name
        zb.add(full, _b(data))
    for name, target in (symlinks or {}).items():
        zb.add(prefix + name, target.encode("utf-8"), mode=_stat.S_IFLNK | 0o755, compress=False)
    for name, data in (raw_files or {}).items():
        zb.add(name, _b(data))
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(zb.finish(prefix_junk=prefix_junk))
    return p
