"""``ArchiveSource`` implementations: ``ZipSource`` (own central-directory reader) and ``DirSource``.

``ZipSource`` reads only the central directory up front and decompresses entries lazily, so a 4 GB
IPA is never unpacked as a whole. It is written against the PKWARE APPNOTE (ZIP 6.3.x) rather than
``zipfile`` because the analyzer must keep going on archives that ``zipfile`` rejects or mangles:
file names with bad encodings, duplicate entries, prepended data, zip64, truncated tails.
Only stored (0) and deflate (8) entries can be read; other methods raise ``InvalidInput`` on access.

Nothing here executes archive content, and nothing is written outside the destination passed to
``extract_to`` (the caller picks a safe destination, see ``safe_extract``).
"""
from __future__ import annotations

import io
import logging
import os
import shutil
import stat as _stat
import struct
import tempfile
import weakref
import zlib
from pathlib import Path
from typing import BinaryIO, Dict, List, Optional, Tuple

from ..errors import InvalidInput, LimitExceeded
from ..util.magic import sniff
from ..util.paths import to_long_path
from . import EntryInfo

log = logging.getLogger(__name__)

__all__ = ["ZipSource", "DirSource", "open_source"]

MiB = 1024 * 1024
# Source: PKWARE APPNOTE.TXT 6.3.x section 4.3 (record layouts) and 4.5 (zip64 / extra fields).
_SIG_EOCD = b"PK\x05\x06"
_SIG_LOC64 = b"PK\x06\x07"
_SIG_EOCD64 = b"PK\x06\x06"
_SIG_CD = b"PK\x01\x02"
_SIG_LH = b"PK\x03\x04"
_EOCD = struct.Struct("<4s4H2LH")            # 22 bytes
_LOC64 = struct.Struct("<4sLQL")             # 20 bytes
_EOCD64 = struct.Struct("<4sQ2H2L4Q")        # 56 bytes
_CD = struct.Struct("<4s4B4HL2L5H2L")        # 46 bytes
_LH = struct.Struct("<4s5HL2L2H")            # 30 bytes
_MAX_COMMENT = 0xFFFF
_MAX_CD_BYTES = 512 * MiB
_CHUNK = 64 * 1024

# "version made by" high byte (host system), APPNOTE 4.4.2: 0 MS-DOS/FAT, 10 NTFS, 14 VFAT.
_DOS_SYSTEMS = (0, 10, 14)
_FLAG_ENCRYPTED = 0x1
_FLAG_UTF8 = 0x800
_STORED, _DEFLATED = 0, 8


# --- seekable entry readers --------------------------------------------------------------------
class _StoredReader(io.RawIOBase):
    """Window ``[start, start+size)`` of an open file (stored entries: seeking is free)."""

    def __init__(self, fh: BinaryIO, start: int, size: int) -> None:
        super().__init__()
        self._fh, self._start, self._size, self._pos = fh, start, size, 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def readinto(self, b) -> int:  # type: ignore[override]
        n = min(len(b), self._size - self._pos)
        if n <= 0:
            return 0
        self._fh.seek(self._start + self._pos)
        got = self._fh.readinto(memoryview(b)[:n]) or 0
        self._pos += got
        return got

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        base = {os.SEEK_SET: 0, os.SEEK_CUR: self._pos, os.SEEK_END: self._size}[whence]
        self._pos = max(0, base + offset)
        return self._pos

    def close(self) -> None:
        if not self.closed:
            try:
                self._fh.close()
            finally:
                super().close()


class _DeflateReader(io.RawIOBase):
    """Streaming inflate of one entry with seek support.

    Sequential reads stream. A backward seek restarts the stream, except that small entries
    (``<= memory_limit``) or, if a ``spill_dir`` is set, entries up to ``spill_limit`` are
    decompressed once into memory / a temporary file so that random access stays cheap.
    The decompressed size may never exceed the declared size (guards against lying headers).
    """

    def __init__(self, fh: BinaryIO, start: int, csize: int, usize: int, *, name: str,
                 memory_limit: int, spill_dir: Optional[Path], spill_limit: int) -> None:
        super().__init__()
        self._fh, self._start, self._csize, self._usize = fh, start, csize, usize
        self._name = name
        self._memory_limit, self._spill_dir, self._spill_limit = memory_limit, spill_dir, spill_limit
        self._mat: Optional[BinaryIO] = None
        self._reset()

    def _reset(self) -> None:
        self._d = zlib.decompressobj(-15)      # raw deflate
        self._cpos = 0
        self._pos = 0
        self._produced = 0
        self._pending = b""

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def _next_chunk(self) -> Optional[bytes]:
        d = self._d
        while True:
            if d.eof:
                return None
            if d.unconsumed_tail:
                data = d.unconsumed_tail
            elif self._cpos < self._csize:
                self._fh.seek(self._start + self._cpos)
                data = self._fh.read(min(_CHUNK, self._csize - self._cpos))
                if not data:
                    raise InvalidInput("truncated archive: entry data of %r ends early" % self._name)
                self._cpos += len(data)
            else:
                raise InvalidInput("truncated or corrupt deflate stream in entry %r" % self._name)
            try:
                out = d.decompress(data, _CHUNK)
            except zlib.error as exc:
                raise InvalidInput("corrupt deflate data in entry %r (%s)" % (self._name, exc)) from exc
            if out:
                self._produced += len(out)
                if self._produced > self._usize:
                    raise InvalidInput("entry %r expands beyond its declared size %d (corrupt archive or "
                                       "decompression bomb)" % (self._name, self._usize))
                return out

    def readinto(self, b) -> int:  # type: ignore[override]
        if self._mat is not None:
            return self._mat.readinto(b) or 0
        want = min(len(b), self._usize - self._pos)
        if want <= 0:
            return 0
        got = 0
        mv = memoryview(b)
        while got < want:
            if not self._pending:
                chunk = self._next_chunk()
                if chunk is None:
                    if self._produced < self._usize:
                        raise InvalidInput("entry %r is shorter than its declared size (%d < %d)"
                                           % (self._name, self._produced, self._usize))
                    break
                self._pending = chunk
            take = min(len(self._pending), want - got)
            mv[got:got + take] = self._pending[:take]
            self._pending = self._pending[take:]
            got += take
        self._pos += got
        return got

    def tell(self) -> int:
        return self._mat.tell() if self._mat is not None else self._pos

    def _materialize(self, target: BinaryIO) -> None:
        self._reset()
        while True:
            chunk = self._next_chunk()
            if chunk is None:
                break
            target.write(chunk)
        if self._produced < self._usize:
            raise InvalidInput("entry %r is shorter than its declared size" % self._name)
        target.seek(0)
        self._mat = target
        try:
            self._fh.close()
        except OSError:
            pass

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        cur = self.tell()
        base = {os.SEEK_SET: 0, os.SEEK_CUR: cur, os.SEEK_END: self._usize}[whence]
        target = min(max(0, base + offset), self._usize)
        if self._mat is not None:
            return self._mat.seek(target)
        if target < self._pos:
            if self._usize <= self._memory_limit:
                self._materialize(io.BytesIO())
                return self._mat.seek(target)   # type: ignore[union-attr]
            if self._spill_dir is not None and self._usize <= self._spill_limit:
                Path(self._spill_dir).mkdir(parents=True, exist_ok=True)
                self._materialize(tempfile.TemporaryFile(dir=str(self._spill_dir)))
                return self._mat.seek(target)   # type: ignore[union-attr]
            self._reset()
        while self._pos < target:               # forward: decompress and discard
            skipped = self.readinto(bytearray(min(_CHUNK, target - self._pos)))
            if skipped == 0:
                break
        return self._pos

    def close(self) -> None:
        if not self.closed:
            try:
                if self._mat is not None:
                    self._mat.close()
                self._fh.close()
            finally:
                super().close()


# --- ZipSource ----------------------------------------------------------------------------------
class _ZEntry:
    __slots__ = ("info", "hoff", "method", "flags", "data_off")

    def __init__(self, info: EntryInfo, hoff: int, method: int, flags: int) -> None:
        self.info, self.hoff, self.method, self.flags = info, hoff, method, flags
        self.data_off: Optional[int] = None


def _parse_extra(extra: bytes) -> Dict[int, bytes]:
    out: Dict[int, bytes] = {}
    i = 0
    while i + 4 <= len(extra):
        hid, ln = struct.unpack_from("<HH", extra, i)
        i += 4
        if i + ln > len(extra):
            break
        out.setdefault(hid, extra[i:i + ln])
        i += ln
    return out


class ZipSource:
    """Read-only zip / ipa archive; see the module docstring."""

    kind = "zip"

    def __init__(self, path: "Path | str", *, max_entries: Optional[int] = None,
                 memory_limit: int = 8 * MiB, spill_dir: Optional[Path] = None,
                 spill_limit: int = 1024 * MiB) -> None:
        self.path = Path(path)
        self.warnings: List[str] = []
        self.encrypted_entries = 0
        self.duplicate_entries = 0
        self.fallback_names = 0
        self._memory_limit = memory_limit
        self._spill_dir = Path(spill_dir) if spill_dir else None
        self._spill_limit = spill_limit
        self._entries: Dict[str, _ZEntry] = {}
        self._streams: "weakref.WeakSet[io.RawIOBase]" = weakref.WeakSet()
        self._closed = False
        try:
            self._fsize = self.path.stat().st_size
            with open(to_long_path(self.path), "rb") as fh:
                self._read_directory(fh, max_entries)
        except OSError as exc:
            raise InvalidInput("cannot read %s: %s" % (self.path, exc)) from exc

    # -- configuration ---------------------------------------------------------------------------
    def set_spill_dir(self, path: Optional[Path]) -> None:
        """Directory for temporary decompressed copies of large entries that are accessed randomly."""
        self._spill_dir = Path(path) if path else None

    # -- central directory -------------------------------------------------------------------------
    def _read_directory(self, fh: BinaryIO, max_entries: Optional[int]) -> None:
        fsize = self._fsize
        tail_len = min(fsize, _MAX_COMMENT + _EOCD.size)
        fh.seek(fsize - tail_len)
        tail = fh.read(tail_len)
        pos = tail.rfind(_SIG_EOCD)
        if pos < 0 or len(tail) - pos < _EOCD.size:
            raise InvalidInput("not a zip archive or truncated file: end of central directory record not found "
                               "in %s" % self.path)
        eocd_off = fsize - tail_len + pos
        (_s, disk, cd_disk, _n_disk, n_total, cd_size, cd_off, clen) = _EOCD.unpack_from(tail, pos)
        if len(tail) - pos - _EOCD.size != clen:
            self.warnings.append("zip comment length does not match the end of file")
        zip64 = False
        if eocd_off >= _LOC64.size:
            fh.seek(eocd_off - _LOC64.size)
            loc = fh.read(_LOC64.size)
            if len(loc) == _LOC64.size and loc[:4] == _SIG_LOC64:
                _ls, _ld, off64, _total = _LOC64.unpack(loc)
                rec = None
                for cand in (off64, eocd_off - _LOC64.size - _EOCD64.size):
                    if 0 <= cand <= fsize - _EOCD64.size:
                        fh.seek(cand)
                        raw = fh.read(_EOCD64.size)
                        if len(raw) == _EOCD64.size and raw[:4] == _SIG_EOCD64:
                            rec = _EOCD64.unpack(raw)
                            break
                if rec is None:
                    raise InvalidInput("corrupt zip64 end of central directory record in %s" % self.path)
                (_s, _sz, _vm, _vn, disk, cd_disk, _n_disk, n_total, cd_size, cd_off) = rec
                zip64 = True
        if not zip64 and (n_total == 0xFFFF or cd_size == 0xFFFFFFFF or cd_off == 0xFFFFFFFF):
            raise InvalidInput("zip64 archive without zip64 end records (truncated?): %s" % self.path)
        if disk != 0 or cd_disk != 0:
            raise InvalidInput("multi-disk (spanned) zip archives are not supported: %s" % self.path)
        concat = eocd_off - cd_size - cd_off          # bytes prepended to the archive (self-extractors)
        if zip64:
            concat -= _EOCD64.size + _LOC64.size
        if concat < 0 or cd_off + concat + cd_size > fsize:
            raise InvalidInput("truncated or corrupt zip: central directory lies outside the file (%s)" % self.path)
        if cd_size > _MAX_CD_BYTES:
            raise InvalidInput("central directory implausibly large (%d bytes)" % cd_size)
        if concat:
            self.warnings.append("%d bytes of data precede the zip structure (self-extracting archive?)" % concat)
        fh.seek(cd_off + concat)
        cd = fh.read(cd_size)
        if len(cd) != cd_size:
            raise InvalidInput("truncated zip: central directory is cut off in %s" % self.path)
        self._parse_cd(cd, concat, n_total, max_entries)

    def _decode_name(self, raw: bytes, flags: int, extra: Dict[int, bytes]) -> str:
        up = extra.get(0x7075)    # Info-ZIP Unicode Path extra field: version, crc32 of the header name, utf-8 name
        if up is not None and len(up) > 5 and up[0] == 1 and struct.unpack_from("<L", up, 1)[0] == (zlib.crc32(raw) & 0xFFFFFFFF):
            try:
                return up[5:].decode("utf-8")
            except UnicodeDecodeError:
                pass
        try:
            return raw.decode("ascii") if not (flags & _FLAG_UTF8) and raw.isascii() else raw.decode("utf-8")
        except UnicodeDecodeError:
            pass
        # Bit 11 clear: APPNOTE says CP437, but most tools write UTF-8 anyway (tried above). Bit 11 set but
        # invalid UTF-8, or neither: fall back to CP437 (never fails) and remember it.
        self.fallback_names += 1
        return raw.decode("cp437")

    def _parse_cd(self, cd: bytes, concat: int, n_total: int, max_entries: Optional[int]) -> None:
        off, end, count = 0, len(cd), 0
        backslash = 0
        while off < end:
            if end - off < _CD.size or cd[off:off + 4] != _SIG_CD:
                raise InvalidInput("corrupt central directory (bad record #%d at offset %d) in %s"
                                   % (count, off, self.path))
            (_s, _vm, system, _vn, _vns, flags, method, _mt, _md, crc, csize, usize, nlen, elen, clen, disk,
             _iattr, eattr, hoff) = _CD.unpack_from(cd, off)
            body = off + _CD.size
            if body + nlen + elen + clen > end:
                raise InvalidInput("corrupt central directory (record #%d overruns)" % count)
            raw_name = cd[body:body + nlen]
            extra = _parse_extra(cd[body + nlen:body + nlen + elen])
            off = body + nlen + elen + clen
            count += 1
            if max_entries is not None and count > max_entries:
                raise LimitExceeded("archive has more than %d entries (limit max_files); refusing to process"
                                    % max_entries)
            z64 = extra.get(0x0001)
            if z64 is not None:
                p = 0
                try:
                    if usize == 0xFFFFFFFF:
                        usize = struct.unpack_from("<Q", z64, p)[0]
                        p += 8
                    if csize == 0xFFFFFFFF:
                        csize = struct.unpack_from("<Q", z64, p)[0]
                        p += 8
                    if hoff == 0xFFFFFFFF:
                        hoff = struct.unpack_from("<Q", z64, p)[0]
                        p += 8
                except struct.error:
                    raise InvalidInput("corrupt zip64 extra field in record #%d" % (count - 1)) from None
            name = self._decode_name(raw_name, flags, extra)
            mode = (eattr >> 16) & 0xFFFF
            if system in _DOS_SYSTEMS and "\\" in name:
                name = name.replace("\\", "/")
                backslash += 1
            while name.startswith("./"):
                name = name[2:]
            if not name:
                continue
            is_dir = name.endswith("/") or _stat.S_ISDIR(mode) or bool(eattr & 0x10 and usize == 0)
            if is_dir and not name.endswith("/"):
                name += "/"
            info = EntryInfo(name=name, size=usize, compressed_size=csize, is_dir=is_dir,
                             is_symlink=_stat.S_ISLNK(mode) and not is_dir, crc=crc, mode=mode)
            if name in self._entries:
                self.duplicate_entries += 1
            if flags & _FLAG_ENCRYPTED:
                self.encrypted_entries += 1
            self._entries[name] = _ZEntry(info, hoff + concat, method, flags)
        if count != n_total and n_total != 0xFFFF:
            self.warnings.append("central directory lists %d entries but the end record says %d" % (count, n_total))
        if self.fallback_names:
            self.warnings.append("%d entry name(s) are not valid UTF-8 and were decoded as CP437 (names may look "
                                 "garbled)" % self.fallback_names)
        if self.duplicate_entries:
            self.warnings.append("%d duplicate entry name(s) in the archive; the last occurrence wins"
                                 % self.duplicate_entries)
        if backslash:
            self.warnings.append("%d entry name(s) used backslash separators and were normalised" % backslash)
        if self.encrypted_entries:
            self.warnings.append("%d entry(ies) are password-protected and cannot be read" % self.encrypted_entries)

    # -- ArchiveSource -----------------------------------------------------------------------------
    def namelist(self) -> List[EntryInfo]:
        return [e.info for e in self._entries.values()]

    def stat(self, name: str) -> EntryInfo:
        return self._entries[name].info

    def _raw(self, name: str) -> io.RawIOBase:
        ent = self._entries[name]
        info = ent.info
        if self._closed:
            raise ValueError("source is closed")
        if info.is_dir or info.size == 0:
            return _StoredReader(io.BytesIO(b""), 0, 0)
        if ent.flags & _FLAG_ENCRYPTED:
            raise InvalidInput("entry %r is password-protected" % name)
        if ent.method not in (_STORED, _DEFLATED):
            raise InvalidInput("entry %r uses unsupported compression method %d" % (name, ent.method))
        fh = open(to_long_path(self.path), "rb")
        try:
            if ent.data_off is None:
                fh.seek(ent.hoff)
                raw = fh.read(_LH.size)
                if len(raw) != _LH.size or raw[:4] != _SIG_LH:
                    raise InvalidInput("corrupt or truncated archive: bad local header for %r" % name)
                nlen, elen = struct.unpack_from("<HH", raw, 26)
                ent.data_off = ent.hoff + _LH.size + nlen + elen
            need = info.size if ent.method == _STORED else info.compressed_size
            if ent.data_off + need > self._fsize:
                raise InvalidInput("truncated archive: data of %r extends beyond the end of the file" % name)
            if ent.method == _STORED:
                rd: io.RawIOBase = _StoredReader(fh, ent.data_off, info.size)
            else:
                rd = _DeflateReader(fh, ent.data_off, info.compressed_size, info.size, name=name,
                                    memory_limit=self._memory_limit, spill_dir=self._spill_dir,
                                    spill_limit=self._spill_limit)
        except BaseException:
            fh.close()
            raise
        self._streams.add(rd)
        return rd

    def open(self, name: str) -> BinaryIO:
        """Seekable stream (see ``_DeflateReader`` for the cost of backward seeks on deflated entries)."""
        if name not in self._entries:
            raise KeyError(name)
        return io.BufferedReader(self._raw(name), buffer_size=_CHUNK)  # type: ignore[return-value]

    def read_head(self, name: str, n: int) -> bytes:
        if name not in self._entries:
            raise KeyError(name)
        info = self._entries[name].info
        n = min(n, info.size)
        if n <= 0:
            return b""
        buf = bytearray(n)
        mv = memoryview(buf)
        got = 0
        with self._raw(name) as raw:
            while got < n:
                r = raw.readinto(mv[got:])
                if not r:
                    break
                got += r
        return bytes(buf[:got])

    def symlink_target(self, name: str) -> str:
        """Target path stored in a symlink entry (zip stores it as the entry content)."""
        return self.read_head(name, 4096).decode("utf-8", "replace")

    def extract_to(self, name: str, dest: Path) -> Path:
        """Write the entry to ``dest`` verifying size and CRC-32; a partial file is removed on failure."""
        ent = self._entries[name]
        dest = Path(dest)
        if ent.info.is_dir:
            os.makedirs(to_long_path(dest), exist_ok=True)
            return dest
        os.makedirs(to_long_path(dest.parent), exist_ok=True)
        crc, total = 0, 0
        try:
            with self._raw(name) as raw, open(to_long_path(dest), "wb") as out:
                buf = bytearray(1 * MiB)
                while True:
                    r = raw.readinto(buf)
                    if not r:
                        break
                    view = memoryview(buf)[:r]
                    crc = zlib.crc32(view, crc)
                    total += r
                    out.write(view)
            if total != ent.info.size or (crc & 0xFFFFFFFF) != ent.info.crc:
                raise InvalidInput("entry %r failed verification (size %d/%d, crc %08x/%08x): corrupt or "
                                   "truncated archive" % (name, total, ent.info.size, crc & 0xFFFFFFFF, ent.info.crc))
        except BaseException:
            try:
                os.unlink(to_long_path(dest))
            except OSError:
                pass
            raise
        return dest

    def close(self) -> None:
        self._closed = True
        for s in list(self._streams):
            try:
                s.close()
            except Exception:  # noqa: BLE001
                log.debug("closing stream failed", exc_info=True)
        self._streams.clear()


# --- DirSource ----------------------------------------------------------------------------------
class DirSource:
    """A directory tree (an ``.app``, a folder containing ``Payload/``, or an extracted IPA).

    Symlinks are listed (``is_symlink=True``) but never followed; their content is the link target.
    """

    kind = "dir"

    def __init__(self, path: "Path | str", *, max_entries: Optional[int] = None) -> None:
        self.path = Path(path)
        self.warnings: List[str] = []
        self._entries: Dict[str, EntryInfo] = {}
        self._real: Dict[str, str] = {}
        if not self.path.is_dir():
            raise InvalidInput("not a directory: %s" % self.path)
        try:
            self._scan(max_entries)
        except OSError as exc:
            raise InvalidInput("cannot read directory %s: %s" % (self.path, exc)) from exc

    @staticmethod
    def _listing(path: str) -> List["os.DirEntry[str]"]:
        with os.scandir(path) as it:
            return sorted(it, key=lambda e: e.name)

    def _scan(self, max_entries: Optional[int]) -> None:
        stack = [iter(self._listing(to_long_path(self.path)))]
        prefixes = [""]
        count = 0
        bad_names = 0
        while stack:
            try:
                e = next(stack[-1])
            except StopIteration:
                stack.pop()
                prefixes.pop()
                continue
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                self.warnings.append("cannot stat %s" % e.path)
                continue
            display = e.name
            try:
                display.encode("utf-8")
            except UnicodeEncodeError:       # undecodable bytes in the file system name (surrogate escapes)
                display = display.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
                bad_names += 1
            name = prefixes[-1] + display
            mode = st.st_mode
            count += 1
            if max_entries is not None and count > max_entries:
                raise LimitExceeded("directory has more than %d entries (limit max_files); refusing to process"
                                    % max_entries)
            if e.is_symlink():
                self._entries[name] = EntryInfo(name=name, size=st.st_size, compressed_size=st.st_size,
                                                is_symlink=True, mode=mode)
                self._real[name] = e.path
            elif _stat.S_ISDIR(mode):
                self._entries[name + "/"] = EntryInfo(name=name + "/", size=0, is_dir=True, mode=mode)
                self._real[name + "/"] = e.path
                stack.append(iter(self._listing(e.path)))
                prefixes.append(name + "/")
            elif _stat.S_ISREG(mode):
                self._entries[name] = EntryInfo(name=name, size=st.st_size, compressed_size=st.st_size, mode=mode)
                self._real[name] = e.path
        if bad_names:
            self.warnings.append("%d file name(s) are not valid Unicode and were shown with replacement characters"
                                 % bad_names)

    def namelist(self) -> List[EntryInfo]:
        return list(self._entries.values())

    def stat(self, name: str) -> EntryInfo:
        return self._entries[name]

    def open(self, name: str) -> BinaryIO:
        info = self._entries[name]
        if info.is_dir:
            return io.BytesIO(b"")  # type: ignore[return-value]
        if info.is_symlink:
            return io.BytesIO(self.symlink_target(name).encode("utf-8"))  # type: ignore[return-value]
        return open(to_long_path(self._real[name]), "rb")

    def read_head(self, name: str, n: int) -> bytes:
        with self.open(name) as fh:
            return fh.read(max(0, n))

    def symlink_target(self, name: str) -> str:
        return os.fsdecode(os.readlink(self._real[name]))

    def extract_to(self, name: str, dest: Path) -> Path:
        info = self._entries[name]
        dest = Path(dest)
        if info.is_dir:
            os.makedirs(to_long_path(dest), exist_ok=True)
            return dest
        os.makedirs(to_long_path(dest.parent), exist_ok=True)
        if info.is_symlink:
            with open(to_long_path(dest), "wb") as out:
                out.write(self.symlink_target(name).encode("utf-8"))
        else:
            shutil.copyfile(to_long_path(self._real[name]), to_long_path(dest))
        return dest

    def close(self) -> None:
        return None


# --- factory ------------------------------------------------------------------------------------
def _tail_has_eocd(path: Path) -> bool:
    size = path.stat().st_size
    n = min(size, _MAX_COMMENT + _EOCD.size)
    with open(to_long_path(path), "rb") as fh:
        fh.seek(size - n)
        return _SIG_EOCD in fh.read(n)


def open_source(path: "Path | str", *, limits: Optional[object] = None) -> "ZipSource | DirSource":
    """Open ``path`` (a zip/ipa file or a directory) as an ``ArchiveSource``.

    The file type is decided by content, not by extension. ``limits`` (a ``LimitsConfig``) supplies
    ``max_files``. Raises ``InvalidInput`` for missing, empty, unreadable or unsupported input.
    """
    p = Path(path)
    max_entries = getattr(limits, "max_files", None)
    if not p.exists():
        raise InvalidInput("input does not exist: %s" % p)
    if p.is_dir():
        return DirSource(p, max_entries=max_entries)
    if not p.is_file():
        raise InvalidInput("input is not a regular file or directory: %s" % p)
    try:
        size = p.stat().st_size
        if size == 0:
            raise InvalidInput("input file is empty: %s" % p)
        with open(to_long_path(p), "rb") as fh:
            head = fh.read(64)
        kind, _conf = sniff(head)
        if kind == "zip" or _tail_has_eocd(p):
            return ZipSource(p, max_entries=max_entries)
    except OSError as exc:
        raise InvalidInput("cannot read %s: %s" % (p, exc)) from exc
    raise InvalidInput("unsupported input %s (detected type: %s); expected an .ipa/.zip archive, an .app "
                       "directory or an extracted IPA directory" % (p, kind))
