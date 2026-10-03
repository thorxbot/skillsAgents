"""Minimal ``ZipSource`` for the WP0 skeleton (WP1 replaces it; the interface is frozen)."""
from __future__ import annotations

import shutil
import stat as _stat
import zipfile
from pathlib import Path
from typing import BinaryIO, Dict, List

from ..errors import InvalidInput
from . import EntryInfo


class ZipSource:
    kind = "zip"

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        try:
            self._zf = zipfile.ZipFile(self.path)
        except (zipfile.BadZipFile, OSError) as exc:
            raise InvalidInput("not a readable zip/ipa: %s (%s)" % (self.path, exc)) from exc
        self._entries: Dict[str, EntryInfo] = {}
        for zi in self._zf.infolist():
            mode = (zi.external_attr >> 16) & 0xFFFF
            self._entries[zi.filename] = EntryInfo(
                name=zi.filename, size=zi.file_size, compressed_size=zi.compress_size,
                is_dir=zi.is_dir(), is_symlink=_stat.S_ISLNK(mode), crc=zi.CRC, mode=mode)

    def namelist(self) -> List[EntryInfo]:
        return list(self._entries.values())

    def stat(self, name: str) -> EntryInfo:
        return self._entries[name]

    def open(self, name: str) -> BinaryIO:
        if name not in self._entries:
            raise KeyError(name)
        return self._zf.open(name)  # type: ignore[return-value]

    def read_head(self, name: str, n: int) -> bytes:
        with self.open(name) as fh:
            return fh.read(n)

    def extract_to(self, name: str, dest: Path) -> Path:
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with self.open(name) as src, open(dest, "wb") as out:
            shutil.copyfileobj(src, out, 1024 * 1024)
        return dest

    def close(self) -> None:
        self._zf.close()
