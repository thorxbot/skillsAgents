"""Input abstraction: ``ArchiveSource`` Protocol (frozen contract) and ``EntryInfo``.

WP1 supplies the real ``ZipSource`` / ``DirSource`` / ``open_source``; WP0 ships only a minimal
``ZipSource`` (``minimal_zip.py``) so the skeleton can be smoke-tested. WP1 may rewrite
``minimal_zip.py`` / add modules and update the lazy re-exports below, but must keep the
Protocol, ``EntryInfo`` and the exported names stable.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, List, Optional, Protocol, runtime_checkable

__all__ = ["EntryInfo", "ArchiveSource", "ZipSource", "open_source"]


@dataclass(frozen=True)
class EntryInfo:
    """One archive entry. ``name`` is the POSIX-style name as stored (directories end with ``/``)."""

    name: str
    size: int
    compressed_size: int = 0
    is_dir: bool = False
    is_symlink: bool = False
    crc: int = 0
    mode: int = 0   # unix st_mode if known, else 0


@runtime_checkable
class ArchiveSource(Protocol):
    """Read-only view of an IPA / zip / directory. ``name`` arguments are ``EntryInfo.name`` values."""

    kind: str          # "zip" | "dir"
    path: Path         # what the user passed in

    def namelist(self) -> List[EntryInfo]:
        """All entries (files and directories), in a stable order."""

    def stat(self, name: str) -> EntryInfo:
        """Entry info; raises ``KeyError`` if the name does not exist."""

    def open(self, name: str) -> BinaryIO:
        """Seekable binary stream of the entry's content; raises ``KeyError`` if missing."""

    def read_head(self, name: str, n: int) -> bytes:
        """First ``n`` bytes (fewer if the entry is shorter) without reading the whole entry."""

    def extract_to(self, name: str, dest: Path) -> Path:
        """Write the entry to ``dest`` (parent dirs created) and return ``dest``.

        The *caller* is responsible for choosing a safe ``dest`` (see ``AnalysisContext.extract``).
        """

    def close(self) -> None:
        """Release file handles (required on Windows before deleting files)."""


def open_source(path: "Path | str") -> ArchiveSource:
    """Open ``path`` as an ``ArchiveSource`` (WP0: zip files only; WP1 adds directories)."""
    from .minimal_zip import ZipSource as _Zip

    return _Zip(Path(path))


def __getattr__(name: str):  # lazy re-export keeps ``import ipa_analyzer.ingest`` cheap
    if name == "ZipSource":
        from .minimal_zip import ZipSource

        return ZipSource
    raise AttributeError(name)
