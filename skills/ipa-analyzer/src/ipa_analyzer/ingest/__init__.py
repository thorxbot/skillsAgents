"""Input abstraction: ``ArchiveSource`` Protocol (frozen contract) and ``EntryInfo``.

The real ``ZipSource`` / ``DirSource`` / ``open_source`` live in ``ingest.source`` (WP1);
``minimal_zip.py`` is kept as a thin alias. The Protocol, ``EntryInfo`` and the exported names are frozen.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, List, Optional, Protocol, runtime_checkable

__all__ = ["EntryInfo", "ArchiveSource", "ZipSource", "DirSource", "open_source"]


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


def open_source(path: "Path | str", **kwargs: object) -> ArchiveSource:
    """Open ``path`` (zip / ipa file or directory) as an ``ArchiveSource`` (see ``ingest.source``)."""
    from .source import open_source as _open

    return _open(Path(path), **kwargs)  # type: ignore[return-value]


def __getattr__(name: str):  # lazy re-export keeps ``import ipa_analyzer.ingest`` cheap
    if name in ("ZipSource", "DirSource"):
        from . import source

        return getattr(source, name)
    raise AttributeError(name)
