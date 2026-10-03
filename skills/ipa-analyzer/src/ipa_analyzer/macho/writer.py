"""Write a single architecture of a (fat) Mach-O to its own file.

Used to hand an arm64 slice to tools that cannot read universal binaries (Il2CppDumper & co.).
Encrypted slices are written as-is; callers must check ``slice.is_encrypted`` themselves.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Sequence, Union

from .errors import MachOError
from .parser import MachOFile, MachOSlice, parse

__all__ = ["write_thin"]

_CHUNK = 1 << 20


def _write_slice(sl: MachOSlice, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    try:
        with open(tmp, "wb") as out:
            for chunk in sl.iter_bytes(_CHUNK):
                out.write(chunk)
        os.replace(str(tmp), str(dest))
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def write_thin(source: Union[MachOFile, MachOSlice, str, "os.PathLike[str]"],
               dest_path: Optional[Union[str, "os.PathLike[str]"]] = None,
               prefer: Sequence[str] = ("arm64", "arm64e")) -> Path:
    """Write one slice of ``source`` to ``dest_path`` and return the path.

    * ``MachOSlice`` - that slice is written.
    * ``MachOFile`` / path - the first slice matching ``prefer`` (in order) is written, falling back to
      any ARM64-class slice and finally to the first slice (the returned file can be parsed to see
      which one was chosen).
    * A thin file given by path with ``dest_path=None`` is not copied: its own path is returned.

    The output is written atomically (``<dest>.part`` then rename); parent directories are created.
    """
    if isinstance(source, MachOSlice):
        sl: Optional[MachOSlice] = source
        owner: Optional[MachOFile] = None
    else:
        if isinstance(source, MachOFile):
            owner, opened = source, False
        else:
            owner, opened = parse(source), True
        try:
            if not owner.is_fat and owner.path is not None and dest_path is None:
                return owner.path
            sl = owner.select_slice(prefer)
            if sl is None:
                raise MachOError("no slice to write")
            if dest_path is None:
                raise ValueError("dest_path is required for fat files and in-memory input")
            dest = Path(dest_path)
            _check_not_source(owner, dest)
            _write_slice(sl, dest)
            return dest
        finally:
            if opened:
                owner.close()
    if dest_path is None:
        raise ValueError("dest_path is required when writing a MachOSlice")
    dest = Path(dest_path)
    _write_slice(sl, dest)
    return dest


def _check_not_source(owner: MachOFile, dest: Path) -> None:
    if owner.path is None:
        return
    try:
        if dest.exists() and os.path.samefile(str(owner.path), str(dest)):
            raise ValueError("destination is the source file itself")
    except OSError:
        return
