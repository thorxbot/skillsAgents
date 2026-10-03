"""Streaming hash helpers."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO, Union

CHUNK = 1024 * 1024


def hash_stream(fileobj: BinaryIO, algo: str = "sha256", *, chunk: int = CHUNK) -> str:
    """Hex digest of everything readable from ``fileobj`` (read from its current position)."""
    h = hashlib.new(algo)
    while True:
        block = fileobj.read(chunk)
        if not block:
            break
        h.update(block)
    return h.hexdigest()


def sha256_stream(source: Union[str, Path, BinaryIO], *, chunk: int = CHUNK) -> str:
    """SHA-256 hex digest of a path or an open binary file object, read in ``chunk``-sized blocks."""
    if hasattr(source, "read"):
        return hash_stream(source, "sha256", chunk=chunk)  # type: ignore[arg-type]
    with open(source, "rb") as fh:  # type: ignore[arg-type]
        return hash_stream(fh, "sha256", chunk=chunk)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
