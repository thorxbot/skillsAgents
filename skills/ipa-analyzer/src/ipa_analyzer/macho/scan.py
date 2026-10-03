"""Streaming byte-pattern scans over large binaries (mmap when possible, chunked reads otherwise).

Typical use: find Unity version strings, ``il2cpp_`` markers or domain names in a multi-hundred-MB
executable without reading it into memory. Patterns are compiled ``bytes`` regexes; a match may not be
longer than ``overlap`` bytes (matches that straddle a window boundary are found through the overlap
and de-duplicated by start offset).
"""
from __future__ import annotations

import mmap
import os
import re
from collections import Counter
from contextlib import contextmanager
from typing import Dict, Iterator, List, NamedTuple, Pattern, Sequence, Tuple, Union

__all__ = ["scan_file", "ScanHit", "ScanResult", "find_unity_version_strings", "find_unity_version_hits",
           "UNITY_VERSION_RE"]

PathLike = Union[str, "os.PathLike[str]"]
DEFAULT_CHUNK = 8 * 1024 * 1024
DEFAULT_OVERLAP = 256
DEFAULT_LIMIT = 100


class ScanHit(NamedTuple):
    offset: int
    data: bytes


class ScanResult(dict):
    """``{pattern.pattern: [ScanHit, ...]}`` plus bookkeeping attributes.

    ``truncated`` is True when at least one pattern reached ``limit`` hits (the scan keeps counting
    in ``counts`` but stops storing); ``scanned`` is the number of bytes covered.
    """

    def __init__(self) -> None:
        super().__init__()
        self.truncated = False
        self.scanned = 0
        self.counts: Dict[bytes, int] = {}


@contextmanager
def _open_view(path: PathLike) -> Iterator[Tuple[object, int]]:
    """Yield ``(buffer, size)``; ``buffer`` supports slicing and ``re`` (an mmap, or a bytes fallback)."""
    with open(path, "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        if size == 0:
            yield b"", 0
            return
        try:
            mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, OSError, OverflowError):
            mm = None
        if mm is None:
            yield _ChunkedFile(fh, size), size
            return
        try:
            yield mm, size
        finally:
            mm.close()      # Windows: the mapping must be closed before the file can be removed


class _ChunkedFile:
    """Minimal buffer-like wrapper used when mmap is unavailable (reads windows on demand)."""

    def __init__(self, fh, size: int) -> None:
        self._fh, self.size = fh, size

    def window(self, start: int, end: int) -> bytes:
        self._fh.seek(start)
        return self._fh.read(end - start)


def scan_file(path: PathLike, patterns: Sequence[Pattern[bytes]], *, chunk: int = DEFAULT_CHUNK,
              overlap: int = DEFAULT_OVERLAP, limit: int = DEFAULT_LIMIT) -> ScanResult:
    """Scan ``path`` for each compiled bytes pattern; return hits keyed by ``pattern.pattern``.

    ``limit`` caps stored hits *per pattern* (counting continues in ``result.counts``).
    """
    result = ScanResult()
    for p in patterns:
        if not isinstance(p.pattern, bytes):
            raise TypeError("patterns must be compiled bytes regexes")
        result.setdefault(p.pattern, [])
        result.counts.setdefault(p.pattern, 0)
    chunk = max(chunk, 1)
    overlap = max(overlap, 0)
    with _open_view(path) as (buf, size):
        result.scanned = size
        if size == 0:
            return result
        start = 0
        while start < size:
            end = min(start + chunk, size)
            win_end = min(end + overlap, size)
            if isinstance(buf, _ChunkedFile):
                base = max(start - 16, 0)     # a little left context for look-behind assertions
                window = buf.window(base, win_end)
            else:
                window, base = buf, 0
            for p in patterns:
                key = p.pattern
                for m in p.finditer(window, start - base, win_end - base):
                    abs_off = base + m.start()
                    if abs_off >= end and end < size:
                        break           # belongs to the next window
                    result.counts[key] += 1
                    if len(result[key]) < limit:
                        result[key].append(ScanHit(abs_off, m.group()))
                    else:
                        result.truncated = True
            start = end
    return result


# --- Unity version strings ---------------------------------------------------------------------
# Unity editor versions look like ``2021.3.16f1`` / ``2019.4.40f1c1`` (China builds append ``c<N>``),
# alpha/beta/patch letters ``a`` ``b`` ``p`` and ``5.6.7f1``; Unity 6 uses ``6000.0.23f1``.
# Source: Unity version naming (unity.com/releases). Heuristic: no runtime check against real
# player binaries was possible offline; matches are bounded so surrounding digits/dots/letters are
# rejected to cut false positives like ``12019.4.1f1`` or dotted IPs.
UNITY_VERSION_RE = re.compile(
    rb"(?<![0-9A-Za-z.])(?:20[12][0-9]|5|6000)\.[0-9]{1,2}\.[0-9]{1,2}[fpab][0-9]{1,2}(?:c[0-9]{1,2})?(?![0-9A-Za-z]|\.[0-9])")


def find_unity_version_hits(path: PathLike, *, limit: int = 200) -> List[ScanHit]:
    """All Unity-version-looking strings with offsets (first ``limit``)."""
    return list(scan_file(path, [UNITY_VERSION_RE], limit=limit).get(UNITY_VERSION_RE.pattern, []))


def find_unity_version_strings(path: PathLike, *, limit: int = 200) -> List[str]:
    """Distinct Unity version strings found in ``path``, most frequent first (ties: first seen)."""
    hits = find_unity_version_hits(path, limit=limit)
    counts: Counter = Counter()
    first: Dict[str, int] = {}
    for h in hits:
        v = h.data.decode("ascii", "replace")
        counts[v] += 1
        first.setdefault(v, h.offset)
    return sorted(counts, key=lambda v: (-counts[v], first[v]))
