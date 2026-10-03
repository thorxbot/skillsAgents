"""Streaming multi-pattern signature scan across chunk boundaries.

``scan_stream`` takes any iterable of ``bytes`` chunks (e.g. the output of
``unityfs.iter_decompressed``) and reports every occurrence of the given literal or regex
patterns together with the absolute stream offset and a short context snippet.  A rolling
window guarantees that signatures straddling a chunk boundary are found exactly once, and the
scan stops on whichever limit trips first: hit count, byte count or wall-clock time.

Pattern facts used by ``SCRIPT_SIGNATURES``:
  * Lua chunk magic ESC "Lua" and LuaJIT magic ESC "LJ" -- lundump.h / lj_bcdump.h (see
    ``lua_bytecode``).
  * PE: DOS header "MZ" (very noisy on its own -- callers should confirm with
    ``pe_cli.is_dotnet_assembly`` on the surrounding bytes); the usual DOS stub text; the CLI
    metadata root magic "BSJB" (ECMA-335 II.24.2.1).
  * Script-path strings inside Unity asset containers: ``[\\w/.-]+\\.(lua|dll|js)(\\.bytes|\\.txt)?``,
    tightened with a trailing "not followed by a word character" guard so ``a.json`` is not read
    as ``a.js``.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional, Sequence

__all__ = [
    "SigPattern",
    "Hit",
    "ScanResult",
    "Hits",
    "SCRIPT_SIGNATURES",
    "literal",
    "regex",
    "scan_stream",
]


@dataclass(frozen=True)
class SigPattern:
    """A named signature: either a literal ``bytes`` string or a compiled bytes regex."""

    id: str
    literal: Optional[bytes] = None
    regex: Optional["re.Pattern[bytes]"] = None
    max_len: int = 0  # longest possible match (regex) -- bounds the rolling window
    noisy: bool = False  # weak signature: expect false positives, confirm before trusting

    def __post_init__(self) -> None:
        if (self.literal is None) == (self.regex is None):
            raise ValueError("exactly one of literal / regex is required")
        if self.literal is not None and not self.literal:
            raise ValueError("empty literal")
        if self.regex is not None and self.max_len <= 0:
            raise ValueError("regex patterns need max_len > 0")

    @property
    def span(self) -> int:
        return len(self.literal) if self.literal is not None else self.max_len


def literal(id: str, data: bytes, *, noisy: bool = False) -> SigPattern:
    return SigPattern(id, literal=bytes(data), noisy=noisy)


def regex(id: str, pattern: bytes, max_len: int, *, flags: int = 0, noisy: bool = False) -> SigPattern:
    return SigPattern(id, regex=re.compile(pattern, flags), max_len=max_len, noisy=noisy)


@dataclass
class Hit:
    pattern: str
    offset: int  # absolute offset of the match start in the scanned stream
    length: int
    match: bytes  # the matched bytes (capped at 256)
    context: bytes  # a short window around the match (capped)


@dataclass
class ScanResult:
    hits: List[Hit] = field(default_factory=list)
    bytes_scanned: int = 0
    stopped: Optional[str] = None  # None | "max_hits" | "max_bytes" | "timeout" | "callback"
    counts: dict = field(default_factory=dict)

    def by_pattern(self, pattern_id: str) -> List[Hit]:
        return [h for h in self.hits if h.pattern == pattern_id]


#: Alias used by the work-package text.
Hits = ScanResult

# UNVERIFIED: the DOS stub text is a compiler convention (Roslyn/MSVC), not a requirement of the PE format.
SCRIPT_SIGNATURES: Sequence[SigPattern] = (
    literal("lua_bytecode", b"\x1bLua"),
    literal("luajit_bytecode", b"\x1bLJ"),
    literal("pe_mz", b"MZ", noisy=True),
    literal("pe_dos_stub", b"This program cannot be run in DOS mode"),
    literal("cli_metadata_bsjb", b"BSJB"),
    regex(
        "script_path",
        rb"[A-Za-z0-9_/.\-]{1,200}\.(?:lua|dll|js)(?:\.bytes|\.txt)?(?![A-Za-z0-9_])",
        max_len=240,
    ),
)

_MATCH_CAP = 256


def scan_stream(
    chunks: Iterable[bytes],
    patterns: Sequence[SigPattern] = SCRIPT_SIGNATURES,
    *,
    max_hits: int = 10_000,
    max_bytes: Optional[int] = None,
    max_seconds: Optional[float] = None,
    on_hit: Optional[Callable[[Hit], Optional[bool]]] = None,
    context_before: int = 16,
    context_after: int = 48,
    max_hits_per_pattern: Optional[int] = None,
) -> ScanResult:
    """Scan ``chunks`` for ``patterns``.

    Limits: ``max_hits`` total (and optionally ``max_hits_per_pattern``), ``max_bytes`` of stream
    consumed (the last chunk is truncated to fit), ``max_seconds`` wall-clock.  ``on_hit`` is
    called for every accepted hit; returning ``True`` from it stops the scan.  Hit offsets are
    absolute in the concatenated stream and each position is reported at most once per pattern.
    """
    result = ScanResult()
    if not patterns:
        return result
    deadline = None if max_seconds is None else time.monotonic() + max_seconds
    window = max(max(p.span for p in patterns), context_after, 1)
    keep = context_before

    buf = b""
    buf_start = 0  # absolute offset of buf[0]
    committed = 0  # absolute offset: every match starting before this has been evaluated
    regex_next = {p.id: 0 for p in patterns}  # per-regex: ignore matches starting before this offset
    per_pattern = {p.id: 0 for p in patterns}

    def process(limit_abs: int) -> bool:
        """Evaluate match starts in [committed, limit_abs); return True if the scan must stop."""
        nonlocal committed
        found: List[Hit] = []
        lo = committed - buf_start
        hi = limit_abs - buf_start
        for p in patterns:
            if p.literal is not None:
                pos = buf.find(p.literal, lo)
                while pos != -1 and pos < hi:
                    found.append(_mk_hit(p, buf, buf_start, pos, pos + len(p.literal), context_before, context_after))
                    pos = buf.find(p.literal, pos + 1)
            else:
                nxt = regex_next[p.id] - buf_start
                for m in p.regex.finditer(buf, max(lo, 0)):
                    if m.start() >= hi:
                        break
                    if m.start() < nxt:
                        continue
                    found.append(_mk_hit(p, buf, buf_start, m.start(), m.end(), context_before, context_after))
                    regex_next[p.id] = buf_start + m.end()
                    nxt = m.end()
        found.sort(key=lambda h: (h.offset, h.pattern))
        committed = limit_abs
        for hit in found:
            if max_hits_per_pattern is not None and per_pattern[hit.pattern] >= max_hits_per_pattern:
                continue
            result.hits.append(hit)
            per_pattern[hit.pattern] += 1
            result.counts[hit.pattern] = result.counts.get(hit.pattern, 0) + 1
            if on_hit is not None and on_hit(hit):
                result.stopped = "callback"
                return True
            if len(result.hits) >= max_hits:
                result.stopped = "max_hits"
                return True
        return False

    total = 0
    stop = False
    for chunk in chunks:
        if not chunk:
            continue
        if deadline is not None and time.monotonic() > deadline:
            result.stopped = "timeout"
            stop = True
            break
        if max_bytes is not None and total + len(chunk) > max_bytes:
            chunk = chunk[: max(0, max_bytes - total)]
            result.stopped = "max_bytes"
            stop = True
        if chunk:
            buf += chunk
            total += len(chunk)
            result.bytes_scanned = total
            limit_abs = buf_start + len(buf) - (window - 1)
            if limit_abs > committed and process(limit_abs):
                stop = True
        if stop:
            break
        # Drop everything that can no longer start or give context to a future match.
        new_start = max(buf_start, committed - keep)
        if new_start > buf_start:
            buf = buf[new_start - buf_start :]
            buf_start = new_start
    if result.stopped in (None, "max_bytes", "timeout"):
        # Final flush: evaluate the tail (matches only need the bytes that exist).
        end_abs = buf_start + len(buf)
        if end_abs > committed:
            saved = result.stopped
            if process(end_abs):
                return result
            result.stopped = saved
    return result


def _mk_hit(p: SigPattern, buf: bytes, buf_start: int, s: int, e: int, before: int, after: int) -> Hit:
    ctx_lo = max(0, s - before)
    ctx_hi = min(len(buf), e + after)
    return Hit(
        pattern=p.id,
        offset=buf_start + s,
        length=e - s,
        match=buf[s : min(e, s + _MATCH_CAP)],
        context=buf[ctx_lo:ctx_hi],
    )
