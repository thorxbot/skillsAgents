"""Native symbol / string evidence from Mach-O binaries: Lua runtime versions, VM flavours, framework symbols.

Only bytes outside FairPlay-encrypted ranges are scanned (``cryptoff .. cryptoff+cryptsize`` of the
chosen slice is ciphertext and would only add noise); a fully encrypted binary therefore yields little
and the result says so (``limited_by_encryption``).  Nothing is executed or decrypted.

Version string formats (checked against the upstream headers on 2026-10-04):
  * PUC-Rio Lua: ``lua.h`` ``LUA_COPYRIGHT`` / ``LUA_RELEASE``: ``"Lua 5.3.6  Copyright (C) 1994-2020 Lua.org, PUC-Rio"``
    (5.1: ``"Lua 5.1.5"`` + ``"  Copyright (C) 1994-2012 ..."``, which concatenates identically in ``lua_ident``);
    ``LUA_VERSION`` alone is ``"Lua 5.x"``.  LuaJIT also reports ``LUA_VERSION "Lua 5.1"``.
  * LuaJIT: ``luajit.h`` ``LUAJIT_VERSION "LuaJIT 2.1.0-beta3"`` and the exported symbol
    ``LUAJIT_VERSION_SYM`` = ``luaJIT_version_2_1_0_beta3``; the rolling branch uses ``"LuaJIT 2.1.ROLLING"``
    in source (release builds substitute a timestamp -- UNVERIFIED).
  * Symbol hints: ``lua_newuserdatauv`` / ``lua_setiuservalue`` exist only in 5.4 (lua.h 5.4.6),
    ``luaopen_utf8`` from 5.3 on, ``luaopen_bit32`` in 5.2/5.3, ``lua_setfenv`` / ``lua_getfenv`` in 5.1 and
    LuaJIT, ``luaopen_jit`` / ``luaopen_ffi`` / ``luaJIT_setmode`` in LuaJIT only.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from ...formats import magic_scan
from ...macho import MachOError, NotMachO, parse
from .detect import HotfixRules, Observation

log = logging.getLogger(__name__)

__all__ = ["NativeScan", "scan_binary", "parse_lua_hit", "build_patterns"]

_READ = 8 * 1024 * 1024
DEFAULT_MAX_BYTES = 768 * 1024 * 1024
DEFAULT_MAX_SECONDS = 90.0

# Source: lua.h of Lua 5.1/5.2/5.3/5.4 (LUA_RELEASE + "  " + LUA_COPYRIGHT)
_LUA_FULL = rb"Lua (5\.[1-5]\.[0-9]{1,2})  Copyright \(C\) 1994-20[0-9]{2} Lua\.org, PUC-Rio"
# Source: lua.h LUA_VERSION ("Lua 5.x"); weak because LuaJIT and docs/error texts also contain it.
_LUA_BARE = rb"(?<![A-Za-z0-9_.])Lua (5\.[1-5])(?![0-9A-Za-z.])"
# Source: luajit.h LUAJIT_VERSION
_LJ_STR = rb"LuaJIT (2\.[0-9]\.[0-9A-Za-z][0-9A-Za-z.+_-]{0,30}?)(?![0-9A-Za-z.+_-])"
# Source: luajit.h LUAJIT_VERSION_SYM
_LJ_SYM = rb"luaJIT_version_([0-9]+)_([0-9]+)_([0-9A-Za-z_]{1,24})"
_SYMS = (b"luaJIT_setmode", b"luaopen_jit", b"luaopen_ffi", b"luaopen_utf8", b"luaopen_bit32",
         b"lua_newuserdatauv", b"lua_setiuservalue", b"lua_setfenv", b"lua_getfenv", b"luaL_newstate",
         b"lua_newstate", b"luaL_loadbufferx", b"luaL_loadbuffer")
_SYM_RE = rb"(?<![A-Za-z0-9_])_?(" + b"|".join(re.escape(s) for s in _SYMS) + rb")(?![A-Za-z0-9_])"

# symbol -> (flavor, version or None, how)
_SYMBOL_IMPLIES: Dict[str, Tuple[str, Optional[str], str]] = {
    "luaJIT_setmode": ("luajit", None, "LuaJIT-only API"),
    "luaopen_jit": ("luajit", None, "LuaJIT-only library"),
    "luaopen_ffi": ("luajit", None, "LuaJIT-only library"),
    "lua_newuserdatauv": ("puc", "5.4", "introduced in Lua 5.4"),
    "lua_setiuservalue": ("puc", "5.4", "introduced in Lua 5.4"),
}


@dataclass
class NativeScan:
    ran: bool = False
    targets: List[Dict[str, Any]] = field(default_factory=list)
    observations: List[Observation] = field(default_factory=list)
    runtime_versions: List[Dict[str, Any]] = field(default_factory=list)
    symbol_hints: List[Dict[str, str]] = field(default_factory=list)
    js_backends: List[Dict[str, Any]] = field(default_factory=list)
    limited_by_encryption: bool = False
    notes: List[str] = field(default_factory=list)

    def merge(self, other: "NativeScan") -> None:
        self.ran = self.ran or other.ran
        self.targets.extend(other.targets)
        self.observations.extend(other.observations)
        for rv in other.runtime_versions:
            if rv not in self.runtime_versions:
                self.runtime_versions.append(rv)
        for h in other.symbol_hints:
            if h not in self.symbol_hints:
                self.symbol_hints.append(h)
        for b in other.js_backends:
            if b not in self.js_backends:
                self.js_backends.append(b)
        self.limited_by_encryption = self.limited_by_encryption or other.limited_by_encryption
        self.notes.extend(n for n in other.notes if n not in self.notes)


def build_patterns(rules: HotfixRules) -> List[magic_scan.SigPattern]:
    pats = [
        magic_scan.regex("lua_full", _LUA_FULL, 80),
        magic_scan.regex("lua_bare", _LUA_BARE, 16),
        magic_scan.regex("luajit_str", _LJ_STR, 48),
        magic_scan.regex("luajit_sym", _LJ_SYM, 64),
        magic_scan.regex("lua_syms", _SYM_RE, 40),
    ]
    for i, jb in enumerate(rules.js_backends):
        pats.append(magic_scan.regex("jsb:%d" % i, jb["regex"].encode("ascii"), 64))
    for i, sig in enumerate(rules.native_signals):
        pid = "fw:%d" % i
        if sig.type == "native_literal":
            pats.append(magic_scan.literal(pid, sig.value.encode("ascii")))
        elif sig.compiled is not None:
            pats.append(magic_scan.regex(pid, sig.value.encode("ascii"), 96))
    return pats


def parse_lua_hit(pattern_id: str, match: bytes) -> Optional[Dict[str, Any]]:
    """Turn a version-string hit into a ``runtime_versions`` entry (without ``source``/``ref``)."""
    text = match.decode("ascii", "replace")
    if pattern_id == "lua_full":
        m = re.search(r"Lua (5\.[1-5])\.([0-9]{1,2})", text)
        if m:
            return {"flavor": "puc", "version": "%s.%s" % (m.group(1), m.group(2)), "series": m.group(1),
                    "confidence": 0.92}
    elif pattern_id == "lua_bare":
        m = re.search(r"Lua (5\.[1-5])", text)
        if m:
            return {"flavor": "puc", "version": m.group(1), "series": m.group(1), "confidence": 0.45}
    elif pattern_id == "luajit_str":
        m = re.search(r"LuaJIT (2\.[0-9])\.(\S+)", text)
        if m:
            return {"flavor": "luajit", "version": "%s.%s" % (m.group(1), m.group(2)), "series": m.group(1),
                    "confidence": 0.92}
    elif pattern_id == "luajit_sym":
        m = re.search(r"luaJIT_version_([0-9]+)_([0-9]+)_(.+)", text)
        if m:
            rest = m.group(3).replace("_", "-", 1)
            return {"flavor": "luajit", "version": "%s.%s.%s" % (m.group(1), m.group(2), rest),
                    "series": "%s.%s" % (m.group(1), m.group(2)), "confidence": 0.88}
    return None


def _ranges(size: int, encrypted: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """``[0, size)`` minus the encrypted ``(start, end)`` ranges."""
    out: List[Tuple[int, int]] = []
    pos = 0
    for s, e in sorted(encrypted):
        s, e = max(0, s), min(size, e)
        if s > pos:
            out.append((pos, s))
        pos = max(pos, e)
    if pos < size:
        out.append((pos, size))
    return out


def _chunks(read, start: int, end: int) -> Iterator[bytes]:
    pos = start
    while pos < end:
        buf = read(pos, min(_READ, end - pos))
        if not buf:
            return
        pos += len(buf)
        yield buf


def scan_binary(path: Path, rules: HotfixRules, *, ref: str, max_bytes: int = DEFAULT_MAX_BYTES,
                max_seconds: float = DEFAULT_MAX_SECONDS) -> NativeScan:
    """Scan one extracted binary (Mach-O thin/fat, or any file) outside its encrypted ranges."""
    res = NativeScan()
    patterns = build_patterns(rules)
    target: Dict[str, Any] = {"path": ref, "encrypted": None, "scanned_bytes": 0, "format": "raw"}
    mf = None
    fh = None
    try:
        try:
            mf = parse(path)
        except (NotMachO, MachOError):
            mf = None
        ranges: List[Tuple[Any, int, int]] = []     # (reader, start, end)
        if mf is not None:
            sl = mf.select_slice()
            if sl is None:
                res.notes.append("%s: no Mach-O slice could be parsed" % ref)
                res.targets.append(target)
                return res
            target["format"] = "macho:" + sl.arch_name
            enc = [(e.cryptoff, e.cryptoff + e.cryptsize) for e in sl.encryption if e.encrypted]
            target["encrypted"] = bool(enc)
            if enc:
                res.limited_by_encryption = True
                res.notes.append("%s: binary is FairPlay-encrypted; only the unencrypted ranges (symbols, data) "
                                 "were scanned, so binary-based detection is limited" % ref)
            for s, e in _ranges(sl.size, enc):
                ranges.append((sl.read, s, e))
        else:
            size = path.stat().st_size
            fh = open(path, "rb")

            def _read(off: int, n: int, _fh=fh) -> bytes:
                _fh.seek(off)
                return _fh.read(n)
            ranges.append((_read, 0, size))
        remaining = max_bytes
        deadline = time.monotonic() + max_seconds
        hits: List[magic_scan.Hit] = []
        for read, s, e in ranges:
            if remaining <= 0 or time.monotonic() > deadline:
                res.notes.append("%s: scan limit reached (bytes or time); results are partial" % ref)
                break
            r = magic_scan.scan_stream(_chunks(read, s, e), patterns, max_bytes=remaining,
                                       max_seconds=max(0.1, deadline - time.monotonic()),
                                       max_hits_per_pattern=6, max_hits=200)
            remaining -= r.bytes_scanned
            target["scanned_bytes"] += r.bytes_scanned
            hits.extend(r.hits)
            if r.stopped in ("timeout", "max_bytes"):
                res.notes.append("%s: scan stopped (%s); results are partial" % (ref, r.stopped))
                break
        res.ran = True
        _interpret(hits, rules, ref, res)
    finally:
        if mf is not None:
            mf.close()
        if fh is not None:
            fh.close()
    res.targets.append(target)
    return res


def _interpret(hits: List[magic_scan.Hit], rules: HotfixRules, ref: str, res: NativeScan) -> None:
    seen_rv = set()
    seen_sym = set()
    for h in hits:
        if h.pattern in ("lua_full", "lua_bare", "luajit_str", "luajit_sym"):
            rv = parse_lua_hit(h.pattern, h.match)
            if rv is None:
                continue
            key = (rv["flavor"], rv["version"], h.pattern)
            if key in seen_rv:
                continue
            seen_rv.add(key)
            rv.update({"source": "native:%s" % h.pattern, "ref": ref})
            res.runtime_versions.append(rv)
        elif h.pattern == "lua_syms":
            sym = h.match.decode("ascii", "replace").lstrip("_")
            if sym in seen_sym:
                continue
            seen_sym.add(sym)
            res.symbol_hints.append({"symbol": sym, "ref": ref})
            imp = _SYMBOL_IMPLIES.get(sym)
            if imp:
                flavor, ver, _how = imp
                res.runtime_versions.append({"flavor": flavor, "version": ver or "2.x", "series": ver,
                                             "confidence": 0.55, "source": "native:symbol:%s" % sym, "ref": ref})
        elif h.pattern.startswith("jsb:"):
            jb = rules.js_backends[int(h.pattern.split(":", 1)[1])]
            entry = {"id": jb["id"], "confidence": jb["weight"] * (rules.unverified_factor if jb.get("unverified") else 1.0),
                     "ref": ref, "symbol": h.match.decode("ascii", "replace")[:40]}
            if not any(b["id"] == entry["id"] and b["ref"] == ref for b in res.js_backends):
                res.js_backends.append(entry)
        elif h.pattern.startswith("fw:"):
            idx = int(h.pattern.split(":", 1)[1])
            sig = rules.native_signals[idx]
            res.observations.append(Observation(
                sig.framework, "native", sig.type, sig.value, sig.weight, ref=ref,
                detail=h.match.decode("ascii", "replace")[:60], strong=sig.strong, unverified=sig.unverified,
                tag=sig.tag))
