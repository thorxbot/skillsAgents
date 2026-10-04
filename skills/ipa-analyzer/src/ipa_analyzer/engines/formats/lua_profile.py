"""Lua version profile shared by the Cocos, ``lua``, ``generic_scripts`` and ``solar2d_love`` checkers.

The output has the same shape as ``engine.unity.hotfix`` ``lua`` (CONTRACT-FREEZE section 4.9)::

    {runtime_versions: [{flavor, version, source, confidence}],
     bytecode: {by_version, invalid, stripped_count, arch_bits},
     files: {plain, bytecode, compressed, encrypted_suspected, total},
     dialect_hints: [str], consistency: {ok, notes: [str]}, custom_lua_suspected: bool}

Headers are parsed with ``ipa_analyzer.formats.lua_bytecode``; plain-text dialect inference uses
``ipa_analyzer.formats.lua_source``; runtime versions come from version strings in the main binary
(``Lua 5.x.y  Copyright (C) 1994-20xx Lua.org, PUC-Rio`` as defined by ``lua.h``; LuaJIT's
``LUAJIT_VERSION`` has the form ``LuaJIT 2.1.0-beta3`` -- UNVERIFIED for builds that strip it).
Nothing here decodes or runs Lua.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Set

from ...formats import lua_source
from . import common
from .common import BlobInfo

#: Source: lua.h (5.1.5 / 5.3.6 / 5.4.x) ``LUA_COPYRIGHT`` and ``LUA_RELEASE``.
PUC_RUNTIME_RE = re.compile(r"Lua (5\.[1-5](?:\.\d{1,2})?)\s+Copyright \(C\) 1994-20\d\d Lua\.org, PUC-Rio")
# UNVERIFIED: ``LUAJIT_VERSION`` format ("LuaJIT 2.1.0-beta3" / "LuaJIT 2.1.<timestamp>") taken from memory of luajit.h.
LUAJIT_RUNTIME_RE = re.compile(r"LuaJIT (2\.[01]\.\d+(?:-[A-Za-z0-9.]+)?)")

RUNTIME_PATTERNS = {
    "lua_puc_version": PUC_RUNTIME_RE.pattern,
    "lua_luajit_version": LUAJIT_RUNTIME_RE.pattern,
}


def runtime_from_hits(hits: Dict[str, List[str]], source: str = "main_binary_string") -> List[Dict[str, Any]]:
    """Turn ``scan_main_binary`` hits for ``RUNTIME_PATTERNS`` into ``runtime_versions`` entries."""
    out: List[Dict[str, Any]] = []
    seen: Set[tuple] = set()
    for text in hits.get("lua_puc_version", []):
        m = PUC_RUNTIME_RE.search(text)
        if m and ("puc", m.group(1)) not in seen:
            seen.add(("puc", m.group(1)))
            out.append({"flavor": "puc", "version": m.group(1), "source": source, "confidence": 0.9})
    for text in hits.get("lua_luajit_version", []):
        m = LUAJIT_RUNTIME_RE.search(text)
        if m and ("luajit", m.group(1)) not in seen:
            seen.add(("luajit", m.group(1)))
            out.append({"flavor": "luajit", "version": m.group(1), "source": source, "confidence": 0.85})
    return out


def _series(entry: Dict[str, Any]) -> Optional[str]:
    v = str(entry.get("version", ""))
    if entry.get("flavor") == "luajit":
        return "luajit_" + ".".join(v.split(".")[:2])
    return ".".join(v.split(".")[:2]) if v else None


class LuaProfiler:
    """Accumulates classified Lua files and renders the profile dict."""

    def __init__(self) -> None:
        self.files: Counter = Counter()
        self.by_version: Counter = Counter()
        self.bits: Counter = Counter()
        self.invalid = 0
        self.tampered = 0
        self.stripped = 0
        self.xor_suspects = 0
        self.dialect_min: Counter = Counter()
        self.dialect_style: Counter = Counter()
        self.dialect_luajit: Counter = Counter()
        self.dialect_conflicts: Counter = Counter()
        self.signals: Counter = Counter()
        self.tamper_signals: Counter = Counter()
        self.chunknames_seen = 0
        self.total = 0

    def add(self, blob: BlobInfo, text: Optional[bytes] = None) -> None:
        """Record one file.  ``text`` (more of a plain file than the sniff head) improves dialect inference."""
        self.total += 1
        kind = blob.kind
        if kind == common.K_LUA_BC:
            self.files["bytecode"] += 1
            info = blob.detail["lua"]
            self.by_version[info.version_key or "unknown"] += 1
            if info.bits:
                self.bits[str(info.bits)] += 1
            if info.stripped:
                self.stripped += 1
        elif kind == common.K_LUA_BC_TAMPERED:
            self.files["encrypted_suspected"] += 1
            self.invalid += 1
            self.tampered += 1
            for s in blob.detail["lua"].tamper_signals:
                self.tamper_signals[s.split(":")[0]] += 1
        elif kind == common.K_LUA_XOR:
            self.files["encrypted_suspected"] += 1
            self.invalid += 1
            self.xor_suspects += 1
        elif kind == common.K_PLAIN:
            self.files["plain"] += 1
            hints = lua_source.infer_dialect(text if text else b"")
            if hints.min_version:
                self.dialect_min[hints.min_version] += 1
            for s in hints.signals:
                self.signals[s] += 1
            for s in hints.style_hints:
                self.dialect_style[s] += 1
            for s in hints.luajit_signals:
                self.dialect_luajit[s] += 1
            for s in hints.conflicts:
                self.dialect_conflicts[s] += 1
        elif kind == common.K_COMPRESSED:
            self.files["compressed"] += 1
        elif kind in (common.K_CUSTOM_HEADER, common.K_HIGH_ENTROPY, common.K_ENCODED_TEXT):
            self.files["encrypted_suspected"] += 1
            self.invalid += 1

    def dialect_hints(self) -> List[str]:
        hints: List[str] = []
        if self.dialect_min:
            top = max(self.dialect_min, key=lambda v: tuple(int(x) for x in v.split(".")))
            hints.append("plain_source_min_version>=%s (%d files)" % (top, self.dialect_min[top]))
        for name, c in sorted(self.dialect_style.items()):
            hints.append("lua51_style:%s (%d files)" % (name, c))
        for name, c in sorted(self.dialect_luajit.items()):
            hints.append("luajit_feature:%s (%d files)" % (name, c))
        for name, c in sorted(self.dialect_conflicts.items()):
            hints.append("conflict:%s (%d files)" % (name, c))
        return hints

    def consistency(self, runtime: List[Dict[str, Any]]) -> Dict[str, Any]:
        notes: List[str] = []
        bc_keys = {k for k in self.by_version if k != "unknown"}
        rt_series = {s for s in (_series(r) for r in runtime) if s}
        ok = True
        if len(bc_keys) > 1:
            notes.append("bytecode headers of more than one Lua version: %s" % ", ".join(sorted(bc_keys)))
        if bc_keys and rt_series:
            missing = sorted(bc_keys - rt_series)
            if missing:
                ok = False
                notes.append("bytecode version(s) %s not matched by runtime version string(s) %s (several VMs, or a "
                             "modified runtime)" % (", ".join(missing), ", ".join(sorted(rt_series))))
        elif bc_keys and not rt_series:
            notes.append("no runtime version string available to compare with the bytecode version")
        if self.dialect_min and bc_keys == set() and rt_series:
            top = max(self.dialect_min, key=lambda v: tuple(int(x) for x in v.split(".")))
            lowest = {s for s in rt_series if not s.startswith("luajit_")}
            if lowest and all(tuple(int(x) for x in s.split(".")) < tuple(int(x) for x in top.split(".")) for s in lowest):
                ok = False
                notes.append("plain sources need Lua >= %s but the runtime string says %s" % (top, ", ".join(sorted(lowest))))
        return {"ok": ok, "notes": notes}

    def to_dict(self, runtime: Optional[Iterable[Dict[str, Any]]] = None) -> Dict[str, Any]:
        rt = list(runtime or [])
        custom = bool(self.tampered or self.xor_suspects)
        return {
            "runtime_versions": rt,
            "bytecode": {"by_version": dict(sorted(self.by_version.items())), "invalid": self.invalid,
                         "stripped_count": self.stripped, "arch_bits": dict(sorted(self.bits.items())),
                         "tamper_signals": dict(sorted(self.tamper_signals.items()))},
            "files": {"plain": self.files["plain"], "bytecode": self.files["bytecode"],
                      "compressed": self.files["compressed"], "encrypted_suspected": self.files["encrypted_suspected"],
                      "total": self.total},
            "dialect_hints": self.dialect_hints(),
            "consistency": self.consistency(rt),
            "custom_lua_suspected": custom,
        }
