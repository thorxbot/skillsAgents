"""Evidence matcher: turns observed signals (framework names, ObjC classes, namespaces, ...) into library items.

Confidence grows with the number of *independent evidence classes* that hit the same library (for example a
framework directory + a load command + an ObjC class prefix). The strongest class sets the base value.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .kb import KnowledgeBase, LibEntry

# evidence class -> (base confidence, Evidence.kind)
_CLASSES: Dict[str, Tuple[float, str]] = {
    "framework_dir": (0.80, "file"), "load_command": (0.80, "macho"), "bundled_dylib": (0.75, "file"),
    "bundle": (0.70, "file"), "file": (0.70, "file"), "objc": (0.75, "symbol"), "symbol": (0.70, "symbol"),
    "swift_module": (0.60, "symbol"), "string": (0.60, "string"), "namespace": (0.80, "tool_output"),
    "plist": (0.70, "plist_key"), "scheme": (0.55, "plist_key"), "hotfix": (0.0, "heuristic"),
    "fingerprint": (0.0, "heuristic"),
}
_BONUS_PER_EXTRA_CLASS = 0.08
_MAX_CONF = 0.97
MAX_EVIDENCE = 8
_PER_CLASS_EVIDENCE = 3
_KIND_ORDER = ("framework", "bundled_dylib", "static_sdk", "resource_bundle", "unity_namespace")
_CLASS_KIND = {"framework_dir": "framework", "load_command": "framework", "bundled_dylib": "bundled_dylib",
               "objc": "static_sdk", "symbol": "static_sdk", "swift_module": "static_sdk", "string": "static_sdk",
               "plist": "static_sdk", "scheme": "static_sdk", "hotfix": "static_sdk", "fingerprint": "static_sdk",
               "bundle": "resource_bundle", "file": "resource_bundle", "namespace": "unity_namespace"}


@dataclass
class Signal:
    """One observation. ``type``: framework | dylib | bundle | file | objc_class | symbol | string | namespace |
    plist_key | url_scheme | query_scheme | swift_module | direct.

    ``via`` refines ``framework`` (``dir`` for a framework directory, ``load`` for an LC_LOAD_DYLIB reference) and
    ``dylib`` (``file`` / ``load``). ``direct`` signals carry an already decided ``lib_id`` (hotfix / fingerprint).
    """
    type: str
    value: str = ""
    ref: str = ""
    via: str = ""
    detail: str = ""
    lib_id: str = ""
    confidence: float = 0.0
    version: Optional[str] = None
    source_kind: str = "fingerprint"
    name: str = ""
    category: str = "other"
    purpose_zh: str = ""
    purpose_en: str = ""
    evidence: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class _Hit:
    entry: LibEntry
    classes: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)
    direct_conf: Dict[str, float] = field(default_factory=dict)
    version: Optional[str] = None

    def add(self, cls: str, ref: str, detail: str) -> None:
        ev = self.classes.setdefault(cls, [])
        item = {"kind": _CLASSES[cls][1], "ref": ref, "detail": detail}
        if len(ev) < _PER_CLASS_EVIDENCE and item not in ev:
            ev.append(item)


class LibMatcher:
    def __init__(self, kb: KnowledgeBase) -> None:
        self.kb = kb
        self._hits: Dict[str, _Hit] = {}

    # -- feeding -----------------------------------------------------------------------------
    def _hit(self, entry_id: str) -> Optional[_Hit]:
        entry = self.kb.entries.get(entry_id)
        if entry is None:
            return None
        return self._hits.setdefault(entry_id, _Hit(entry))

    def add(self, sig: Signal) -> List[str]:
        """Feed one signal; returns the ids of the libraries it matched."""
        t = sig.type
        matched: List[Tuple[str, str, str]] = []      # (id, class, detail)
        if t == "framework":
            cls = {"dir": "framework_dir", "swift": "swift_module"}.get(sig.via, "load_command")
            matched = [(i, cls, sig.detail or "framework %s" % sig.value) for i in self.kb.lookup("framework", sig.value)]
        elif t == "swift_module":
            matched = [(i, "swift_module", "Swift module %s" % sig.value) for i in self.kb.lookup("framework", sig.value)]
        elif t == "dylib":
            cls = "bundled_dylib" if sig.via == "file" else "load_command"
            matched = [(i, cls, sig.detail or "dylib %s" % sig.value) for i in self.kb.lookup("dylib", sig.value)]
        elif t == "bundle":
            matched = [(i, "bundle", sig.detail or "bundle %s" % sig.value) for i in self.kb.lookup("bundle", sig.value)]
        elif t == "file":
            matched = [(i, "file", sig.detail or "file %s" % sig.value) for i in self.kb.lookup_file(sig.value)]
        elif t == "objc_class":
            matched = [(i, "objc", "ObjC class %s (prefix %s)" % (sig.value, p)) for i, p in self.kb.lookup_objc(sig.value)]
        elif t == "symbol":
            matched = [(i, "symbol", "symbol %s" % sig.value) for i, _ in self.kb.lookup_symbol(sig.value)]
        elif t == "string":
            matched = [(i, "string", "string %r" % tok) for i, tok in self.kb.find_strings(sig.value)]
        elif t == "namespace":
            matched = [(i, "namespace", "namespace %s (rule %s)" % (sig.value, tok)) for i, tok in self.kb.lookup_namespace(sig.value)]
        elif t == "plist_key":
            matched = [(i, "plist", "Info.plist key %s" % sig.value) for i in self.kb.lookup("plist_key", sig.value)]
        elif t in ("url_scheme", "query_scheme"):
            matched = [(i, "scheme", "%s %s" % (t.replace("_", " "), sig.value)) for i in self.kb.lookup(t, sig.value)]
        elif t == "direct":
            return self._add_direct(sig)
        ids: List[str] = []
        for lib_id, cls, detail in matched:
            hit = self._hit(lib_id)
            if hit is None:
                continue
            hit.add(cls, sig.ref, detail)
            ids.append(lib_id)
        return sorted(set(ids))

    def _add_direct(self, sig: Signal) -> List[str]:
        if not sig.lib_id:
            return []
        if sig.lib_id not in self.kb.entries:
            ent = LibEntry(id=sig.lib_id, name=sig.name or sig.lib_id, vendor="", category=sig.category,
                           purpose_zh=sig.purpose_zh, purpose_en=sig.purpose_en, merge_only=True)
            self.kb.entries[sig.lib_id] = ent
        hit = self._hit(sig.lib_id)
        assert hit is not None
        cls = "hotfix" if sig.source_kind == "hotfix" else "fingerprint"
        evs = sig.evidence or [{"kind": "heuristic", "ref": sig.ref, "detail": sig.detail or "detected by %s stage" % cls}]
        for ev in evs[:_PER_CLASS_EVIDENCE]:
            lst = hit.classes.setdefault(cls, [])
            if ev not in lst and len(lst) < _PER_CLASS_EVIDENCE:
                lst.append({"kind": str(ev.get("kind", "heuristic")), "ref": str(ev.get("ref", "")),
                            "detail": str(ev.get("detail", ""))})
        hit.direct_conf[cls] = max(hit.direct_conf.get(cls, 0.0), max(0.0, min(1.0, sig.confidence)) * 0.9)
        if sig.version and not hit.version:
            hit.version = sig.version
        return [sig.lib_id]

    def set_version(self, lib_id: str, version: str) -> None:
        h = self._hits.get(lib_id)
        if h is not None and version and not h.version:
            h.version = version

    # -- results -----------------------------------------------------------------------------
    @staticmethod
    def _confidence(hit: _Hit) -> float:
        vals = []
        for cls in hit.classes:
            base = _CLASSES[cls][0]
            vals.append(hit.direct_conf.get(cls, 0.0) if cls in ("hotfix", "fingerprint") else base)
        if not vals:
            return 0.0
        vals.sort(reverse=True)
        return round(min(_MAX_CONF, vals[0] + _BONUS_PER_EXTRA_CLASS * (len(vals) - 1)), 2)

    def hit_ids(self) -> List[str]:
        return sorted(self._hits)

    def hit_classes(self, lib_id: str) -> List[str]:
        h = self._hits.get(lib_id)
        return sorted(h.classes) if h else []

    def items(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for lib_id in sorted(self._hits):
            h = self._hits[lib_id]
            e = h.entry
            kind = min((_CLASS_KIND[c] for c in h.classes), key=_KIND_ORDER.index)
            evidence: List[Dict[str, str]] = []
            for cls in sorted(h.classes, key=lambda c: -(_CLASSES[c][0] or 1.0)):
                evidence.extend(h.classes[cls])
            rec: Dict[str, Any] = {
                "id": e.id, "name": e.name, "kind": kind, "vendor": e.vendor, "category": e.category,
                "purpose_zh": e.purpose_zh, "purpose_en": e.purpose_en, "tags": list(e.tags),
                "confidence": self._confidence(h), "evidence": evidence[:MAX_EVIDENCE]}
            if h.version:
                rec["version"] = h.version
            out.append(rec)
        out.sort(key=lambda r: (r["category"], r["id"]))
        return out
