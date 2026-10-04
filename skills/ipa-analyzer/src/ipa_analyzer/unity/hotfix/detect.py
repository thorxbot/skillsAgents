"""Rule loading and framework merging for the Unity hot-update stage (WP5b).

``data/hotfix.json`` holds every framework signature.  Evidence collectors (metadata strings, dump
namespaces, native symbols, file names) turn raw matches into :class:`Observation` objects with the
help of :class:`HotfixRules`; :func:`merge_frameworks` folds them into ``frameworks[]`` entries with a
confidence (noisy-or of the signal weights, unverified signals down-weighted) and an evidence list.

Version hints are only emitted when an observable marker exists (``version_hint`` is ``None``
otherwise); nothing is guessed from the framework identity alone.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Pattern, Tuple

from ...models import Evidence
from ...util.paths import resource_dir

log = logging.getLogger(__name__)

__all__ = ["Observation", "Signal", "FrameworkRule", "HotfixRules", "load_rules", "merge_frameworks"]

MAX_CONFIDENCE = 0.97
_MAX_EVIDENCE = 12


@dataclass
class Signal:
    framework: str
    type: str
    value: str
    weight: float
    strong: bool = False
    unverified: bool = False
    tag: str = ""
    note: str = ""
    max_matches: int = 0
    compiled: Optional[Pattern[Any]] = None
    sources: List[str] = field(default_factory=list)


@dataclass
class FrameworkRule:
    id: str
    name: str
    kind: str
    max_confidence: float = MAX_CONFIDENCE
    runtime_hints: List[Dict[str, Any]] = field(default_factory=list)
    bytecode_header_variants: List[str] = field(default_factory=list)
    signals: List[Signal] = field(default_factory=list)


@dataclass
class Observation:
    """One matched signal.  ``source`` is metadata | dump | native | file | bundle."""

    framework: str
    source: str
    signal_type: str
    value: str
    weight: float
    ref: str = ""
    detail: str = ""
    strong: bool = False
    unverified: bool = False
    tag: str = ""

    def to_evidence(self) -> Evidence:
        kind = {"metadata": "string", "dump": "string", "native": "symbol", "file": "file", "bundle": "file"}.get(
            self.source, "heuristic")
        detail = "%s:%s %s" % (self.source, self.signal_type, self.value)
        if self.detail:
            detail += " (%s)" % self.detail
        if self.unverified:
            detail += " [unverified rule]"
        return Evidence(kind, self.ref or self.value, detail)


class HotfixRules:
    """Compiled view of ``hotfix.json``."""

    def __init__(self, doc: Dict[str, Any]) -> None:
        self.doc = doc
        self.unverified_factor = float(doc.get("unverified_weight_factor", 0.6))
        self.frameworks: Dict[str, FrameworkRule] = {}
        self.ns_index: Dict[str, List[Signal]] = {}
        self.type_index: Dict[str, List[Signal]] = {}
        self.assembly_index: Dict[str, List[Signal]] = {}
        self.native_signals: List[Signal] = []
        self.file_signals: List[Signal] = []
        self.pool_signals: List[Signal] = []
        for fw in doc.get("frameworks", []):
            rule = FrameworkRule(
                id=fw["id"], name=fw.get("name", fw["id"]), kind=fw.get("kind", "resource"),
                max_confidence=float(fw.get("max_confidence", MAX_CONFIDENCE)),
                runtime_hints=list(fw.get("runtime_hints", [])),
                bytecode_header_variants=list(fw.get("bytecode_header_variants", [])))
            for s in fw.get("signals", []):
                sig = Signal(
                    framework=rule.id, type=s["type"], value=s["value"], weight=float(s.get("weight", 0.3)),
                    strong=bool(s.get("strong", False)), unverified=bool(s.get("unverified", False)),
                    tag=s.get("tag", ""), note=s.get("note", ""), max_matches=int(s.get("max_matches", 0)),
                    sources=list(s.get("sources", [])))
                if sig.type in ("native_regex",):
                    sig.compiled = re.compile(sig.value.encode("ascii"))
                elif sig.type == "file":
                    sig.compiled = re.compile(sig.value, re.IGNORECASE)
                elif sig.type == "pool_regex":
                    sig.compiled = re.compile(sig.value, re.IGNORECASE)
                rule.signals.append(sig)
                self._index(sig)
            self.frameworks[rule.id] = rule
        storage = doc.get("storage", {})
        self.storage = storage
        self.protection_hints = [dict(h, compiled=re.compile(h["regex"], re.IGNORECASE))
                                 for h in doc.get("protection_hints", [])]
        self.js_backends = [dict(b, compiled=re.compile(b["regex"].encode("ascii"))) for b in doc.get("js_backends", [])]
        hd = doc.get("hot_dll", {})
        self.aot_name_res = [re.compile(r) for r in hd.get("aot_name_regex", [])]
        self.hot_name_res = [re.compile(r) for r in hd.get("hot_name_regex", [])]

    def _index(self, sig: Signal) -> None:
        if sig.type == "namespace":
            self.ns_index.setdefault(sig.value, []).append(sig)
        elif sig.type == "type":
            self.type_index.setdefault(sig.value, []).append(sig)
        elif sig.type == "assembly":
            self.assembly_index.setdefault(sig.value, []).append(sig)
        elif sig.type in ("native_regex", "native_literal"):
            self.native_signals.append(sig)
        elif sig.type == "file":
            self.file_signals.append(sig)
        elif sig.type == "pool_regex":
            self.pool_signals.append(sig)

    def effective_weight(self, sig: Signal) -> float:
        return sig.weight * (self.unverified_factor if sig.unverified else 1.0)

    # --- matchers -----------------------------------------------------------------------------
    def match_namespace(self, name: str) -> List[Signal]:
        """Signals whose namespace equals ``name`` or is a segment-wise prefix of it."""
        out: List[Signal] = []
        parts = name.split(".")
        for k in range(1, len(parts) + 1):
            out.extend(self.ns_index.get(".".join(parts[:k]), ()))
        return out

    def match_token(self, token: str) -> List[Tuple[Signal, str]]:
        """Metadata identifier -> ``[(signal, how)]`` for namespace / type / assembly rules."""
        hits: List[Tuple[Signal, str]] = []
        if not token:
            return hits
        for s in self.type_index.get(token, ()):
            hits.append((s, "type"))
        for s in self.assembly_index.get(token, ()):
            hits.append((s, "assembly"))
        if "." in token or token in self.ns_index:
            for s in self.match_namespace(token):
                hits.append((s, "namespace"))
        return hits

    def match_path(self, rel: str) -> List[Signal]:
        return [s for s in self.file_signals if s.compiled is not None and s.compiled.search(rel)]

    def is_aot_name(self, assembly: str, known_aot: Iterable[str] = ()) -> bool:
        base = assembly[:-4] if assembly.lower().endswith(".dll") else assembly
        if base in set(known_aot):
            return True
        return any(r.search(base) for r in self.aot_name_res)

    def looks_hot_name(self, assembly: str) -> bool:
        base = assembly[:-4] if assembly.lower().endswith(".dll") else assembly
        return any(r.search(base) for r in self.hot_name_res)


_CACHE: Dict[str, HotfixRules] = {}


def load_rules(path: Optional[Path] = None) -> HotfixRules:
    """Load (and cache) ``data/hotfix.json``."""
    p = Path(path) if path else resource_dir("data") / "hotfix.json"
    key = str(p)
    if key not in _CACHE:
        with open(p, "r", encoding="utf-8") as fh:
            _CACHE[key] = HotfixRules(json.load(fh))
    return _CACHE[key]


def merge_frameworks(rules: HotfixRules, observations: Iterable[Observation]) -> List[Dict[str, Any]]:
    """Fold observations into ``frameworks[]`` (id, name, kind, confidence, version_hint, evidence)."""
    by_fw: Dict[str, List[Observation]] = {}
    for ob in observations:
        by_fw.setdefault(ob.framework, []).append(ob)
    result: List[Dict[str, Any]] = []
    for fw_id, obs in by_fw.items():
        rule = rules.frameworks.get(fw_id)
        if rule is None:
            continue
        # one weight per distinct (source, signal type, value): repeated hits of the same signal do not stack
        seen: Dict[Tuple[str, str, str], Observation] = {}
        for ob in obs:
            seen.setdefault((ob.source, ob.signal_type, ob.value), ob)
        miss = 1.0
        for ob in seen.values():
            w = ob.weight * (rules.unverified_factor if ob.unverified else 1.0)
            miss *= 1.0 - max(0.0, min(w, 0.95))
        conf = min(1.0 - miss, rule.max_confidence, MAX_CONFIDENCE)
        if conf < 0.15:
            continue
        ordered = sorted(seen.values(), key=lambda o: (-o.weight, o.source, o.value))
        evidence = [o.to_evidence().to_dict() for o in ordered[:_MAX_EVIDENCE]]
        backends = sorted({o.tag.split(":", 1)[1] for o in seen.values() if o.tag.startswith("backend:")})
        result.append({
            "id": rule.id, "name": rule.name, "kind": rule.kind, "confidence": round(conf, 3),
            "version_hint": None, "evidence": evidence,
            "sources": sorted({o.source for o in seen.values()}),
            "backends": backends,
        })
    result.sort(key=lambda f: (-f["confidence"], f["id"]))
    return result
