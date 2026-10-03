"""Engine layer contracts (frozen): signature / fingerprint / detect data types and checker plugin API.

* ``EngineSignature`` mirrors one ``data/engines/<id>.json`` file (WP7 loads them).
* ``FingerprintResult`` is the shape of ``ctx.results["engine.fingerprint"]``.
* ``DetectResult`` is the shape of ``ctx.results["engine.detect"]``.
* ``EngineChecker`` + ``@register_checker`` define the per-engine resource/script-protection plugins
  (WP7b) that the ``engine.other`` stage dispatches to.
"""
from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable

from ..errors import RegistryError
from ..models import Evidence, Finding, Status, Verdict, to_jsonable

log = logging.getLogger(__name__)

SIGNAL_TYPES = ("file", "dir", "string", "dylib", "symbol", "objc_prefix", "plist_key", "binary_section")
ENGINE_KINDS = ("game_engine", "cross_platform_ui", "web_hybrid", "native", "open_source_lib")


# --- known-engine signatures (data/engines/*.json) -------------------------------------------------
@dataclass
class SignalSpec:
    type: str                 # one of SIGNAL_TYPES
    pattern: str
    weight: float = 0.0
    strong: bool = False      # a strong signal alone confirms the candidate
    unverified: bool = False  # source not verified -> weight must be reduced by the loader
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.type, "pattern": self.pattern, "weight": self.weight, "strong": self.strong,
                "unverified": self.unverified, "note": self.note}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SignalSpec":
        return cls(type=str(d["type"]), pattern=str(d["pattern"]), weight=float(d.get("weight", 0.0)),
                   strong=bool(d.get("strong", False)), unverified=bool(d.get("unverified", False)),
                   note=str(d.get("note", "")))


@dataclass
class EngineSignature:
    id: str
    name: str
    family: str = ""
    kind: str = "game_engine"                      # one of ENGINE_KINDS
    signals: List[SignalSpec] = field(default_factory=list)
    confirm_threshold: float = 1.0
    exclusive_with: List[str] = field(default_factory=list)
    language_hints: List[str] = field(default_factory=list)
    notes: str = ""
    sources: List[str] = field(default_factory=list)   # mandatory in the JSON files (WP7 validates)

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "name": self.name, "family": self.family, "kind": self.kind,
                "signals": [s.to_dict() for s in self.signals], "confirm_threshold": self.confirm_threshold,
                "exclusive_with": list(self.exclusive_with), "language_hints": list(self.language_hints),
                "notes": self.notes, "sources": list(self.sources)}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EngineSignature":
        return cls(id=str(d["id"]), name=str(d.get("name", d["id"])), family=str(d.get("family", "")),
                   kind=str(d.get("kind", "game_engine")),
                   signals=[SignalSpec.from_dict(s) for s in d.get("signals") or []],
                   confirm_threshold=float(d.get("confirm_threshold", 1.0)),
                   exclusive_with=[str(x) for x in d.get("exclusive_with") or []],
                   language_hints=[str(x) for x in d.get("language_hints") or []],
                   notes=str(d.get("notes", "")), sources=[str(x) for x in d.get("sources") or []])


# --- engine.fingerprint -----------------------------------------------------------------------------
@dataclass
class FingerprintHit:
    id: str                       # capability id (e.g. "lua", "box2d", "metal") or, for containers, the archive path
    confidence: float = 0.0
    name: str = ""
    evidence: List[Evidence] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "name": self.name, "confidence": round(float(self.confidence), 4),
                "evidence": [e.to_dict() for e in self.evidence], "extra": to_jsonable(self.extra)}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FingerprintHit":
        return cls(id=str(d["id"]), confidence=float(d.get("confidence", 0.0)), name=str(d.get("name", "")),
                   evidence=[Evidence.from_dict(e) for e in d.get("evidence") or []],
                   extra=dict(d.get("extra") or {}))


_FP_LISTS = ("shader_formats", "script_vms", "physics", "audio", "animation", "network", "asset_formats",
             "containers")


@dataclass
class FingerprintResult:
    # backend id ("metal" | "gles" | "vulkan" | "angle") -> hit; only backends that were detected are present
    render: Dict[str, FingerprintHit] = field(default_factory=dict)
    shader_formats: List[FingerprintHit] = field(default_factory=list)
    script_vms: List[FingerprintHit] = field(default_factory=list)
    physics: List[FingerprintHit] = field(default_factory=list)
    audio: List[FingerprintHit] = field(default_factory=list)
    animation: List[FingerprintHit] = field(default_factory=list)
    network: List[FingerprintHit] = field(default_factory=list)
    asset_formats: List[FingerprintHit] = field(default_factory=list)
    containers: List[FingerprintHit] = field(default_factory=list)
    # {thin_uikit_shell: bool|None, cpp_ratio: float|None, objc_swift_ratio: float|None, main_loop_hints: [str]}
    host: Dict[str, Any] = field(default_factory=dict)
    summary_text: str = ""

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"render": {k: v.to_dict() for k, v in sorted(self.render.items())}}
        for name in _FP_LISTS:
            out[name] = [h.to_dict() for h in getattr(self, name)]
        out["host"] = to_jsonable(self.host)
        out["summary_text"] = self.summary_text
        return out

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FingerprintResult":
        r = cls(render={k: FingerprintHit.from_dict(v) for k, v in (d.get("render") or {}).items()},
                host=dict(d.get("host") or {}), summary_text=str(d.get("summary_text", "")))
        for name in _FP_LISTS:
            setattr(r, name, [FingerprintHit.from_dict(h) for h in d.get(name) or []])
        return r


# --- engine.detect ----------------------------------------------------------------------------------
@dataclass
class EngineMatch:
    id: str
    name: str = ""
    confidence: float = 0.0
    family: str = ""
    kind: str = ""
    confirmed: bool = False
    signals_matched: List[Dict[str, Any]] = field(default_factory=list)   # [{type, pattern, weight, ref}]
    evidence: List[Evidence] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "name": self.name, "confidence": round(float(self.confidence), 4),
                "family": self.family, "kind": self.kind, "confirmed": self.confirmed,
                "signals_matched": to_jsonable(self.signals_matched),
                "evidence": [e.to_dict() for e in self.evidence], "extra": to_jsonable(self.extra)}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EngineMatch":
        return cls(id=str(d["id"]), name=str(d.get("name", "")), confidence=float(d.get("confidence", 0.0)),
                   family=str(d.get("family", "")), kind=str(d.get("kind", "")),
                   confirmed=bool(d.get("confirmed", False)),
                   signals_matched=list(d.get("signals_matched") or []),
                   evidence=[Evidence.from_dict(e) for e in d.get("evidence") or []],
                   extra=dict(d.get("extra") or {}))


@dataclass
class DetectResult:
    primary: Optional[EngineMatch] = None                 # None when no known engine reached its threshold
    candidates: List[EngineMatch] = field(default_factory=list)   # all matches > 0, sorted by confidence desc, then id
    wrapper: Optional[Dict[str, Any]] = None              # {host: {id,name,confidence}, embedded: [{id,name,confidence}]}
    custom: Dict[str, Any] = field(default_factory=lambda: {"verdict": Verdict.UNKNOWN.value, "confidence": 0.0})
    languages: List[Dict[str, Any]] = field(default_factory=list)   # [{lang, confidence, evidence[]}]
    is_game_engine: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)

    # helpers for checkers
    @property
    def primary_id(self) -> Optional[str]:
        return self.primary.id if self.primary else None

    def candidate_ids(self, *, min_confidence: float = 0.0, confirmed_only: bool = False) -> List[str]:
        return [c.id for c in self.candidates
                if c.confidence >= min_confidence and (c.confirmed or not confirmed_only)]

    def has(self, engine_id: str, *, min_confidence: float = 0.0) -> bool:
        return engine_id in self.candidate_ids(min_confidence=min_confidence) or self.primary_id == engine_id

    def to_dict(self) -> Dict[str, Any]:
        return {"primary": self.primary.to_dict() if self.primary else None,
                "candidates": [c.to_dict() for c in self.candidates],
                "wrapper": to_jsonable(self.wrapper), "custom": to_jsonable(self.custom),
                "languages": to_jsonable(self.languages), "is_game_engine": bool(self.is_game_engine),
                "extra": to_jsonable(self.extra)}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DetectResult":
        p = d.get("primary")
        return cls(primary=EngineMatch.from_dict(p) if p else None,
                   candidates=[EngineMatch.from_dict(c) for c in d.get("candidates") or []],
                   wrapper=d.get("wrapper"),
                   custom=dict(d.get("custom") or {"verdict": "unknown", "confidence": 0.0}),
                   languages=list(d.get("languages") or []), is_game_engine=bool(d.get("is_game_engine", False)),
                   extra=dict(d.get("extra") or {}))


# --- checker plugin API -----------------------------------------------------------------------------
@dataclass
class CheckerResult:
    findings: List[Finding] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)   # stored at ctx.results["engine.other"][engine_id]
    status: Status = Status.OK                           # OK | PARTIAL | SKIPPED | FAILED
    reason: Optional[str] = None
    warnings: List[str] = field(default_factory=list)


@runtime_checkable
class EngineChecker(Protocol):
    engine_id: str      # unique, must not start with "_" (reserved keys in ctx.results["engine.other"])

    def applies(self, ctx: Any, detect: DetectResult) -> bool:
        """Cheap check whether this checker is relevant for the detected engine(s)."""

    def run(self, ctx: Any, detect: DetectResult) -> CheckerResult:
        """Inspect ``ctx`` read-only and report. Exceptions are isolated by the dispatcher."""


_CHECKERS: Dict[str, EngineChecker] = {}
_CHECKER_IMPORT_FAILURES: Dict[str, str] = {}


def register_checker(engine_id: str, *, registry: Optional[Dict[str, EngineChecker]] = None):
    """Class decorator: instantiate (no args) and register under ``engine_id``."""

    def deco(cls):
        reg = _CHECKERS if registry is None else registry
        if engine_id.startswith("_"):
            raise RegistryError("checker id %r must not start with '_'" % engine_id)
        if engine_id in reg:
            raise RegistryError("duplicate engine checker %r (%s)" % (engine_id, getattr(cls, "__module__", "?")))
        inst = cls()
        inst.engine_id = engine_id
        reg[engine_id] = inst
        return cls

    return deco


def get_checkers(*, discover: bool = True) -> List[EngineChecker]:
    """All registered checkers sorted by ``engine_id`` (imports ``engines.checkers`` on first call)."""
    if discover:
        importlib.import_module("ipa_analyzer.engines.checkers")
    return [_CHECKERS[k] for k in sorted(_CHECKERS)]


def checker_import_failures() -> Dict[str, str]:
    return dict(_CHECKER_IMPORT_FAILURES)


def _record_checker_import_failure(module: str, error: str) -> None:
    _CHECKER_IMPORT_FAILURES[module] = error
    log.error("engine checker module %s failed to import: %s", module, error)
