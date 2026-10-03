"""Core data contracts: Verdict / Status / Evidence / Finding / StageResult / Report.

Frozen public API (see docs/CONTRACT-FREEZE.md). ``to_dict()`` output has a fixed key order for
dataclass fields; free-form payloads (``params``, ``data`` ...) are normalised with
``to_jsonable`` (string keys, JSON-native types).
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import math
import plistlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePath
from typing import Any, Dict, Iterable, List, Optional

from .config import Config  # re-exported for convenience

__all__ = [
    "SCHEMA_VERSION", "Verdict", "Status", "Evidence", "Finding", "StageResult", "Report",
    "Config", "to_jsonable", "dumps_json", "EVIDENCE_KINDS",
]

SCHEMA_VERSION = "1.0"

# Recommended Evidence.kind values (open set; the JSON schema does not enforce it).
EVIDENCE_KINDS = ("file", "plist_key", "macho", "string", "symbol", "heuristic", "tool_output")


class Verdict(str, Enum):
    YES = "yes"
    NO = "no"
    SUSPECTED = "suspected"
    UNKNOWN = "unknown"
    NA = "n/a"


class Status(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    FAILED = "failed"


def to_jsonable(obj: Any, *, sort_keys: bool = False) -> Any:
    """Recursively convert ``obj`` to JSON-native types.

    Handles Enum, dataclass (via ``to_dict`` if present), Path, tuple/set/frozenset (set -> sorted
    list), bytes (-> hex string, not base64, to stay greppable), datetime, plistlib.UID. Dict keys
    must be str/int/bool/None-free; non-str keys are stringified. NaN/Inf floats -> None.
    Raises ``TypeError`` for anything else.
    """
    if obj is None or isinstance(obj, (bool, int, str)):
        if isinstance(obj, Enum):
            return obj.value
        return obj
    if isinstance(obj, Enum):
        return to_jsonable(obj.value, sort_keys=sort_keys)
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else None
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        return to_jsonable(obj.to_dict(), sort_keys=sort_keys)
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_jsonable(getattr(obj, f.name), sort_keys=sort_keys) for f in dataclasses.fields(obj)}
    if isinstance(obj, dict):
        items = []
        for k, v in obj.items():
            if isinstance(k, Enum):
                k = k.value
            if isinstance(k, (int, bool)) or k is None:
                k = str(k)
            if not isinstance(k, str):
                raise TypeError("non-string dict key of type %s" % type(k).__name__)
            items.append((k, to_jsonable(v, sort_keys=sort_keys)))
        if sort_keys:
            items.sort(key=lambda kv: kv[0])
        return dict(items)
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v, sort_keys=sort_keys) for v in obj]
    if isinstance(obj, (set, frozenset)):
        return sorted((to_jsonable(v, sort_keys=sort_keys) for v in obj), key=lambda x: json.dumps(x, sort_keys=True))
    if isinstance(obj, PurePath):
        return obj.as_posix()
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return bytes(obj).hex()
    if isinstance(obj, (_dt.datetime, _dt.date)):
        return obj.isoformat()
    if isinstance(obj, plistlib.UID):
        return obj.data
    raise TypeError("object of type %s is not JSON-serialisable" % type(obj).__name__)


def dumps_json(obj: Any, *, indent: Optional[int] = 2, sort_keys: bool = False) -> str:
    """Deterministic JSON text (UTF-8 friendly, LF newlines, trailing newline)."""
    return json.dumps(to_jsonable(obj, sort_keys=sort_keys), ensure_ascii=False, indent=indent,
                      sort_keys=sort_keys) + "\n"


def _clamp01(x: Any) -> float:
    try:
        v = float(x)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(v):
        return 0.0
    return min(1.0, max(0.0, v))


@dataclass
class Evidence:
    kind: str          # recommended: file | plist_key | macho | string | symbol | heuristic | tool_output
    ref: str           # what the evidence points at (archive path, plist key, symbol name, ...)
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "ref": self.ref, "detail": self.detail}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Evidence":
        return cls(kind=str(d.get("kind", "")), ref=str(d.get("ref", "")), detail=str(d.get("detail", "")))


@dataclass
class Finding:
    id: str
    verdict: Verdict
    confidence: float
    title: str
    summary: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    evidence: List[Evidence] = field(default_factory=list)
    remediation: str = ""
    tags: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.verdict, Verdict):
            self.verdict = Verdict(self.verdict)
        self.confidence = _clamp01(self.confidence)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "verdict": self.verdict.value,
            "confidence": round(self.confidence, 4),
            "title": self.title,
            "summary": self.summary,
            "params": to_jsonable(self.params),
            "evidence": [e.to_dict() for e in self.evidence],
            "remediation": self.remediation,
            "tags": list(self.tags),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        return cls(
            id=str(d["id"]),
            verdict=Verdict(d.get("verdict", "unknown")),
            confidence=d.get("confidence", 0.0),
            title=str(d.get("title", "")),
            summary=str(d.get("summary", "")),
            params=dict(d.get("params") or {}),
            evidence=[Evidence.from_dict(e) for e in d.get("evidence") or []],
            remediation=str(d.get("remediation", "")),
            tags=[str(t) for t in d.get("tags") or []],
        )


@dataclass
class StageResult:
    name: str
    status: Status
    duration_s: float = 0.0
    error: Optional[str] = None      # set when status == FAILED
    reason: Optional[str] = None     # set when status == SKIPPED (and optionally PARTIAL)
    findings: List[Finding] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)   # becomes ctx.results[name]
    warnings: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.status, Status):
            self.status = Status(self.status)

    # --- constructors -------------------------------------------------------------------------
    @classmethod
    def ok(cls, name: str, data: Optional[Dict[str, Any]] = None, findings: Iterable[Finding] = (),
           warnings: Iterable[str] = ()) -> "StageResult":
        return cls(name, Status.OK, data=dict(data or {}), findings=list(findings), warnings=list(warnings))

    @classmethod
    def partial(cls, name: str, data: Optional[Dict[str, Any]] = None, findings: Iterable[Finding] = (),
                warnings: Iterable[str] = (), reason: Optional[str] = None) -> "StageResult":
        return cls(name, Status.PARTIAL, reason=reason, data=dict(data or {}), findings=list(findings),
                   warnings=list(warnings))

    @classmethod
    def skipped(cls, name: str, reason: str, findings: Iterable[Finding] = ()) -> "StageResult":
        return cls(name, Status.SKIPPED, reason=reason, findings=list(findings))

    @classmethod
    def failed(cls, name: str, error: str, data: Optional[Dict[str, Any]] = None) -> "StageResult":
        return cls(name, Status.FAILED, error=error, data=dict(data or {}))

    # --- (de)serialisation --------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "duration_s": round(self.duration_s, 3),
            "error": self.error,
            "reason": self.reason,
            "findings": [f.to_dict() for f in self.findings],
            "data": to_jsonable(self.data),
            "warnings": list(self.warnings),
        }

    def summary_dict(self) -> Dict[str, Any]:
        """Compact form used in ``Report.stages`` (no ``data``)."""
        return {
            "name": self.name,
            "status": self.status.value,
            "duration_s": round(self.duration_s, 3),
            "error": self.error,
            "reason": self.reason,
            "warnings": list(self.warnings),
            "finding_ids": [f.id for f in self.findings],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "StageResult":
        return cls(
            name=str(d["name"]),
            status=Status(d.get("status", "failed")),
            duration_s=float(d.get("duration_s", 0.0) or 0.0),
            error=d.get("error"),
            reason=d.get("reason"),
            findings=[Finding.from_dict(f) for f in d.get("findings") or []],
            data=dict(d.get("data") or {}),
            warnings=[str(w) for w in d.get("warnings") or []],
        )


_REPORT_FIELDS = (
    "schema_version", "tool", "generated_at", "input", "app", "classification", "structure", "resources",
    "libraries", "protection", "engine_details", "privacy", "stages", "findings", "warnings", "redaction",
    "summary", "artifacts", "config",
)


@dataclass
class Report:
    """Top-level ``report.json`` (docs/02-ARCHITECTURE.md section 3.2). See CONTRACT-FREEZE for sources."""

    schema_version: str = SCHEMA_VERSION
    tool: Dict[str, str] = field(default_factory=lambda: {"name": "ipa-analyzer", "version": ""})
    generated_at: str = ""
    input: Dict[str, Any] = field(default_factory=dict)
    app: Dict[str, Any] = field(default_factory=dict)
    classification: Dict[str, Any] = field(default_factory=dict)
    structure: Dict[str, Any] = field(default_factory=dict)
    resources: Dict[str, Any] = field(default_factory=dict)
    libraries: List[Dict[str, Any]] = field(default_factory=list)
    protection: Dict[str, Any] = field(default_factory=lambda: {"findings": []})
    engine_details: Dict[str, Any] = field(default_factory=dict)
    privacy: Dict[str, Any] = field(default_factory=dict)
    stages: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    redaction: Dict[str, Any] = field(default_factory=lambda: {"applied": False, "fields": []})
    # Optional extension points (omitted from output when None):
    summary: Optional[Dict[str, Any]] = None      # executive-summary data (WP8)
    artifacts: Optional[Dict[str, str]] = None    # logical name -> path relative to the output directory
    config: Optional[Dict[str, Any]] = None       # effective Config.to_dict()

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for name in _REPORT_FIELDS:
            v = getattr(self, name)
            if v is None and name in ("summary", "artifacts", "config"):
                continue
            if name == "findings":
                out[name] = [f.to_dict() for f in v]
            elif name == "protection":
                p = to_jsonable({k: x for k, x in v.items() if k != "findings"}, sort_keys=True)
                p["findings"] = [f.to_dict() if isinstance(f, Finding) else to_jsonable(f)
                                 for f in (v.get("findings") or [])]
                out[name] = dict(sorted(p.items()))
            else:
                out[name] = to_jsonable(v, sort_keys=name in (
                    "input", "app", "classification", "structure", "resources", "engine_details", "privacy",
                    "summary", "artifacts", "config", "tool", "redaction"))
        return out

    def to_json(self, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent) + "\n"

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Report":
        kw: Dict[str, Any] = {}
        for name in _REPORT_FIELDS:
            if name in d:
                kw[name] = d[name]
        kw["findings"] = [Finding.from_dict(f) for f in d.get("findings") or []]
        return cls(**kw)
