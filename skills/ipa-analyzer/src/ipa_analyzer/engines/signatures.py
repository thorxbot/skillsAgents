"""Known-engine signature library: loading, validation and the pattern grammar (WP7).

One engine per JSON file in ``data/engines/``; users add or override engines with
``<user data dir>/engines.user.d/*.json`` (``IPA_ANALYZER_HOME`` aware) and ``--engines-user DIR``.
A file holds either one object or a list of objects; a later definition with the same ``id``
replaces the earlier one. Malformed files only produce warnings.

Signal pattern grammar (``SignalSpec.type`` -> ``pattern``)
------------------------------------------------------------
Matching is done against the app-relative view of the bundle (``Payload/X.app/`` stripped).

``file``      glob, case-insensitive. ``*`` = any run inside one path segment, ``**`` = any run across
              segments, ``?`` = one character. No ``/`` in the pattern: matches the base name anywhere in
              the bundle. A ``/`` (a leading ``/`` anchors a bare name at the bundle root): matches the whole
              relative path. Special forms: ``magic:<id>`` (inventory magic id, e.g. ``magic:ccz``) and
              ``head:<ASCII>`` (files whose magic is unknown and whose first bytes equal the ASCII text).
              A trailing ``#<n>`` requires at least ``n`` matching files.
``dir``       glob against directory paths (same rules, a trailing ``/`` is ignored); ``#<n>`` as above.
``string``    literal byte string searched in the readable ``__cstring``-type sections of the Mach-O files
              (never in encrypted ranges); ``re:<regex>`` for a regular expression.
``symbol``    exact symbol name, ``prefix*`` or ``*substring*``, written without the single leading
              underscore that Mach-O adds (``luaL_newstate`` matches ``_luaL_newstate``; the C++ symbol
              ``__ZN7cocos2d...`` is written ``_ZN7cocos2d...``). ``re:<regex>`` is allowed.
``objc_prefix`` Objective-C class name starting with the pattern (``__objc_classname`` and ``OBJC_CLASS_$_`` symbols).
``dylib``     case-insensitive substring of a linked library's install name.
``plist_key`` top-level ``Info.plist`` key, or ``Key=value`` for a string value.
``binary_section`` ``SEGMENT,section`` present in any parsed Mach-O file.

Verification policy: every signal that could not be checked against a primary source (official
documentation, source code, or a real sample) carries ``unverified: true``. The loader then forbids
``strong`` and caps the weight at ``UNVERIFIED_WEIGHT_CAP``, so unverified knowledge can only confirm an
engine through several independent signals.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..util.paths import resource_dir, user_data_dir
from .api import ENGINE_KINDS, SIGNAL_TYPES, EngineSignature, SignalSpec

log = logging.getLogger(__name__)

#: Upper bound for the weight of a signal flagged ``unverified`` (heuristic policy, see module docstring).
UNVERIFIED_WEIGHT_CAP = 0.4
#: Weight floor used for ``strong`` signals (a strong signal alone confirms an engine).
USER_DIR_NAME = "engines.user.d"
_ID_RE = re.compile(r"^[a-z0-9_]+$")
_COUNT_RE = re.compile(r"^(.*)#(\d{1,6})$")
_EXTRA_KEYS = ("embeddable", "open_source_base", "version_regex", "role", "wrapper_host", "layout_expected")


# --- pattern grammar -----------------------------------------------------------------------------
@dataclass(frozen=True)
class ParsedPattern:
    """A signal pattern split into its matching form (``kind``) and value."""

    kind: str                   # glob|magic|head|literal|regex|exact|prefix|contains|keyvalue|section
    value: str
    min_count: int = 1
    regex: Optional["re.Pattern[bytes]"] = field(default=None, compare=False)


def split_count(pattern: str) -> Tuple[str, int]:
    m = _COUNT_RE.match(pattern)
    if m and m.group(1):
        return m.group(1), max(1, int(m.group(2)))
    return pattern, 1


def parse_pattern(sig_type: str, pattern: str) -> ParsedPattern:
    """Parse ``pattern`` for ``sig_type``; raises ``ValueError`` for an invalid pattern."""
    if sig_type not in SIGNAL_TYPES:
        raise ValueError("unknown signal type %r" % sig_type)
    if not pattern:
        raise ValueError("empty pattern")
    if sig_type in ("file", "dir"):
        body, count = split_count(pattern)
        if sig_type == "file" and body.startswith("magic:"):
            return ParsedPattern("magic", body[6:].lower(), count)
        if sig_type == "file" and body.startswith("head:"):
            if not body[5:]:
                raise ValueError("empty head: pattern")
            return ParsedPattern("head", body[5:], count)
        return ParsedPattern("glob", body.lower().rstrip("/") if sig_type == "dir" else body.lower(), count)
    if sig_type in ("string", "symbol") and pattern.startswith("re:"):
        try:
            rx = re.compile(pattern[3:].encode("utf-8"))
        except re.error as exc:
            raise ValueError("invalid regex %r: %s" % (pattern, exc))
        return ParsedPattern("regex", pattern[3:], 1, rx)
    if sig_type == "string":
        return ParsedPattern("literal", pattern)
    if sig_type == "symbol":
        norm = pattern
        if norm.startswith("*") and norm.endswith("*") and len(norm) > 2:
            return ParsedPattern("contains", norm.strip("*"))
        if norm.endswith("*"):
            return ParsedPattern("prefix", norm[:-1])
        return ParsedPattern("exact", norm)
    if sig_type == "objc_prefix":
        return ParsedPattern("prefix", pattern)
    if sig_type == "dylib":
        return ParsedPattern("contains", pattern.lower())
    if sig_type == "plist_key":
        if "=" in pattern:
            return ParsedPattern("keyvalue", pattern)
        return ParsedPattern("exact", pattern)
    # binary_section
    if "," not in pattern:
        raise ValueError("binary_section must look like '__TEXT,__cstring'")
    return ParsedPattern("section", pattern)


# --- validation -----------------------------------------------------------------------------------
def validate_signature_dict(d: Any) -> List[str]:
    """Return a list of problems with one signature object (empty list = valid)."""
    errs: List[str] = []
    if not isinstance(d, dict):
        return ["signature must be a JSON object"]
    sid = d.get("id")
    if not isinstance(sid, str) or not _ID_RE.match(sid):
        errs.append("'id' must be a lower-case [a-z0-9_] string")
    if not isinstance(d.get("name"), str) or not d.get("name"):
        errs.append("'name' is required")
    kind = d.get("kind", "game_engine")
    if kind not in ENGINE_KINDS:
        errs.append("'kind' must be one of %s" % ", ".join(ENGINE_KINDS))
    sources = d.get("sources")
    if not isinstance(sources, list) or not sources or not all(isinstance(s, str) and s.strip() for s in sources):
        errs.append("'sources' must be a non-empty list of strings")
    thr = d.get("confirm_threshold", 1.0)
    if not isinstance(thr, (int, float)) or isinstance(thr, bool) or not 0 < thr <= 3:
        errs.append("'confirm_threshold' must be a number in (0, 3]")
    sigs = d.get("signals")
    if not isinstance(sigs, list) or not sigs:
        errs.append("'signals' must be a non-empty list")
        sigs = []
    for i, s in enumerate(sigs):
        where = "signals[%d]" % i
        if not isinstance(s, dict):
            errs.append("%s must be an object" % where)
            continue
        st, pat = s.get("type"), s.get("pattern")
        if st not in SIGNAL_TYPES:
            errs.append("%s: unknown type %r" % (where, st))
            continue
        if not isinstance(pat, str) or not pat:
            errs.append("%s: 'pattern' is required" % where)
            continue
        w = s.get("weight", 0.0)
        if not isinstance(w, (int, float)) or isinstance(w, bool) or not 0 <= w <= 1:
            errs.append("%s: 'weight' must be in [0, 1]" % where)
        try:
            parse_pattern(st, pat)
        except ValueError as exc:
            errs.append("%s: %s" % (where, exc))
    for key in ("exclusive_with", "language_hints"):
        v = d.get(key, [])
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            errs.append("'%s' must be a list of strings" % key)
    return errs


def _normalise(d: Dict[str, Any]) -> Tuple[EngineSignature, Dict[str, Any]]:
    """Build the dataclass and apply the unverified policy."""
    sig = EngineSignature.from_dict(d)
    for s in sig.signals:
        s.weight = float(s.weight)
        if s.unverified:
            s.strong = False
            s.weight = min(s.weight, UNVERIFIED_WEIGHT_CAP)
        elif s.strong and s.weight < 0.9:
            s.weight = 0.9
    extras = {k: d[k] for k in _EXTRA_KEYS if k in d}
    return sig, extras


@dataclass
class SignatureSet:
    """All loaded engine signatures plus bookkeeping."""

    signatures: Dict[str, EngineSignature] = field(default_factory=dict)
    extras: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    origins: Dict[str, str] = field(default_factory=dict)       # id -> file name
    user_ids: List[str] = field(default_factory=list)           # ids defined / overridden by user directories
    warnings: List[str] = field(default_factory=list)

    def add(self, d: Dict[str, Any], origin: str, *, user: bool = False) -> bool:
        errs = validate_signature_dict(d)
        if errs:
            self.warnings.append("%s: ignored invalid engine definition (%s)" % (origin, "; ".join(errs[:3])))
            return False
        sig, extras = _normalise(d)
        if sig.id in self.signatures:
            log.debug("engine %s from %s replaces the definition from %s", sig.id, origin, self.origins.get(sig.id))
        self.signatures[sig.id] = sig
        self.extras[sig.id] = extras
        self.origins[sig.id] = origin
        if user and sig.id not in self.user_ids:
            self.user_ids.append(sig.id)
        return True

    def ids(self) -> List[str]:
        return sorted(self.signatures)


def _read_json_objects(path: Path, warnings: List[str]) -> List[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        warnings.append("%s: cannot read engine definition (%s)" % (path.name, exc))
        return []
    if isinstance(doc, dict):
        return [doc]
    if isinstance(doc, list):
        return [x for x in doc if isinstance(x, dict)]
    warnings.append("%s: engine definition must be an object or a list of objects" % path.name)
    return []


def load_dir(directory: Path, sigset: SignatureSet, *, user: bool = False) -> int:
    """Load every ``*.json`` of ``directory`` into ``sigset``; returns the number accepted."""
    n = 0
    if not directory.is_dir():
        return 0
    for path in sorted(directory.glob("*.json")):
        for obj in _read_json_objects(path, sigset.warnings):
            if sigset.add(obj, path.name, user=user):
                n += 1
    return n


def default_user_dirs(extra: Optional[Path] = None) -> List[Path]:
    """``<IPA_ANALYZER_HOME>/engines.user.d`` followed by the ``--engines-user`` directory (if any)."""
    dirs = [user_data_dir() / USER_DIR_NAME]
    if extra is not None:
        dirs.append(Path(extra))
    return dirs


def load_signatures(*, data_dir: Optional[Path] = None, user_dirs: Optional[Sequence[Path]] = None,
                    engines_user_dir: Optional[Path] = None) -> SignatureSet:
    """Load built-in plus user signatures. ``user_dirs`` overrides the default user locations."""
    sigset = SignatureSet()
    base = Path(data_dir) if data_dir is not None else resource_dir("data")
    load_dir(base / "engines", sigset)
    for d in (user_dirs if user_dirs is not None else default_user_dirs(engines_user_dir)):
        load_dir(Path(d), sigset, user=True)
    return sigset


def iter_signal_specs(sigs: Iterable[EngineSignature]) -> Iterable[Tuple[EngineSignature, SignalSpec]]:
    for sig in sigs:
        for spec in sig.signals:
            yield sig, spec
