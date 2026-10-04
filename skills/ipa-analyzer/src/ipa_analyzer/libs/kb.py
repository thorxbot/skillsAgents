"""Libs knowledge base: loading, validation, user overrides and lookup indexes.

Format: ``references/libs-kb-format.md``. ``data/libs.json`` ships with the skill; users add or override
entries (same ``id`` replaces the shipped entry) in ``libs.user.json``. A malformed user file or entry only
produces a warning.
"""
from __future__ import annotations

import fnmatch
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Pattern, Sequence, Tuple

from ..util import paths as _paths

log = logging.getLogger(__name__)

MATCH_FIELDS: Tuple[str, ...] = ("dylib", "framework", "objc_prefix", "symbol_regex", "string", "bundle", "namespace",
                                 "file", "plist_key", "url_scheme", "query_scheme")
DEFAULT_CATEGORIES: Tuple[str, ...] = ("engine", "network", "ads", "analytics", "crash", "payment", "social", "push",
                                       "media", "security", "hotfix", "storage", "ui", "system", "other")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-]*$")
_GLOB_CHARS = set("*?[")
USER_FILE_NAME = "libs.user.json"


@dataclass(frozen=True)
class LibEntry:
    id: str
    name: str
    vendor: str
    category: str
    purpose_zh: str
    purpose_en: str
    tags: Tuple[str, ...] = ()
    homepage: str = ""
    merge_only: bool = False
    match: Dict[str, Tuple[str, ...]] = field(default_factory=dict)
    sources: Tuple[str, ...] = ()
    user: bool = False

    @classmethod
    def from_dict(cls, d: Dict[str, Any], *, user: bool = False) -> "LibEntry":
        match = {k: tuple(str(x) for x in v) for k, v in (d.get("match") or {}).items() if k in MATCH_FIELDS and v}
        return cls(id=d["id"], name=d["name"], vendor=str(d.get("vendor", "")), category=d["category"],
                   purpose_zh=d.get("purpose_zh", ""), purpose_en=d.get("purpose_en", ""),
                   tags=tuple(str(t) for t in d.get("tags") or ()), homepage=str(d.get("homepage", "")),
                   merge_only=bool(d.get("merge_only", False)), match=match,
                   sources=tuple(str(s) for s in d.get("sources") or ()), user=user)


def is_glob(token: str) -> bool:
    return any(c in token for c in _GLOB_CHARS)


def norm_token(field_name: str, token: str) -> str:
    """Canonical (lower-case) form of a match token used for lookups."""
    t = token.strip()
    if field_name == "bundle" and t.lower().endswith(".bundle"):
        t = t[:-7]
    if field_name == "framework" and t.lower().endswith(".framework"):
        t = t[:-10]
    return t if field_name in ("objc_prefix", "string", "namespace", "symbol_regex") else t.lower()


def validate_entry(d: Any, categories: Sequence[str] = DEFAULT_CATEGORIES) -> List[str]:
    """Problems with one raw entry (empty list = valid)."""
    errs: List[str] = []
    if not isinstance(d, dict):
        return ["entry is not an object"]
    eid = d.get("id")
    if not isinstance(eid, str) or not _ID_RE.match(eid):
        errs.append("invalid id %r" % (eid,))
    for key in ("name", "purpose_en", "purpose_zh"):
        if not isinstance(d.get(key), str) or not d.get(key, "").strip():
            errs.append("missing %s" % key)
    if d.get("category") not in categories:
        errs.append("category %r not in whitelist" % (d.get("category"),))
    if "vendor" in d and not isinstance(d["vendor"], str):
        errs.append("vendor must be a string")
    tags = d.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        errs.append("tags must be a list of strings")
    match = d.get("match", {})
    if not isinstance(match, dict):
        return errs + ["match must be an object"]
    for k, v in match.items():
        if k not in MATCH_FIELDS:
            errs.append("unknown match field %r" % k)
            continue
        if not isinstance(v, list) or not all(isinstance(x, str) and x.strip() for x in v):
            errs.append("match.%s must be a list of non-empty strings" % k)
            continue
        if k == "symbol_regex":
            for rx in v:
                try:
                    re.compile(rx)
                except re.error as exc:
                    errs.append("match.symbol_regex %r does not compile: %s" % (rx, exc))
    if not match and not d.get("merge_only"):
        errs.append("entry has no match rules and is not merge_only")
    return errs


def _entries_of(doc: Any) -> List[Any]:
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict):
        for key in ("libs", "items", "entries"):
            if isinstance(doc.get(key), list):
                return doc[key]
    return []


def validate_kb_doc(doc: Any) -> List[str]:
    """Whole-document checks: per-entry problems, duplicate ids and conflicting match rules."""
    errs: List[str] = []
    cats = tuple(doc.get("categories") or DEFAULT_CATEGORIES) if isinstance(doc, dict) else DEFAULT_CATEGORIES
    seen_ids: Dict[str, int] = {}
    owners: Dict[Tuple[str, str], str] = {}
    for i, e in enumerate(_entries_of(doc)):
        for p in validate_entry(e, cats):
            errs.append("entry %d (%s): %s" % (i, e.get("id") if isinstance(e, dict) else "?", p))
        if not isinstance(e, dict) or not isinstance(e.get("id"), str):
            continue
        if e["id"] in seen_ids:
            errs.append("duplicate id %s" % e["id"])
        seen_ids[e["id"]] = i
        for k, vals in (e.get("match") or {}).items():
            if not isinstance(vals, list):
                continue
            for v in vals:
                if not isinstance(v, str):
                    continue
                key = (k, norm_token(k, v))
                if key in owners and owners[key] != e["id"]:
                    errs.append("rule %s:%s claimed by both %s and %s" % (k, v, owners[key], e["id"]))
                owners.setdefault(key, e["id"])
    return errs


def _glob_re(token: str) -> Pattern[str]:
    return re.compile(fnmatch.translate(token), re.IGNORECASE)


class KnowledgeBase:
    """Entries plus lookup indexes. Build with :func:`load_kb`."""

    def __init__(self, entries: Iterable[LibEntry], warnings: Optional[List[str]] = None) -> None:
        self.entries: Dict[str, LibEntry] = {e.id: e for e in entries}
        self.warnings: List[str] = list(warnings or [])
        self._literal: Dict[str, Dict[str, List[str]]] = {f: {} for f in MATCH_FIELDS}
        self._globs: Dict[str, List[Tuple[Pattern[str], str]]] = {f: [] for f in MATCH_FIELDS}
        self.symbol_rules: List[Tuple[Pattern[str], str]] = []
        self._string_tokens: Dict[str, List[str]] = {}
        self._objc: Dict[str, List[str]] = {}
        self._objc_tuple: Tuple[str, ...] = ()
        self._string_re: Optional[Pattern[str]] = None
        self._build()

    # -- index construction ------------------------------------------------------------------
    def _build(self) -> None:
        for e in self.entries.values():
            for f, tokens in e.match.items():
                for tok in tokens:
                    if f == "symbol_regex":
                        try:
                            self.symbol_rules.append((re.compile(tok), e.id))
                        except re.error:
                            self.warnings.append("lib %s: bad symbol_regex %r skipped" % (e.id, tok))
                    elif f == "string":
                        self._string_tokens.setdefault(tok, []).append(e.id)
                    elif f == "objc_prefix":
                        self._objc.setdefault(tok, []).append(e.id)
                    elif f in ("framework", "bundle", "dylib", "file") and is_glob(tok):
                        self._globs[f].append((_glob_re(norm_token(f, tok) if f != "file" else tok), e.id))
                    else:
                        self._literal[f].setdefault(norm_token(f, tok), []).append(e.id)
        self._objc_tuple = tuple(sorted(self._objc))
        if self._string_tokens:
            self._string_re = re.compile("|".join(re.escape(t) for t in sorted(self._string_tokens, key=len, reverse=True)))

    # -- lookups -----------------------------------------------------------------------------
    def lookup(self, field_name: str, value: str) -> List[str]:
        """Entry ids whose ``field_name`` rules match ``value`` (framework/bundle/dylib/file/plist_key/...)."""
        v = norm_token(field_name, value) if field_name != "file" else value.lower()
        out = list(self._literal[field_name].get(v, ()))
        for rx, eid in self._globs[field_name]:
            if rx.match(v if field_name != "file" else value):
                out.append(eid)
        return sorted(set(out))

    def lookup_file(self, rel_path: str) -> List[str]:
        """Entry ids whose ``file`` rules match an app-relative path (a bare name matches any directory)."""
        low = rel_path.lower()
        base = low.rsplit("/", 1)[-1]
        out = list(self._literal["file"].get(low, ())) + list(self._literal["file"].get(base, ()))
        for tok, ids in self._literal["file"].items():
            if "/" in tok and (low.endswith("/" + tok)):
                out.extend(ids)
        for rx, eid in self._globs["file"]:
            if rx.match(rel_path) or rx.match(base):
                out.append(eid)
        return sorted(set(out))

    def lookup_objc(self, class_name: str) -> List[Tuple[str, str]]:
        """``[(entry_id, prefix)]`` for ObjC class names starting with a known prefix."""
        if not self._objc_tuple or not class_name.startswith(self._objc_tuple):
            return []
        return [(eid, p) for p in self._objc_tuple if class_name.startswith(p) for eid in self._objc[p]]

    def lookup_namespace(self, ns: str) -> List[Tuple[str, str]]:
        """Entry ids for a C# namespace (token equals it or is a dotted ancestor)."""
        out: List[Tuple[str, str]] = []
        parts = ns.split(".")
        for i in range(1, len(parts) + 1):
            tok = ".".join(parts[:i])
            for eid in self._literal["namespace"].get(tok, ()):
                out.append((eid, tok))
        return out

    def lookup_symbol(self, name: str) -> List[Tuple[str, str]]:
        return [(eid, rx.pattern) for rx, eid in self.symbol_rules if rx.search(name)]

    def find_strings(self, text: str) -> List[Tuple[str, str]]:
        """``[(entry_id, token)]`` for literal string rules occurring in ``text``."""
        if self._string_re is None:
            return []
        out: List[Tuple[str, str]] = []
        for m in self._string_re.finditer(text):
            for eid in self._string_tokens.get(m.group(0), ()):
                out.append((eid, m.group(0)))
        return out

    @property
    def has_string_rules(self) -> bool:
        return self._string_re is not None

    def brand_words(self) -> Dict[str, str]:
        """Lower-case brand word -> entry name (first word of names/vendors, length >= 5) for name hints."""
        words: Dict[str, str] = {}
        for e in self.entries.values():
            for src in (e.name, e.vendor):
                first = re.split(r"[^A-Za-z0-9]+", src.strip())[0] if src.strip() else ""
                if len(first) >= 5 and first.lower() not in words:
                    words[first.lower()] = e.name
        return words


def _read_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def default_user_path() -> Path:
    return _paths.user_data_dir() / USER_FILE_NAME


def load_kb(user_path: Optional[Path] = None, data_dir: Optional[Path] = None) -> KnowledgeBase:
    """Load ``data/libs.json`` merged with the user file (``user_path`` or ``libs.user.json`` in the user dir).

    Invalid shipped or user entries are skipped with a warning; the result is always usable.
    """
    warnings: List[str] = []
    base = Path(data_dir) if data_dir else _paths.resource_dir("data")
    entries: Dict[str, LibEntry] = {}
    cats: Sequence[str] = DEFAULT_CATEGORIES

    def absorb(path: Path, user: bool) -> None:
        nonlocal cats
        try:
            doc = _read_json(path)
        except (OSError, ValueError) as exc:
            warnings.append("libs knowledge base %s unreadable: %s" % (path, exc))
            return
        if isinstance(doc, dict) and isinstance(doc.get("categories"), list) and not user:
            cats = tuple(str(c) for c in doc["categories"])
        raw = _entries_of(doc)
        if not raw and not (isinstance(doc, (list, dict))):
            warnings.append("libs knowledge base %s has an unexpected structure" % path)
        for i, d in enumerate(raw):
            problems = validate_entry(d, cats)
            if problems:
                warnings.append("%s entry %d skipped: %s" % (path.name, i, "; ".join(problems)))
                continue
            entries[d["id"]] = LibEntry.from_dict(d, user=user)

    shipped = base / "libs.json"
    if shipped.is_file():
        absorb(shipped, False)
    else:
        warnings.append("libs knowledge base %s not found" % shipped)
    upath = Path(user_path) if user_path else default_user_path()
    if upath.is_file():
        absorb(upath, True)
    elif user_path:
        warnings.append("user libs file %s not found" % upath)
    return KnowledgeBase(entries.values(), warnings)
