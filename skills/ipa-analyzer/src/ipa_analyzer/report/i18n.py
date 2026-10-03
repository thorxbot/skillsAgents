"""i18n catalog loader for report rendering.

Layout: ``data/i18n/<lang>/<module>.json`` (one file per work package, top-level JSON object).
Two kinds of keys (CONTRACT-FREEZE section 1): Finding IDs map to ``{"title", "summary",
"remediation"}`` objects; every other key is a UI string prefixed with its module name.

Lookup order for a Finding: catalog[lang] -> catalog["en"] -> the English fallback text carried by the
Finding itself. Templates use ``str.format`` syntax with ``Finding.params`` (attribute / index access
is refused, so a template can never reach into objects).
"""
from __future__ import annotations

import json
import logging
import re
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from ..util.paths import resource_dir

log = logging.getLogger(__name__)

FALLBACK_LANG = "en"
FINDING_FIELDS = ("title", "summary", "remediation")

__all__ = ["I18nError", "I18nConflictError", "Catalog", "FindingText", "load_catalog", "render_template",
           "FALLBACK_LANG"]


class I18nError(Exception):
    """Unreadable or malformed i18n data."""


class I18nConflictError(I18nError):
    """The same top-level key is defined by two files of one language."""

    def __init__(self, conflicts: Sequence[Tuple[str, str, str, str]]) -> None:
        self.conflicts = list(conflicts)   # (lang, key, first_file, second_file)
        lines = ["%s: key %r defined in both %s and %s" % c for c in self.conflicts]
        super().__init__("i18n key conflict(s):\n  " + "\n  ".join(lines))


# --- template rendering --------------------------------------------------------------------------
class _Params(dict):
    def __missing__(self, key: str) -> str:
        return "{%s}" % key


class _SafeFormatter(string.Formatter):
    """Formatter without attribute / index access (``{a.b}``, ``{a[0]}`` are rejected)."""

    def get_field(self, field_name: str, args: Any, kwargs: Any) -> Any:
        if "." in field_name or "[" in field_name:
            raise ValueError("attribute / index access is not allowed: %r" % field_name)
        return self.get_value(field_name, args, kwargs), field_name


_FORMATTER = _SafeFormatter()
_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)(?:![rsa])?(?::[^{}]*)?\}")


def _display_value(v: Any) -> Any:
    if v is None:
        return "-"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (int, float, str)):
        return v
    if isinstance(v, (list, tuple, set, frozenset)):
        return ", ".join(str(_display_value(x)) for x in (sorted(v, key=str) if isinstance(v, (set, frozenset)) else v))
    if isinstance(v, dict):
        return ", ".join("%s=%s" % (k, _display_value(x)) for k, x in sorted(v.items(), key=lambda kv: str(kv[0])))
    return str(v)


def render_template(template: str, params: Optional[Mapping[str, Any]] = None) -> str:
    """Interpolate ``{name}`` placeholders; unknown names stay literal; never raises."""
    if not template:
        return ""
    p = _Params({str(k): _display_value(v) for k, v in (params or {}).items()})
    try:
        return _FORMATTER.vformat(template, (), p)
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        # bad format spec / refused field: fall back to plain substitution of simple names
        return _PLACEHOLDER_RE.sub(lambda m: str(p[m.group(1)]) if m.group(1) in p else m.group(0), template)


@dataclass
class FindingText:
    title: str
    summary: str
    remediation: str
    localized: bool    # True when title/summary came from the requested language


# --- catalog -------------------------------------------------------------------------------------
@dataclass
class Catalog:
    lang: str
    tables: Dict[str, Dict[str, Any]] = field(default_factory=dict)   # lang -> merged mapping
    warnings: List[str] = field(default_factory=list)                 # load-time problems
    missing_findings: List[str] = field(default_factory=list)         # finding ids without ``lang`` text

    # -- construction
    @classmethod
    def from_mapping(cls, lang: str, tables: Mapping[str, Mapping[str, Any]]) -> "Catalog":
        return cls(lang=lang, tables={k: dict(v) for k, v in tables.items()})

    # -- raw lookup
    def has(self, key: str, *, any_lang: bool = False) -> bool:
        if key in self.tables.get(self.lang, {}):
            return True
        return any_lang and key in self.tables.get(FALLBACK_LANG, {})

    def raw(self, key: str, default: Any = None) -> Any:
        for lang in (self.lang, FALLBACK_LANG):
            tbl = self.tables.get(lang)
            if tbl is not None and key in tbl:
                return tbl[key]
        return default

    def t(self, key: str, default: str = "", **params: Any) -> str:
        """UI string for ``key`` (requested language, then English, then ``default``, then the key)."""
        v = self.raw(key)
        if not isinstance(v, str):
            v = default if default else key
        return render_template(v, params) if params or "{" in v else v

    def tr(self, key: str, default: str = "") -> str:
        """Like ``t`` without interpolation (strings containing literal braces)."""
        v = self.raw(key)
        return v if isinstance(v, str) else (default or key)

    # -- findings
    def _entry(self, lang: str, fid: str) -> Optional[Mapping[str, Any]]:
        e = self.tables.get(lang, {}).get(fid)
        return e if isinstance(e, dict) else None

    def finding_text(self, finding: Mapping[str, Any]) -> FindingText:
        """Localised title / summary / remediation of a Finding dict (see module docstring)."""
        fid = str(finding.get("id", ""))
        params = finding.get("params") if isinstance(finding.get("params"), dict) else {}
        entry_lang = self._entry(self.lang, fid)
        entry_en = self._entry(FALLBACK_LANG, fid)
        out: Dict[str, str] = {}
        localized = True
        for fld in FINDING_FIELDS:
            tmpl: Optional[str] = None
            for entry in (entry_lang, entry_en):
                if entry and isinstance(entry.get(fld), str) and entry.get(fld):
                    tmpl = entry[fld]
                    break
            if tmpl is None:
                tmpl = str(finding.get(fld) or "")
            out[fld] = render_template(tmpl, params)
        if self.lang != FALLBACK_LANG and not (entry_lang and isinstance(entry_lang.get("title"), str)
                                               and entry_lang.get("title")):
            localized = False
            if fid and fid not in self.missing_findings:
                self.missing_findings.append(fid)
        return FindingText(out["title"], out["summary"], out["remediation"], localized)

    def collect_warnings(self) -> List[str]:
        """Warnings for the report (load problems + findings lacking text in the requested language)."""
        out = list(self.warnings)
        if self.missing_findings:
            ids = sorted(self.missing_findings)
            shown = ", ".join(ids[:12]) + (", ... (+%d)" % (len(ids) - 12) if len(ids) > 12 else "")
            out.append("i18n: %d finding id(s) have no '%s' text and fell back to the built-in English text: %s"
                       % (len(ids), self.lang, shown))
        return out


def _read_json_object(path: Path) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise I18nError("cannot read i18n file %s: %s" % (path, exc))
    if not isinstance(data, dict):
        raise I18nError("i18n file %s must contain a JSON object at top level" % path)
    return data


def _load_lang(base: Path, lang: str, on_conflict: str, warnings: List[str],
               modules: Optional[Iterable[str]]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    owner: Dict[str, str] = {}
    conflicts: List[Tuple[str, str, str, str]] = []
    d = base / lang
    if not d.is_dir():
        return merged
    wanted = set(modules) if modules is not None else None
    for path in sorted(d.glob("*.json"), key=lambda p: p.name):
        if wanted is not None and path.stem not in wanted:
            continue
        try:
            data = _read_json_object(path)
        except I18nError as exc:
            if on_conflict == "raise":
                raise
            warnings.append("i18n: %s" % exc)
            continue
        for key, val in data.items():
            if key in merged:
                conflicts.append((lang, key, owner[key], path.name))
                if on_conflict == "warn":
                    continue          # first definition wins
            merged[key] = val
            owner.setdefault(key, path.name)
    if conflicts:
        if on_conflict == "raise":
            raise I18nConflictError(conflicts)
        for c in conflicts:
            warnings.append("i18n: %s: key %r defined in both %s and %s (kept the first)" % c)
    return merged


def load_catalog(lang: str, *, data_dir: Optional[Path] = None, on_conflict: str = "raise",
                 modules: Optional[Iterable[str]] = None) -> Catalog:
    """Merge ``<data>/i18n/<lang>/*.json`` (and English as fallback) into a ``Catalog``.

    ``on_conflict``: ``"raise"`` (default) raises ``I18nConflictError`` listing both files;
    ``"warn"`` keeps the first definition and records a warning (used by the report stage so that
    another module's mistake never prevents a report). ``modules`` restricts loading to those file stems.
    """
    if on_conflict not in ("raise", "warn"):
        raise ValueError("on_conflict must be 'raise' or 'warn'")
    base = (Path(data_dir) if data_dir is not None else resource_dir("data")) / "i18n"
    warnings: List[str] = []
    tables: Dict[str, Dict[str, Any]] = {}
    for code in dict.fromkeys([FALLBACK_LANG, lang]):
        tables[code] = _load_lang(base, code, on_conflict, warnings, modules)
    cat = Catalog(lang=lang, tables=tables, warnings=warnings)
    if not tables.get(lang) and not tables.get(FALLBACK_LANG):
        cat.warnings.append("i18n: no catalog found under %s" % base)
    return cat
