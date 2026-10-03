"""``report.json`` serialisation: stable key order, stable list order, large tables moved to side files.

Stability contract: apart from ``generated_at`` and ``duration_s`` the output depends only on the
content of the report, not on the iteration order of the dicts / order-insensitive lists fed in.
``stages``, ``findings``, ``warnings`` and ``evidence`` lists keep their producer order (execution
order is deterministic); collections with no inherent order are sorted by explicit keys below.
"""
from __future__ import annotations

import copy
import json
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from ..models import Report, to_jsonable

__all__ = ["canonicalize", "render_json", "externalize_large", "TOP_LEVEL_ORDER", "EXTERNALIZE_RULES"]

TOP_LEVEL_ORDER = (
    "schema_version", "tool", "generated_at", "input", "app", "classification", "structure", "resources",
    "libraries", "protection", "engine_details", "privacy", "stages", "findings", "warnings", "redaction",
    "summary", "artifacts", "config",
)
FINDING_ORDER = ("id", "verdict", "confidence", "title", "summary", "params", "evidence", "remediation", "tags")
EVIDENCE_ORDER = ("kind", "ref", "detail")
STAGE_ORDER = ("name", "status", "duration_s", "error", "reason", "warnings", "finding_ids")


def _s(x: Any) -> str:
    return "" if x is None else str(x)


def _n(x: Any) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def _by(*keys: str, desc: Tuple[str, ...] = ()) -> Callable[[Any], Tuple[Any, ...]]:
    """Sort key over dict items: numeric keys listed in ``desc`` sort descending, the rest as text."""

    def key(item: Any) -> Tuple[Any, ...]:
        if not isinstance(item, dict):
            return (1, json.dumps(item, sort_keys=True, default=str))
        out: List[Any] = [0]
        for k in keys:
            out.append(-_n(item.get(k)) if k in desc else _s(item.get(k)))
        return tuple(out)

    return key


def _plain(item: Any) -> Tuple[Any, ...]:
    return (0, _s(item)) if not isinstance(item, (dict, list)) else (1, json.dumps(item, sort_keys=True, default=str))


# path (tuple of dict keys; list levels are transparent) -> sort key
_LIST_SORT: Dict[Tuple[str, ...], Callable[[Any], Any]] = {
    ("libraries",): _by("category", "name", "id"),
    ("structure", "binaries"): _by("path"),
    ("structure", "nested_units"): _by("path"),
    ("structure", "languages"): _by("lang", "confidence", desc=("confidence",)),
    ("structure", "engine", "candidates"): _by("confidence", "id", desc=("confidence",)),
    ("resources", "by_category"): _by("size", "category", desc=("size",)),
    ("resources", "by_ext"): _by("size", "ext", desc=("size",)),
    ("resources", "top_files"): _by("size", "path", desc=("size",)),
    ("resources", "archives"): _by("path"),
    ("resources", "localizations"): _plain,
    ("privacy", "permissions"): _by("key"),
    ("privacy", "url_schemes"): _plain,
    ("privacy", "query_schemes"): _plain,
    ("privacy", "trackers"): _by("id", "name"),
    ("privacy", "ats", "exception_domains"): _plain,
    ("app", "extensions"): _by("path"),
    ("app", "devices"): _plain,
    ("app", "background_modes"): _plain,
    ("app", "capabilities"): _plain,
    ("engine_details", "detect", "candidates"): _by("confidence", "id", desc=("confidence",)),
    ("engine_details", "detect", "languages"): _by("lang"),
    ("engine_details", "unity", "bundles", "paths_sample"): _plain,
    ("engine_details", "unity", "dump", "namespaces"): _plain,
}
for _dim in ("shader_formats", "script_vms", "physics", "audio", "animation", "network", "asset_formats", "containers"):
    _LIST_SORT[("engine_details", "fingerprint", _dim)] = _by("confidence", "id", desc=("confidence",))


def _ordered(d: Mapping[str, Any], order: Tuple[str, ...]) -> Dict[str, Any]:
    out = {k: d[k] for k in order if k in d}
    for k in sorted(k for k in d if k not in out):
        out[k] = d[k]
    return out


def _canon(obj: Any, path: Tuple[str, ...]) -> Any:
    if isinstance(obj, dict):
        new = {k: _canon(v, path + (k,)) for k, v in obj.items()}
        if {"kind", "ref"} <= set(new) and set(new) <= {"kind", "ref", "detail"}:
            return _ordered(new, EVIDENCE_ORDER)
        if path in (("findings",), ("protection", "findings")):
            return _ordered(new, FINDING_ORDER)
        if path == ("stages",):
            return _ordered(new, STAGE_ORDER)
        if path == ():
            return _ordered(new, TOP_LEVEL_ORDER)
        return {k: new[k] for k in sorted(new)}
    if isinstance(obj, list):
        # list levels are transparent for the path so ("findings",) matches each finding dict
        items = [_canon(v, path) for v in obj]
        key = _LIST_SORT.get(path)
        if key is not None:
            items = sorted(items, key=key)
        elif path and path[-1] == "children":
            items = sorted(items, key=_by("size", "name", desc=("size",)))
        return items
    return obj


def canonicalize(report: Mapping[str, Any]) -> Dict[str, Any]:
    """Deep-copied report dict with stable key and list order (see module docstring)."""
    return _canon(copy.deepcopy(dict(report)), ())


# --- large tables -> side files ------------------------------------------------------------------
# (dotted path of a list, inline limit, side file, key for the total, key for the side-file name)
EXTERNALIZE_RULES: Tuple[Tuple[Tuple[str, ...], int, str, str, str], ...] = (
    (("engine_details", "unity", "dump", "namespaces"), 100, "unity-namespaces.json", "namespaces_total",
     "namespaces_file"),
    (("engine_details", "unity", "bundles", "paths_sample"), 50, "unity-bundle-paths.json", "paths_sample_total",
     "paths_sample_file"),
)


def externalize_large(report: Dict[str, Any]) -> Dict[str, Any]:
    """Move oversized lists out of ``report`` (in place). Returns ``{relative_file: json_value}``.

    The list is truncated to its inline limit; ``<key>_total`` and ``<key>_file`` (path relative to the
    output directory) are added next to it. Call after :func:`canonicalize`.
    """
    side: Dict[str, Any] = {}
    for path, limit, fname, total_key, file_key in EXTERNALIZE_RULES:
        parent: Any = report
        for p in path[:-1]:
            parent = parent.get(p) if isinstance(parent, dict) else None
            if parent is None:
                break
        if not isinstance(parent, dict):
            continue
        lst = parent.get(path[-1])
        if isinstance(lst, list) and len(lst) > limit:
            side["details/" + fname] = list(lst)
            parent[path[-1]] = lst[:limit]
            parent[total_key] = len(lst)
            parent[file_key] = "details/" + fname
    return side


def render_json(report: Any, *, canonical: bool = True) -> str:
    """Report (``Report`` or dict) -> JSON text with LF line endings and a trailing newline."""
    data = report.to_dict() if isinstance(report, Report) else dict(report)
    data = to_jsonable(data)
    if canonical:
        data = canonicalize(data)
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"
