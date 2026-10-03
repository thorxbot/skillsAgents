"""``*UsageDescription`` collection and sensitivity lookup (``data/permissions.json``)."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from ..util.paths import resource_dir
from .infoplist import as_str

log = logging.getLogger(__name__)

__all__ = ["load_permission_db", "collect_permissions", "summarize_permissions", "LEVELS", "DEFAULT_LEVEL"]

LEVELS = ("high", "medium", "low")
DEFAULT_LEVEL = "medium"        # unknown keys: sensitivity cannot be judged, report the middle level + known=false
_MAX_TEXT = 1000

_db_cache: Dict[str, Dict[str, Dict[str, str]]] = {}


def load_permission_db(path: Optional[Path] = None) -> Dict[str, Dict[str, str]]:
    """``{key: {level, meaning_zh, meaning_en}}``. Missing / corrupt file -> ``{}`` (logged)."""
    p = Path(path) if path is not None else resource_dir("data") / "permissions.json"
    cache_key = str(p)
    if cache_key in _db_cache:
        return _db_cache[cache_key]
    db: Dict[str, Dict[str, str]] = {}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        entries = raw.get("permissions", {}) if isinstance(raw, dict) else {}
        for k, v in entries.items():
            if isinstance(v, dict):
                level = v.get("level") if v.get("level") in LEVELS else DEFAULT_LEVEL
                db[str(k)] = {"level": level, "meaning_zh": str(v.get("meaning_zh", "")),
                              "meaning_en": str(v.get("meaning_en", ""))}
    except (OSError, ValueError) as exc:
        log.warning("cannot load permission database %s: %s", p, exc)
    _db_cache[cache_key] = db
    return db


def _clip(text: str) -> str:
    return text if len(text) <= _MAX_TEXT else text[:_MAX_TEXT] + "..."


def collect_permissions(info: Mapping[str, Any], localized: Mapping[str, Mapping[str, str]],
                        db: Optional[Mapping[str, Mapping[str, str]]] = None) -> List[Dict[str, Any]]:
    """Every ``*UsageDescription`` key of ``info`` (includes ``NSUserTrackingUsageDescription``).

    ``localized`` is ``{lang: {key: text}}`` from ``InfoPlist.strings``. Sorted by sensitivity, then key.
    Keys whose Info.plist value is not a string are still listed (empty description) because the
    declaration itself is the signal.
    """
    db = db if db is not None else load_permission_db()
    rank = {lv: i for i, lv in enumerate(LEVELS)}
    out: List[Dict[str, Any]] = []
    for key in sorted(str(k) for k in info):
        if not key.endswith("UsageDescription"):
            continue
        entry = db.get(key)
        loc = {}
        for lang in sorted(localized):
            text = localized[lang].get(key)
            if isinstance(text, str) and text.strip():
                loc[lang] = _clip(text.strip())
        out.append({
            "key": key,
            "description": _clip(as_str(info.get(key)) or ""),
            "localized": loc,
            "level": entry["level"] if entry else DEFAULT_LEVEL,
            "meaning_zh": entry["meaning_zh"] if entry else "",
            "meaning_en": entry["meaning_en"] if entry else "",
            "known": entry is not None,
        })
    out.sort(key=lambda p: (rank.get(p["level"], 9), p["key"]))
    return out


def summarize_permissions(perms: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_level = {lv: sum(1 for p in perms if p["level"] == lv) for lv in LEVELS}
    return {"count": len(perms), "by_level": by_level,
            "high_keys": [p["key"] for p in perms if p["level"] == "high"],
            "unknown_keys": [p["key"] for p in perms if not p.get("known")]}
