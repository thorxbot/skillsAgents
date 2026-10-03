"""File classification (path pattern -> magic -> extension) driven by ``data/filetypes.json``.

``classify(rel, magic, confidence)`` maps one file to one of ``CATEGORIES``. The magic type from
``util.magic`` takes precedence over the extension (a ``.dat`` that is really UnityFS becomes
``assetbundle``); weak magics (confidence below ``magic.STRONG_CONFIDENCE``) never override a known
extension. No encryption conclusions are drawn here.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Pattern, Tuple

from .magic import STRONG_CONFIDENCE
from .paths import resource_dir

log = logging.getLogger(__name__)

__all__ = ["CATEGORIES", "FileTypeRules", "load_rules", "classify", "file_ext", "load_inventory_files"]

# Frozen category ids (CONTRACT-FREEZE section 4.2).
CATEGORIES: Tuple[str, ...] = (
    "executable", "framework", "plugin", "dylib", "assets_car", "ui_layout", "localization", "plist", "image",
    "audio", "video", "font", "database", "script", "shader", "model_3d", "engine_data", "assetbundle",
    "packed_archive", "signing", "config", "text", "other",
)


@dataclass
class _Rule:
    regex: Optional[Pattern[str]]
    category: str
    scope: str = "any"          # "app" | "outside" | "any"
    ext: str = ""


@dataclass
class FileTypeRules:
    path_rules: List[_Rule] = field(default_factory=list)
    macho_rules: List[_Rule] = field(default_factory=list)
    macho_default: str = "executable"
    magic: Dict[str, str] = field(default_factory=dict)
    fallback_magic: Dict[str, str] = field(default_factory=dict)
    generic_magic: Dict[str, str] = field(default_factory=dict)
    name_rules: List[_Rule] = field(default_factory=list)
    ext: Dict[str, str] = field(default_factory=dict)


def _rules(items: List[Dict[str, Any]]) -> List[_Rule]:
    out: List[_Rule] = []
    for it in items:
        rx = re.compile(it["regex"]) if it.get("regex") else None
        out.append(_Rule(rx, it["category"], it.get("scope", "any"), it.get("ext", "")))
    return out


def _invert(mapping: Dict[str, List[str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for cat, keys in mapping.items():
        for k in keys:
            out[k] = cat
    return out


def parse_rules(doc: Dict[str, Any]) -> FileTypeRules:
    """Build rules from a decoded ``filetypes.json`` document (also used by tests)."""
    cats = set(doc.get("categories", CATEGORIES))
    r = FileTypeRules(
        path_rules=_rules(doc.get("path_rules", [])), macho_rules=_rules(doc.get("macho_rules", [])),
        macho_default=doc.get("macho_default", "executable"),
        magic=_invert(doc.get("magic_categories", {})), fallback_magic=_invert(doc.get("fallback_magic_categories", {})),
        generic_magic=_invert(doc.get("generic_magic_categories", {})), name_rules=_rules(doc.get("name_rules", [])),
        ext=_invert(doc.get("ext_categories", {})),
    )
    used = set(r.magic.values()) | set(r.fallback_magic.values()) | set(r.generic_magic.values()) | set(r.ext.values())
    used |= {x.category for x in r.path_rules + r.macho_rules + r.name_rules} | {r.macho_default}
    unknown = used - cats
    if unknown:
        raise ValueError("filetypes.json uses unknown categories: %s" % ", ".join(sorted(unknown)))
    return r


_CACHE: Dict[str, FileTypeRules] = {}


def load_rules(path: Optional[Path] = None) -> FileTypeRules:
    """Load (and cache) the rules from ``data/filetypes.json``."""
    p = Path(path) if path else resource_dir("data") / "filetypes.json"
    key = str(p)
    if key not in _CACHE:
        with open(p, "r", encoding="utf-8") as fh:
            _CACHE[key] = parse_rules(json.load(fh))
    return _CACHE[key]


def file_ext(name: str) -> str:
    """Lower-case extension including the dot (``".png"``), ``""`` if there is none."""
    base = name.rsplit("/", 1)[-1]
    return PurePosixPath(base).suffix.lower()


def _scope_ok(scope: str, in_app: bool) -> bool:
    return scope == "any" or (scope == "app") == in_app


def _first(rules: List[_Rule], rel: str, ext: str, in_app: bool) -> Optional[str]:
    for r in rules:
        if not _scope_ok(r.scope, in_app):
            continue
        if r.ext and r.ext != ext:
            continue
        if r.regex is not None and not r.regex.search(rel):
            continue
        return r.category
    return None


def classify(rel: str, magic: str, confidence: float = 1.0, *, in_app: bool = True,
             rules: Optional[FileTypeRules] = None) -> str:
    """Category of a file. ``rel`` is relative to the .app root (or the archive name when ``in_app`` is False)."""
    rl = rules or load_rules()
    ext = file_ext(rel)
    hit = _first(rl.path_rules, rel, ext, in_app)
    if hit:
        return hit
    strong = confidence >= STRONG_CONFIDENCE
    if magic == "macho" and strong:
        return _first(rl.macho_rules, rel, ext, in_app) or rl.macho_default
    if strong and magic in rl.magic:
        return rl.magic[magic]
    hit = _first(rl.name_rules, rel, ext, in_app)
    if hit:
        return hit
    if ext in rl.ext:
        return rl.ext[ext]
    if magic == "macho":      # weak Mach-O signature and nothing else to go on
        return _first(rl.macho_rules, rel, ext, in_app) or rl.macho_default
    for table in (rl.magic, rl.fallback_magic, rl.generic_magic):
        if magic in table:
            return table[magic]
    return "other"


def load_inventory_files(inventory: Dict[str, Any], out_dir: Optional[Path]) -> List[Dict[str, Any]]:
    """Full file table of an ``inventory`` result.

    ``ctx.results["inventory"]["files"]`` holds at most ``files_total`` entries but may be truncated for
    very large archives (``files_truncated``); in that case the complete table is read from
    ``<out_dir>/<inventory_file>``. Falls back to the truncated list if the file is unavailable.
    """
    files = list(inventory.get("files") or [])
    if not inventory.get("files_truncated") or out_dir is None:
        return files
    rel = inventory.get("inventory_file")
    if not rel:
        return files
    try:
        with open(Path(out_dir) / rel, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        full = doc.get("files") if isinstance(doc, dict) else None
        if isinstance(full, list):
            return full
    except (OSError, ValueError):
        log.debug("could not read %s", rel, exc_info=True)
    return files
