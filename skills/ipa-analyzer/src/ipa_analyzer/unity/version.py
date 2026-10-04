"""Unity editor version: parsing of the sources and cross-checking.

Sources and their facts:

* SerializedFile header (``Data/globalgamemanagers``, ``levelN``, ``sharedassetsN.assets``,
  ``resources.assets``, ``Resources/unity_builtin_extra``, ...): big-endian ``u32 metadataSize, u32 fileSize,
  u32 version, u32 dataOffset``; for version >= 9 ``u8 endian + 3 reserved``; for version >= 22 then
  ``u32 metadataSize, i64 fileSize, i64 dataOffset, i64 unknown``; for version >= 7 a NUL-terminated
  Unity version string, then (version >= 8) ``i32 targetPlatform`` in the endianness given above.
  Source: AssetStudio ``SerializedFile.cs`` / UnityPy ``SerializedFile.py``; VERIFIED on real v22 files
  (``2022.3.62f3c1`` and ``6000.3.10f1`` with target platform 9 = iOS).
* UnityFS header ``unity_revision`` (``formats.unityfs``).
* Player binary strings (``macho.scan.UNITY_VERSION_RE``).

Observed on real apps: ``Data/Resources/unity default resources`` keeps the version of the editor build it was
copied from (2022.3.54f1 / 6000.3.9f1 next to 2022.3.62f3c1 / 6000.3.10f1 in all other files), so it is
recorded but ranked last and a disagreement with it is reported as a *stale* conflict.
"""
from __future__ import annotations

import re
import struct
from typing import Any, Dict, List, Optional

__all__ = ["parse_unity_version", "parse_serialized_header", "serialized_source_kind", "resolve_version",
           "VERSION_RE", "SOURCE_PRIORITY"]

VERSION_RE = re.compile(r"^(\d{1,4})\.(\d{1,2})\.(\d{1,3})([abfpx])(\d{1,3})(c\d{1,3})?$")
# Source kinds in adoption order (lower = more authoritative).
SOURCE_PRIORITY: Dict[str, int] = {
    "serialized:globalgamemanagers": 1,
    "binary": 2,
    "serialized": 3,
    "bundle": 4,
    "serialized:default_resources": 5,
}
_STALE_KINDS = ("serialized:default_resources",)
_SUSPECT_KINDS = ("bundle",)


def parse_unity_version(text: str) -> Optional[Dict[str, Any]]:
    """``"2022.3.62f3c1"`` -> ``{text, core: "2022.3.62f3", suffix: "c1", tuple: (2022, 3, 62)}`` (None if not a version)."""
    m = VERSION_RE.match((text or "").strip())
    if not m:
        return None
    major, minor, patch, kind, build, suffix = m.groups()
    return {"text": m.group(0), "core": "%s.%s.%s%s%s" % (major, minor, patch, kind, build),
            "suffix": suffix or "", "tuple": (int(major), int(minor), int(patch))}


def parse_serialized_header(head: bytes) -> Optional[Dict[str, Any]]:
    """Format version, Unity version string and target platform of a SerializedFile prefix (None if not one)."""
    if len(head) < 24:
        return None
    _meta, _fsize, ver, _doff = struct.unpack_from(">IIII", head, 0)
    if not 9 <= ver <= 64:
        return None
    pos = 16
    little = True
    endian = head[pos]
    if endian > 1:
        return None
    little = endian == 0
    pos += 4
    if ver >= 22:
        if len(head) < pos + 28:
            return None
        pos += 4 + 8 + 8 + 8
    end = head.find(b"\x00", pos, pos + 64)
    if end <= pos:
        return None
    try:
        text = head[pos:end].decode("ascii")
    except UnicodeDecodeError:
        return None
    parsed = parse_unity_version(text)
    if parsed is None:
        return None
    platform: Optional[int] = None
    if ver >= 8 and len(head) >= end + 5:
        platform = struct.unpack_from("<i" if little else ">i", head, end + 1)[0]
    return {"format_version": ver, "unity_version": parsed["text"], "target_platform": platform,
            "little_endian": little}


def serialized_source_kind(rel: str) -> Optional[str]:
    """Source kind for an app-relative path that is probably a SerializedFile (``None`` otherwise)."""
    low = rel.lower()
    leaf = low.rsplit("/", 1)[-1]
    if leaf == "globalgamemanagers":
        return "serialized:globalgamemanagers"
    if leaf == "unity default resources":
        return "serialized:default_resources"
    if (leaf in ("unity_builtin_extra", "maindata", "resources.assets", "globalgamemanagers.assets")
            or re.match(r"^(level\d+|sharedassets\d+\.assets)$", leaf)):
        return "serialized"
    return None


def resolve_version(sources: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Combine version observations into ``{value, sources, conflicts}``.

    Each source is ``{source: kind, value: str, ref: str}`` (``kind`` is a key of ``SOURCE_PRIORITY``;
    unknown kinds rank last).  The adopted value is the one of the most authoritative source; values that
    differ in their core (everything but a ``cN`` suffix) from it are reported in ``conflicts`` with a
    ``kind`` (``stale`` for the default-resources file, ``bundle`` for bundles which may come from another
    editor patch, ``real`` otherwise).
    """
    usable = []
    for s in sources:
        p = parse_unity_version(str(s.get("value", "")))
        if p is None:
            continue
        usable.append({"source": s.get("source", ""), "value": p["text"], "ref": s.get("ref", ""),
                       "_core": p["core"], "_prio": SOURCE_PRIORITY.get(str(s.get("source", "")), 9)})
    usable.sort(key=lambda s: (s["_prio"], s["value"], s["ref"]))
    out_sources = [{k: v for k, v in s.items() if not k.startswith("_")} for s in usable]
    if not usable:
        return {"value": None, "sources": [], "conflicts": []}
    top = [s for s in usable if s["_prio"] == usable[0]["_prio"]]
    counts: Dict[str, int] = {}
    for s in top:
        counts[s["value"]] = counts.get(s["value"], 0) + 1
    best = sorted(counts, key=lambda v: (-counts[v], v))[0]
    adopted = next(s for s in top if s["value"] == best)
    conflicts: List[Dict[str, Any]] = []
    by_core: Dict[str, List[Dict[str, Any]]] = {}
    for s in usable:
        by_core.setdefault(s["_core"], []).append(s)
    if len(by_core) > 1:
        for core, group in by_core.items():
            if core == adopted["_core"]:
                continue
            kinds = {g["source"] for g in group}
            if kinds <= set(_STALE_KINDS):
                kind = "stale"
            elif kinds <= set(_SUSPECT_KINDS):
                kind = "bundle"
            else:
                kind = "real"
            conflicts.append({
                "kind": kind, "adopted": adopted["value"], "other": group[0]["value"],
                "sources": [{"source": g["source"], "ref": g["ref"]} for g in group[:5]],
                "note": {"stale": "the default-resources file keeps the version of the editor build it was copied from",
                         "bundle": "AssetBundles may have been built with another editor patch",
                         "real": "independent sources disagree"}[kind]})
    conflicts.sort(key=lambda c: (c["kind"], c["other"]))
    return {"value": adopted["value"], "sources": out_sources, "conflicts": conflicts}


def china_variant(text: Optional[str]) -> bool:
    """True when the version carries a ``cN`` suffix (seen on Unity China builds; hint only, UNVERIFIED)."""
    p = parse_unity_version(text or "")
    return bool(p and p["suffix"])


__all__.append("china_variant")
