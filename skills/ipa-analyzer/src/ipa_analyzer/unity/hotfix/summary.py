"""Aggregate summary of the hot-update picture: protection tri-states and the one-line description.

``summary_text`` is the English fallback (``data/i18n/*/unity_hotfix.json`` provides the localised pieces
for the report); it reads like ``HybridCLR + xLua (LuaJIT 2.1 bytecode, 64-bit, stripped), scripts in
AssetBundles, remote catalog via Addressables``.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

__all__ = ["overall_protection", "lua_phrase", "build_summary_text"]

_RANK = {"suspected": 3, "yes": 3, "no": 2, "unknown": 1, "n/a": 0}


def overall_protection(per_kind: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Combine ``{lua, js, csharp}`` verdicts: suspected/yes > no > unknown > n/a."""
    best = "n/a"
    for v in per_kind.values():
        if _RANK.get(v["verdict"], 0) > _RANK.get(best, 0):
            best = v["verdict"]
    conf = max([v["confidence"] for v in per_kind.values() if v["verdict"] == best] or [0.3])
    return {"verdict": best, "confidence": conf}


def lua_phrase(lua: Dict[str, Any]) -> str:
    bc = lua["bytecode"]
    parts: List[str] = []
    versions = ", ".join(("LuaJIT " + k[len("luajit_"):]) if k.startswith("luajit_") else "Lua " + k
                         for k in sorted(bc["by_version"]))
    f = lua["files"]
    if bc["by_version"]:
        parts.append("%s bytecode" % versions)
        if len(bc["arch_bits"]) == 1:
            parts.append("%s-bit" % next(iter(bc["arch_bits"])))
        if bc["stripped_count"] and bc["stripped_count"] == sum(bc["by_version"].values()):
            parts.append("stripped")
    elif f["plain"]:
        parts.append("plain source")
    rv = [r for r in lua["runtime_versions"] if r.get("confidence", 0) >= 0.6]
    if rv and not bc["by_version"]:
        r = rv[0]
        parts.append("runtime %s %s" % ("LuaJIT" if r["flavor"] == "luajit" else "Lua", r["version"]))
    if f["encrypted_suspected"]:
        parts.append("%d suspected-encrypted" % f["encrypted_suspected"])
    return ", ".join(parts)


def build_summary_text(frameworks: List[Dict[str, Any]], lua: Dict[str, Any], storage: Dict[str, Any],
                       resource_update: Dict[str, Any], script_protection: Dict[str, str],
                       limits: Optional[List[str]] = None) -> str:
    main = [f for f in frameworks if f["id"] not in ("custom_hotupdate",) and f["kind"] != "resource"
            and not f["id"].endswith("_unattributed") and f["confidence"] >= 0.5]
    names: List[str] = []
    for f in main:
        label = f["name"]
        if f["kind"] == "lua":
            ph = lua_phrase(lua)
            if ph:
                label += " (%s)" % ph
        names.append(label)
    if not names:
        names = [f["name"] for f in frameworks if f["id"].endswith("_unattributed") and f["confidence"] >= 0.4]
    if not names and any(f["id"] == "custom_hotupdate" for f in frameworks):
        names = ["custom hot-update logic (identifier naming hints only)"]
    text = " + ".join(names) if names else "no code hot-update framework identified"
    where: List[str] = []
    if storage["loose_total"]:
        where.append("loose files")
    if storage["in_bundles_total"]:
        where.append("AssetBundles")
    if storage["in_serialized_total"]:
        where.append("serialized files")
    if where:
        text += ", scripts in " + " / ".join(where)
    res = [f for f in frameworks if f["kind"] == "resource" and f["id"] != "custom_hotupdate" and f["confidence"] >= 0.5]
    if res:
        phrase = "resource updates via " + ", ".join(
            "%s%s" % (f["name"], (" " + f["version_hint"]) if f.get("version_hint") else "") for f in res)
        cats = resource_update.get("catalogs") or []
        if any(c.get("kind") == "remote_copy" for c in cats):
            phrase = "remote catalog via " + ", ".join(f["name"] for f in res)
        text += ", " + phrase
    if resource_update.get("hosts"):
        text += " (hosts: %s)" % ", ".join(resource_update["hosts"][:3])
    prot = [k for k, v in script_protection.items() if v == "suspected"]
    if prot:
        text += "; possible script protection: " + ", ".join(sorted(prot))
    if limits:
        text += "; limits: " + "; ".join(limits)
    return text
