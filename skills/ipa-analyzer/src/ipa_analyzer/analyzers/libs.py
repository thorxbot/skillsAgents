"""Stage ``libs`` (WP4): which third-party libraries / SDKs the app uses and what they are for.

Evidence sources, strongest first: framework directories and ``LC_LOAD_DYLIB`` references, resource bundles and
well-known files, ObjC class names (readable only in decrypted slices) and imported ``_OBJC_CLASS_$_`` symbols
(readable even when the code is FairPlay-encrypted, because the symbol table lives outside the encrypted range),
Swift module names, Info.plist keys, Unity dump namespaces and the hotfix / fingerprint stages. Anything that
no rule explains goes to ``unknown`` with an empty purpose; the optional ``hint`` is a name-only guess.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..context import AnalysisContext
from ..libs import LibMatcher, Signal, load_kb, load_sysframeworks
from ..libs.sysframeworks import framework_name_of
from ..macho import MachOError, parse
from ..models import Evidence, Finding, StageResult, Verdict
from ..registry import register
from ..util.filetypes import load_inventory_files
from ..util.plist_utils import load_plist

log = logging.getLogger(__name__)

NAME = "libs"
MAX_CLASSES_PER_BINARY = 300_000
MAX_SYMBOLS_PER_BINARY = 300_000
MAX_STRINGS_PER_BINARY = 3_000_000
MAX_VERSION_READS = 80
MAX_UNKNOWN_EVIDENCE = 4
_SWIFT_SYM = re.compile(r"^_?\$[sS]([1-9][0-9]{0,2})")
_PRIVACY_SUFFIX = re.compile(r"(_?PrivacyInfo|_Privacy)$")
_DIM_CATEGORY = {"physics": "engine", "audio": "media", "animation": "engine", "network": "network", "script_vms": "hotfix"}
_DIM_PURPOSE = {
    "physics": ("物理引擎 / 中间件(由引擎指纹阶段识别)", "Physics engine / middleware (identified by the engine fingerprint stage)"),
    "audio": ("音频引擎 / 中间件(由引擎指纹阶段识别)", "Audio engine / middleware (identified by the engine fingerprint stage)"),
    "animation": ("动画 / 骨骼动画运行时(由引擎指纹阶段识别)", "Animation runtime (identified by the engine fingerprint stage)"),
    "network": ("网络 / 序列化中间件(由引擎指纹阶段识别)", "Networking / serialization middleware (identified by the engine fingerprint stage)"),
    "script_vms": ("脚本虚拟机 / 运行时(由引擎指纹阶段识别)", "Scripting VM / runtime (identified by the engine fingerprint stage)"),
}
_PRIVACY_TAG_MAP = {"ads": ("ads",), "analytics": ("analytics",), "attribution": ("analytics", "tracking"),
                    "tracking": ("tracking",), "social": ("social",)}


class _Components:
    """Observed libraries-to-be-explained (frameworks, dylibs, resource bundles) and whether a rule matched them."""

    def __init__(self) -> None:
        self.items: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def note(self, kind: str, name: str, ref: str, detail: str) -> Dict[str, Any]:
        rec = self.items.setdefault((kind, name.lower()), {"kind": kind, "name": name, "evidence": [], "matched": False})
        ev = {"kind": "file" if "dir" in detail or "bundle" in detail else "macho", "ref": ref, "detail": detail}
        if ev not in rec["evidence"] and len(rec["evidence"]) < MAX_UNKNOWN_EVIDENCE:
            rec["evidence"].append(ev)
        return rec


def _leaf(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _read_info_version(ctx: AnalysisContext, unit_path: str) -> Optional[str]:
    src = ctx.source
    if src is None:
        return None
    try:
        with src.open(unit_path.rstrip("/") + "/Info.plist") as fh:
            data = fh.read(2 * 1024 * 1024)
    except (KeyError, OSError, ValueError):
        return None
    plist = load_plist(data)
    if isinstance(plist, dict):
        for key in ("CFBundleShortVersionString", "CFBundleVersion"):
            val = plist.get(key)
            if isinstance(val, str) and val.strip() and len(val) < 64:
                return val.strip()
    return None


def _scan_binary(ctx: AnalysisContext, binary: Dict[str, Any], matcher: LibMatcher, stats: Dict[str, int],
                 warnings: List[str]) -> bool:
    """Feed ObjC class names / imported symbols / strings of one binary. Returns False on a read failure."""
    path = binary["path"]
    local = ctx.extract([path]).get(path)
    if local is None:
        warnings.append("cannot extract %s for scanning" % path)
        return False
    kb = matcher.kb
    try:
        with parse(local) as mf:
            sl = mf.select_slice() or (mf.slices[0] if mf.slices else None)
            if sl is None:
                return True
            encrypted = sl.is_encrypted
            stats["encrypted" if encrypted else "plain"] += 1
            for n, cname in enumerate(sl.objc_class_names(skip_encrypted=True)):
                if n >= MAX_CLASSES_PER_BINARY:
                    break
                matcher.add(Signal("objc_class", cname, ref=path))
            swift_mods = set()
            for n, sym in enumerate(sl.iter_imported_symbols()):
                if n >= MAX_SYMBOLS_PER_BINARY:
                    break
                name = sym.name
                if name.startswith("_OBJC_CLASS_$_"):
                    matcher.add(Signal("objc_class", name[14:], ref=path, via="import"))
                    continue
                m = _SWIFT_SYM.match(name)
                if m:
                    mod = name[m.end():m.end() + int(m.group(1))]
                    if mod.isidentifier():
                        swift_mods.add(mod)
                if kb.symbol_rules:
                    matcher.add(Signal("symbol", name, ref=path))
            for mod in sorted(swift_mods):
                matcher.add(Signal("swift_module", mod, ref=path))
            if kb.has_string_rules:
                for n, s in enumerate(sl.iter_cstrings(4, skip_encrypted=True)):
                    if n >= MAX_STRINGS_PER_BINARY:
                        break
                    matcher.add(Signal("string", s, ref=path))
    except MachOError as exc:
        warnings.append("%s: %s" % (path, exc))
        return False
    except (OSError, ValueError, MemoryError) as exc:
        warnings.append("cannot scan %s: %s" % (path, exc))
        return False
    return True


def _plist_signals(ctx: AnalysisContext, matcher: LibMatcher) -> None:
    src = ctx.source
    if src is not None:
        try:
            with src.open(ctx.app_path("Info.plist")) as fh:
                plist = load_plist(fh.read(8 * 1024 * 1024))
        except (KeyError, OSError, ValueError):
            plist = None
        if isinstance(plist, dict):
            for key in plist:
                if isinstance(key, str):
                    matcher.add(Signal("plist_key", key, ref=ctx.app_path("Info.plist")))
    meta = ctx.results.get("meta") or {}
    for s in meta.get("url_schemes") or []:
        if isinstance(s, str):
            matcher.add(Signal("url_scheme", s, ref="Info.plist:CFBundleURLTypes"))
    for s in meta.get("query_schemes") or []:
        if isinstance(s, str):
            matcher.add(Signal("query_scheme", s, ref="Info.plist:LSApplicationQueriesSchemes"))


def _stage_signals(ctx: AnalysisContext, matcher: LibMatcher) -> None:
    unity = ctx.results.get("engine.unity") or {}
    dump = unity.get("dump") if isinstance(unity.get("dump"), dict) else {}
    for ns in (dump.get("namespaces") or [])[:2000]:
        if isinstance(ns, str):
            matcher.add(Signal("namespace", ns, ref="engine.unity:dump"))
    hot = ctx.results.get("engine.unity.hotfix") or {}
    for fw in hot.get("frameworks") or []:
        if isinstance(fw, dict) and fw.get("id"):
            matcher.add(Signal("direct", lib_id=str(fw["id"]), source_kind="hotfix", name=str(fw.get("name") or fw["id"]),
                               category="hotfix", confidence=float(fw.get("confidence") or 0.5),
                               version=fw.get("version_hint") or None, ref="engine.unity.hotfix",
                               purpose_zh="热更新 / 脚本框架(由 Unity 热更新阶段识别)",
                               purpose_en="Hot-update / scripting framework (identified by the Unity hotfix stage)",
                               evidence=[e for e in fw.get("evidence") or [] if isinstance(e, dict)]))
    lua = hot.get("lua") if isinstance(hot.get("lua"), dict) else {}
    for rv in lua.get("runtime_versions") or []:
        if isinstance(rv, dict):
            lid = "luajit" if rv.get("flavor") == "luajit" else "lua"
            matcher.add(Signal("direct", lib_id=lid, source_kind="hotfix", name="LuaJIT" if lid == "luajit" else "Lua",
                               category="hotfix", confidence=float(rv.get("confidence") or 0.5),
                               version=str(rv["version"]) if rv.get("version") else None, ref="engine.unity.hotfix",
                               detail="Lua runtime version from %s" % (rv.get("source") or "hotfix stage"),
                               purpose_zh="Lua 脚本运行时", purpose_en="Lua scripting runtime"))
    fp = ctx.results.get("engine.fingerprint") or {}
    for dim, cat in _DIM_CATEGORY.items():
        for hit in fp.get(dim) or []:
            if not isinstance(hit, dict) or not hit.get("id"):
                continue
            zh, en = _DIM_PURPOSE[dim]
            matcher.add(Signal("direct", lib_id=str(hit["id"]), source_kind="fingerprint", name=str(hit.get("name") or hit["id"]),
                               category=cat, confidence=float(hit.get("confidence") or 0.5), ref="engine.fingerprint",
                               purpose_zh=zh, purpose_en=en, detail="engine.fingerprint %s hit" % dim,
                               evidence=[e for e in hit.get("evidence") or [] if isinstance(e, dict)]))


def _brand_hint(name: str, brands: Dict[str, str]) -> Optional[str]:
    low = name.lower()
    best = None
    for word in brands:
        if word in low and (best is None or len(word) > len(best)):
            best = word
    if best is None:
        return None
    return "name contains '%s' (like %s) - unverified guess from the name only" % (best, brands[best])


def _privacy_covered(name: str, matched_names: set) -> bool:
    base = _PRIVACY_SUFFIX.sub("", name)
    return base != name and base.lower() in matched_names


@register(name='libs', requires=('inventory',), after=('macho', 'engine.fingerprint', 'engine.unity', 'engine.unity.hotfix', 'engine.other'))
class LibsStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        inv = ctx.results.get("inventory") or {}
        kb = load_kb(ctx.cfg.libs_user_path)
        sysfw = load_sysframeworks()
        warnings: List[str] = list(kb.warnings)
        matcher = LibMatcher(kb)
        comps = _Components()
        partial_reasons: List[str] = []

        # 1. archive structure: nested units + well-known files ----------------------------
        unit_paths: Dict[str, str] = {}
        for u in inv.get("nested_units") or []:
            kind, name, upath = u.get("kind"), str(u.get("name") or ""), str(u.get("path") or "")
            if kind == "framework":
                comps.note("framework", name, upath, "framework directory")
                unit_paths.setdefault(name, upath)
                matcher.add(Signal("framework", name, ref=upath, via="dir", detail="framework directory %s.framework" % name))
            elif kind == "bundle":
                comps.note("bundle", name, upath, "resource bundle %s.bundle" % name)
                matcher.add(Signal("bundle", name, ref=upath, detail="resource bundle %s.bundle" % name))
            elif kind == "dylib":
                leaf = _leaf(str(u.get("rel") or upath)) or name
                comps.note("dylib", leaf, upath, "bundled dylib file")
                matcher.add(Signal("dylib", leaf, ref=upath, via="file", detail="bundled dylib %s" % leaf))
        for f in load_inventory_files(inv, ctx.out_dir if ctx.is_bound else None):
            path = f.get("path")
            if isinstance(path, str):
                rel = ctx.rel(path)
                if rel:
                    matcher.add(Signal("file", rel, ref=path, detail="file %s" % rel))

        # 2. Mach-O: load commands + per-binary scans -------------------------------------
        macho = ctx.results.get("macho")
        sys_seen: Dict[str, Dict[str, Any]] = {}
        sys_unknown: Dict[str, Dict[str, Any]] = {}
        stats = {"encrypted": 0, "plain": 0}
        binaries = [b for b in (macho or {}).get("binaries") or [] if isinstance(b, dict)]
        if macho is None:
            partial_reasons.append("macho results unavailable: binary-based detection skipped")
        for b in binaries:
            bpath = b.get("path", "")
            for d in b.get("dylibs") or []:
                dpath = str(d.get("path") or "")
                if d.get("kind") == "system":
                    rec = sysfw.lookup(dpath)
                    if rec is None:
                        sys_unknown.setdefault(rec_key(dpath), {"name": _leaf(dpath), "path": dpath, "ref": bpath})
                        continue
                    sys_seen.setdefault(rec.name, {"rec": rec, "ref": bpath, "path": dpath, "count": 0})["count"] += 1
                    continue
                fw = framework_name_of(dpath)
                if fw:
                    comps.note("framework", fw, bpath, "LC_LOAD_DYLIB %s" % dpath)
                    matcher.add(Signal("framework", fw, ref=bpath, via="load", detail="LC_LOAD_DYLIB %s" % dpath))
                else:
                    leaf = _leaf(dpath)
                    comps.note("dylib", leaf, bpath, "LC_LOAD_DYLIB %s" % dpath)
                    matcher.add(Signal("dylib", leaf, ref=bpath, via="load", detail="LC_LOAD_DYLIB %s" % dpath))
        scan_failed = 0
        if ctx.source is not None:
            for b in binaries:
                if not _scan_binary(ctx, b, matcher, stats, warnings):
                    scan_failed += 1
        if scan_failed:
            partial_reasons.append("%d binary scan(s) failed" % scan_failed)

        # 3. Info.plist keys, schemes, other stages ------------------------------------
        _plist_signals(ctx, matcher)
        _stage_signals(ctx, matcher)

        # 4. versions for matched frameworks --------------------------------------------
        reads = 0
        for lib_id in matcher.hit_ids():
            if "framework_dir" not in matcher.hit_classes(lib_id) or reads >= MAX_VERSION_READS:
                continue
            for fname, upath in unit_paths.items():
                if lib_id in kb.lookup("framework", fname):
                    reads += 1
                    ver = _read_info_version(ctx, upath)
                    if ver:
                        matcher.set_version(lib_id, ver)
                    break
        items = matcher.items()

        # 5. mark components that some rule explained --------------------------------------
        matched_names = set()
        for (kind, low), rec in comps.items.items():
            ids = kb.lookup("framework" if kind == "framework" else "bundle" if kind == "bundle" else "dylib",
                            rec["name"] if kind != "dylib" else rec["name"])
            if ids and any(i in matcher.hit_ids() for i in ids):
                rec["matched"] = True
                matched_names.add(low)
        brands = kb.brand_words()
        unknown: List[Dict[str, Any]] = []
        for rec in sorted(comps.items.values(), key=lambda r: (r["kind"], r["name"].lower())):
            if rec["matched"]:
                continue
            if rec["kind"] == "bundle" and _privacy_covered(rec["name"], matched_names):
                continue
            kind = {"framework": "framework", "dylib": "bundled_dylib", "bundle": "resource_bundle"}[rec["kind"]]
            u: Dict[str, Any] = {"name": rec["name"], "kind": kind, "evidence": rec["evidence"]}
            hint = _brand_hint(rec["name"], brands)
            if hint:
                u["hint"] = hint
            unknown.append(u)
        for key in sorted(sys_unknown):
            s = sys_unknown[key]
            unknown.append({"name": s["name"], "kind": "system", "evidence": [
                {"kind": "macho", "ref": s["ref"], "detail": "LC_LOAD_DYLIB %s (not in the system table)" % s["path"]}]})

        # 6. system items ---------------------------------------------------------------
        system_items: List[Dict[str, Any]] = []
        for name in sorted(sys_seen):
            s = sys_seen[name]
            rec = s["rec"]
            item: Dict[str, Any] = {
                "id": "system.%s" % name, "name": name, "kind": "system", "vendor": "Apple", "category": "system",
                "purpose_zh": rec.purpose_zh, "purpose_en": rec.purpose_en, "tags": ["sensitive"] if rec.sensitive else [],
                "confidence": 0.95, "evidence": [{"kind": "macho", "ref": s["ref"], "detail": "LC_LOAD_DYLIB %s" % s["path"]}]}
            if rec.sensitive:
                item["sensitive"] = True
                item["capability"] = rec.capability
            system_items.append(item)
        all_items = sorted(items + system_items, key=lambda r: (r["category"], r["id"]))

        by_category: Dict[str, int] = {}
        for it in all_items:
            by_category[it["category"]] = by_category.get(it["category"], 0) + 1
        privacy: Dict[str, List[str]] = {"ads": [], "analytics": [], "tracking": [], "social": []}
        for it in items:
            for tag in it["tags"]:
                for target in _PRIVACY_TAG_MAP.get(tag, ()):
                    if it["id"] not in privacy[target]:
                        privacy[target].append(it["id"])
        for v in privacy.values():
            v.sort()

        total_bins = len(binaries)
        limitations = {"binary_encrypted": stats["encrypted"] > 0, "encrypted_binaries": stats["encrypted"],
                       "readable_binaries": stats["plain"], "total_binaries": total_bins}
        data: Dict[str, Any] = {"items": all_items, "unknown": unknown, "by_category": by_category,
                                "privacy_tags": privacy, "limitations": limitations,
                                "kb": {"entries": len(kb.entries), "user_entries": sum(1 for e in kb.entries.values() if e.user)}}
        findings = _findings(items, system_items, unknown, limitations, by_category)
        if partial_reasons:
            return StageResult.partial(NAME, data, findings, warnings, reason="; ".join(partial_reasons))
        return StageResult.ok(NAME, data, findings, warnings)


def rec_key(path: str) -> str:
    return path.lower()


def _findings(items: List[Dict[str, Any]], system_items: List[Dict[str, Any]], unknown: List[Dict[str, Any]],
              lim: Dict[str, Any], by_category: Dict[str, int]) -> List[Finding]:
    enc = lim["binary_encrypted"]
    top = sorted(((c, n) for c, n in by_category.items() if c != "system"), key=lambda kv: (-kv[1], kv[0]))[:3]
    top_txt = ", ".join("%s=%d" % kv for kv in top) or "-"
    n_third = len(items)
    params = {"identified": n_third, "system": len(system_items), "unknown": len(unknown),
              "encrypted_binaries": lim["encrypted_binaries"], "readable_binaries": lim["readable_binaries"],
              "top_categories": top_txt}
    evidence = [Evidence(e.get("kind", "heuristic"), e.get("ref", ""), "%s: %s" % (it["id"], e.get("detail", "")))
                for it in items[:5] for e in it["evidence"][:1]]
    if n_third:
        verdict, conf = Verdict.YES, 0.85
    elif enc or unknown:
        verdict, conf = Verdict.UNKNOWN, 0.4
    else:
        verdict, conf = Verdict.NO, 0.5
    text = "Identified %d third-party librar%s and %d system librar%s; %d unrecognised; top categories: %s." % (
        n_third, "y" if n_third == 1 else "ies", len(system_items), "y" if len(system_items) == 1 else "ies", len(unknown), top_txt)
    remediation = ""
    params["remediation_zh"] = ""
    if enc:
        params["remediation_zh"] = "请提供已解密的 IPA,以便做基于 ObjC 类名 / 字符串的库识别;本工具不提供解密。"
        text += " Binary is FairPlay-encrypted: binary-based detection is limited to load commands, imported symbols and files."
        remediation = "Provide a decrypted IPA for ObjC class / string based library detection; this tool never decrypts."
    out = [Finding("libs.summary", verdict, conf, "Libraries identified", text, params, evidence, remediation, tags=["libs"])]
    names = ", ".join(u["name"] for u in unknown[:10])
    if unknown:
        out.append(Finding("libs.unknown", Verdict.UNKNOWN, 0.3, "Unrecognised libraries",
                           "%d librar%s matched no knowledge-base rule (purpose unknown): %s." % (
                               len(unknown), "y" if len(unknown) == 1 else "ies", names),
                           {"count": len(unknown), "names": names},
                           [Evidence("file", (e["evidence"][0]["ref"] if e["evidence"] else ""), u["name"])
                            for u in unknown[:5] for e in [u]],
                           "Look the unknown libraries up online and record confirmed ones in libs.user.json "
                           "(format: references/libs-kb-format.md).", tags=["libs"]))
    else:
        out.append(Finding("libs.unknown", Verdict.NA, 0.5, "Unrecognised libraries",
                           "Every observed library matched a knowledge-base rule.", {"count": 0, "names": ""}, [], "", tags=["libs"]))
    return out
