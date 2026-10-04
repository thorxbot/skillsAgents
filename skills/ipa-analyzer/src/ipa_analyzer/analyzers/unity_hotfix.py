"""Stage ``engine.unity.hotfix`` (WP5b): which hot-update mechanism a Unity game uses, where its scripts live
(loose files / AssetBundles / serialized files), in what format (plain / bytecode / compressed / suspected
encrypted) and which Lua version.

Four evidence channels, cheapest first: the identifier pool of ``global-metadata.dat`` (no dumper needed, not
affected by FairPlay), the optional il2cpp dump namespaces, native symbols / Lua version strings in the
unencrypted parts of the Mach-O binaries, and files + sampled bundle content.  Every limit is reported
(``scanned.bundles_sampled / total``); compressed is not encrypted, bytecode is not encrypted, high entropy is
only ``suspected``, and a sample is not the population.  Nothing is decrypted, executed or repaired.
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, Iterator, List, Optional, Tuple

from ..context import AnalysisContext
from ..formats import pe_cli
from ..models import Evidence, Finding, StageResult, Verdict
from ..registry import register
from ..unity.hotfix import csharp, detect, js, lua, metadata_strings, native_signals, resource_update, storage, summary
from ..util.filetypes import load_inventory_files

log = logging.getLogger(__name__)

NAME = "engine.unity.hotfix"
BUNDLE_TIME_BUDGET_S = 240.0
_MAX_BINARIES = 5
_PROTECTION_REMEDIATION = ("Provide a decrypted IPA to inspect the native code; this tool never decrypts or "
                           "extracts keys.")
_ENC_REMEDIATION = "The main binary is FairPlay-encrypted, so binary-based detection is limited; supply a decrypted IPA."


@register(name="engine.unity.hotfix", requires=("engine.unity",), after=("inventory", "macho"))
class EngineUnityHotfixStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        unity = ctx.results.get("engine.unity")
        if not isinstance(unity, dict):
            return StageResult.skipped(NAME, "engine.unity produced no result (not a Unity app)")
        try:
            return _run(ctx, unity)
        except Exception as exc:     # noqa: BLE001 - isolate: a hot-update failure must not hide the Unity result
            log.exception("hotfix analysis failed")
            return StageResult.failed(NAME, "%s: %s" % (type(exc).__name__, exc))


# ------------------------------------------------------------------------------------- main


def _run(ctx: AnalysisContext, unity: Dict[str, Any]) -> StageResult:
    rules = detect.load_rules()
    warnings: List[str] = []
    degraded: List[str] = []
    failed_sources: List[str] = []
    src = ctx.source
    if src is None:
        return StageResult.skipped(NAME, "no input source is open")

    inv = ctx.results.get("inventory")
    files: List[Dict[str, Any]] = []
    if isinstance(inv, dict):
        files = load_inventory_files(inv, ctx.out_dir if ctx.is_bound else None)
    else:
        failed_sources.append("inventory")
        warnings.append("inventory is unavailable: loose-file and bundle discovery was skipped")
    bundles_in = unity.get("bundles") if isinstance(unity.get("bundles"), dict) else {}
    extra_bundles = [p for p in (bundles_in.get("paths_sample") or []) if isinstance(p, str)]
    disc = storage.discover(files, ctx.rel, rules, extra_bundle_paths=extra_bundles if not files else ())

    observations: List[detect.Observation] = []

    # 1. metadata identifier pool + URL literals
    md = unity.get("metadata") if isinstance(unity.get("metadata"), dict) else {}
    mscan = metadata_strings.MetadataScan()
    meta_hosts: List[str] = []
    meta_path = md.get("path") if isinstance(md.get("path"), str) else _find_metadata(disc.file_names, ctx)
    if meta_path and md.get("present") is not False:
        try:
            mscan, meta_hosts = _scan_metadata(ctx, rules, meta_path, md)
        except Exception as exc:     # noqa: BLE001
            failed_sources.append("metadata_strings")
            warnings.append("metadata string scan failed: %s" % exc)
    else:
        mscan.skipped_reason = "no global-metadata.dat (Mono backend or not a standard Unity player)"
    if not mscan.ran:
        degraded.append("metadata_strings: %s" % (mscan.skipped_reason or "not run"))
        if meta_path and md.get("present") is not False and "metadata_strings" not in failed_sources:
            failed_sources.append("metadata_strings (unavailable: %s)" % (mscan.skipped_reason or "not run"))
    observations.extend(mscan.observations)

    # 2. il2cpp dump namespaces (optional)
    dump = unity.get("dump") if isinstance(unity.get("dump"), dict) else {}
    dump_ns = list(dump.get("namespaces") or []) + list(((dump.get("summary") or {}).get("framework_namespaces")) or [])
    dump_used = 0
    for ns in dict.fromkeys(n for n in dump_ns if isinstance(n, str)):
        for sig in rules.match_namespace(ns):
            observations.append(detect.Observation(sig.framework, "dump", "namespace", sig.value, sig.weight,
                                                   ref=ns, strong=sig.strong, unverified=sig.unverified, tag=sig.tag))
            dump_used += 1

    # 3. file-name evidence
    for rel in disc.file_names:
        for sig in rules.match_path(rel):
            observations.append(detect.Observation(sig.framework, "file", "file", sig.value, sig.weight, ref=rel,
                                                   strong=sig.strong, unverified=sig.unverified, tag=sig.tag))

    # 4. native symbols / Lua version strings
    nscan = native_signals.NativeScan()
    try:
        nscan = _scan_native(ctx, rules, unity, disc.file_names)
    except Exception as exc:     # noqa: BLE001
        failed_sources.append("native_signals")
        warnings.append("native scan failed: %s" % exc)
    observations.extend(nscan.observations)
    if nscan.limited_by_encryption:
        degraded.append("native_signals: binary is FairPlay-encrypted, detection limited to unencrypted ranges")
    elif not nscan.ran:
        degraded.append("native_signals: no binary could be scanned")

    # 5. storage: loose files + bundles + serialized files
    blobs: Dict[str, List[storage.Blob]] = {"lua": [], "dll": [], "js": []}
    containers: List[storage.ContainerScan] = []
    loose_counts = {"lua": 0, "dll": 0, "js": 0}
    for kind, rows in disc.loose.items():
        for info in rows:
            b = storage.load_loose_blob(src, info, kind)
            if b is not None:
                blobs[kind].append(b)
                loose_counts[kind] += 1
    for info in disc.bytes_sniff:
        b = _sniff_bytes_file(src, info)
        if b is not None:
            blobs[b.kind].append(b)
            loose_counts[b.kind] += 1
    bundle_sample = storage.pick_sample(disc.bundles, max(0, int(ctx.cfg.unity.hotfix_scan_bundles)))
    per_bundle = max(1 << 20, int(ctx.cfg.unity.hotfix_scan_bytes_per_bundle))
    started = time.monotonic()
    skipped_budget = 0
    for info in bundle_sample:
        if time.monotonic() - started > BUNDLE_TIME_BUDGET_S:
            skipped_budget += 1
            continue
        cs = storage.scan_bundle(src, info, max_bytes=per_bundle)
        containers.append(cs)
    ser_rows = disc.serialized[:storage.MAX_SERIALIZED_FILES]
    for info in ser_rows:
        containers.append(storage.scan_serialized(src, info))
    for cs in containers:
        for b in cs.blobs:
            blobs[b.kind].append(b)

    bundle_scans = [c for c in containers if c.kind == "bundle"]
    ser_scans = [c for c in containers if c.kind == "serialized"]
    status_counts: Dict[str, int] = {}
    for c in bundle_scans:
        status_counts[c.status] = status_counts.get(c.status, 0) + 1
    readable = sum(status_counts.get(s, 0) for s in ("ok", "partial"))
    unreadable = len(bundle_scans) - readable
    unreadable_all = unreadable + sum(1 for c in ser_scans if c.status not in ("ok", "partial"))
    if skipped_budget:
        warnings.append("bundle scan time budget exhausted: %d sampled bundle(s) were not scanned" % skipped_budget)

    named: Dict[str, int] = {"lua": 0, "dll": 0, "js": 0}
    named_dll: List[str] = []
    text_hint_containers = 0
    for c in containers:
        for k, n in c.script_name_counts.items():
            if k == "dll" and c.kind != "bundle":
                continue          # serialized files list Unity's own module names (UnityEngine.*.dll)
            named[k] = named.get(k, 0) + n
        if c.kind == "bundle":
            named_dll.extend(c.script_names.get("dll", []))
        if c.lua_text_hits >= 3:
            text_hint_containers += 1

    # 6. frameworks (+ unattributed script mechanisms)
    frameworks = detect.merge_frameworks(rules, observations)
    for fw in frameworks:
        if fw["id"] == "addressables":
            ru_ver = _addressables_version(ctx, files, disc)
            if ru_ver:
                fw["version_hint"] = ru_ver
    _add_unattributed(frameworks, blobs, named)

    # 7. per-language profiles
    lua_fw_hints = {f["id"]: rules.frameworks[f["id"]].runtime_hints for f in frameworks
                    if f["id"] in rules.frameworks and rules.frameworks[f["id"]].kind == "lua"
                    and rules.frameworks[f["id"]].runtime_hints}
    lua_block = lua.analyze(blobs["lua"], nscan.runtime_versions, framework_hints=lua_fw_hints,
                            named_only=max(0, named["lua"] - len(blobs["lua"]) if blobs["lua"] else named["lua"]),
                            text_hint_containers=text_hint_containers, native_limited=nscan.limited_by_encryption)
    lua_block["framework_defaults"] = [{"framework": k, "hints": v} for k, v in sorted(lua_fw_hints.items())]
    lua_block["symbol_hints"] = nscan.symbol_hints[:20]
    csharp_runtime = any(f["kind"] == "csharp" and f["confidence"] >= 0.5 and not f["id"].endswith("_unattributed")
                         for f in frameworks)
    csharp_block = csharp.analyze(blobs["dll"], rules, mscan.assemblies, hotfix_runtime=csharp_runtime,
                                  named_only=named_dll, managed_dlls=len(disc.managed_dlls))
    puerts = next((f for f in frameworks if f["id"] == "puerts"), None)
    type_backends = [{"id": b, "confidence": puerts["confidence"] * 0.8} for b in (puerts or {}).get("backends", [])]
    js_exts = sorted({re.search(r"(\.[a-z]+(?:\.(?:txt|bytes))?)$", b.name.lower()).group(1)    # type: ignore[union-attr]
                      for b in blobs["js"] if re.search(r"(\.[a-z]+(?:\.(?:txt|bytes))?)$", b.name.lower())})
    js_block = js.analyze(blobs["js"], type_backends, nscan.js_backends, named_in_containers=named["js"],
                          extensions=js_exts)
    js_block["excluded_sdk_scripts"] = disc.excluded.get("js", 0)
    ru_block = resource_update.analyze(src, files, ctx.rel, frameworks=frameworks, metadata_hosts=meta_hosts)

    # 8. storage block, protection, summary
    in_b = {k: sum(1 for b in blobs[k] if b.source == "bundle") for k in blobs}
    in_s = {k: sum(1 for b in blobs[k] if b.source == "serialized") for k in blobs}
    sampled = len(bundle_scans)
    scanned_block = {
        "bundles_sampled": sampled, "total": len(disc.bundles), "bundles_readable": readable,
        "bundles_unreadable": unreadable, "unreadable_by_reason": dict(sorted(
            (k, v) for k, v in status_counts.items() if k not in ("ok", "partial"))),
        "bundles_not_scanned_budget": skipped_budget,
        "sample_ratio": round(sampled / len(disc.bundles), 4) if disc.bundles else None,
        "serialized_scanned": len(ser_scans), "serialized_total": len(disc.serialized),
        "bytes_scanned": sum(c.bytes_scanned for c in containers),
        "sample_paths": [c.path for c in bundle_scans[:10]],
        "unity_versions": sorted({c.unity_version for c in bundle_scans if c.unity_version})[:5],
    }
    storage_block = {
        "loose": dict(loose_counts, excluded_sdk=dict(sorted(disc.excluded.items())),
                      managed_dlls=len(disc.managed_dlls), truncated=dict(disc.truncated)),
        "in_bundles": dict(in_b, named=dict(named)),
        "in_serialized": dict(in_s),
        "scanned": scanned_block,
        "loose_total": sum(loose_counts.values()), "in_bundles_total": sum(in_b.values()),
        "in_serialized_total": sum(in_s.values()),
    }
    any_lua = bool(blobs["lua"]) or named["lua"] > 0 or any(
        f["kind"] == "lua" and f["confidence"] >= 0.5 and not f["id"].endswith("_unattributed") for f in frameworks)
    any_js = bool(blobs["js"]) or named["js"] > 0 or any(
        f["kind"] == "js" and f["confidence"] >= 0.5 and not f["id"].endswith("_unattributed") for f in frameworks)
    limited = bool(unreadable_all or nscan.limited_by_encryption or not mscan.ran or skipped_budget)
    prot = {
        "lua": lua.protection_verdict(lua_block, containers_unreadable=unreadable_all, any_lua_signal=any_lua,
                                      coverage_limited=limited),
        "js": js.protection_verdict(js_block, containers_unreadable=unreadable_all, js_signal=any_js,
                                    coverage_limited=limited),
        "csharp": csharp.protection_verdict(csharp_block, containers_unreadable=unreadable_all,
                                            csharp_signal=csharp_runtime, coverage_limited=limited),
    }
    hints = mscan.protection_hints
    if hints:
        for kind_key, target in (("lua", "script"), ("js", "script"), ("csharp", "script")):
            if prot[kind_key]["verdict"] in ("n/a", "unknown", "no") and any(h["target"] == target for h in hints):
                prot[kind_key]["hint_identifiers"] = [h["identifier"] for h in hints if h["target"] == target][:6]
    limits: List[str] = []
    if disc.bundles and sampled < len(disc.bundles):
        limits.append("sampled %d/%d bundles" % (sampled, len(disc.bundles)))
    if unreadable:
        limits.append("%d sampled bundle(s) unreadable (%s)" % (unreadable, ", ".join(
            "%s x%d" % kv for kv in sorted(scanned_block["unreadable_by_reason"].items()))))
    if nscan.limited_by_encryption:
        limits.append("main binary encrypted: binary-based detection limited")
    if not mscan.ran:
        limits.append("metadata strings not scanned")
    script_prot = {k: v["verdict"] for k, v in prot.items()}
    text = summary.build_summary_text(frameworks, lua_block, storage_block, ru_block, script_prot, limits)

    data: Dict[str, Any] = {
        "frameworks": frameworks,
        "lua": lua_block,
        "js": js_block,
        "csharp": csharp_block,
        "resource_update": ru_block,
        "storage": storage_block,
        "script_protection": script_prot,
        "script_protection_detail": prot,
        "summary_text": text,
        "evidence_sources": {
            "metadata_strings": mscan.to_dict(),
            "dump_namespaces": {"used": dump_used > 0, "matched_signals": dump_used},
            "native": {"ran": nscan.ran, "limited_by_encryption": nscan.limited_by_encryption,
                       "targets": nscan.targets, "notes": nscan.notes},
            "files": {"matched": sum(1 for o in observations if o.source == "file")},
        },
        "protection_hints": mscan.protection_hints,
        "degraded": degraded,
    }
    findings = _findings(frameworks, lua_block, js_block, csharp_block, ru_block, prot, data, mscan, nscan,
                         storage_block, any_lua, any_js, csharp_runtime, unreadable_all, len(disc.bundles) == sampled)
    if failed_sources:
        return StageResult.partial(NAME, data, findings, warnings, reason="failed sources: " + ", ".join(failed_sources))
    return StageResult.ok(NAME, data, findings, warnings)


# ------------------------------------------------------------------------------- collectors


def _find_metadata(names: List[str], ctx: AnalysisContext) -> Optional[str]:
    for rel in names:
        if rel.endswith("Data/Managed/Metadata/global-metadata.dat"):
            return ctx.app_path(rel)
    return None


def _scan_metadata(ctx: AnalysisContext, rules: detect.HotfixRules, path: str, md: Dict[str, Any]
                   ) -> Tuple[metadata_strings.MetadataScan, List[str]]:
    verdict = md.get("verdict")
    if verdict in ("yes", "suspected"):
        scan = metadata_strings.MetadataScan()
        scan.skipped_reason = "metadata verdict is %s: identifier pool not readable" % verdict
        return scan, []
    local = ctx.extract([path]).get(path)
    if local is not None:
        fobj = open(local, "rb")
        size = local.stat().st_size
    else:
        fobj = ctx.source.open(path)          # type: ignore[union-attr]
        size = ctx.source.stat(path).size     # type: ignore[union-attr]
    try:
        scan = metadata_strings.scan_metadata(fobj, size, rules, ref=path, region=md.get("string_region"),
                                              verdict=verdict, header_ok=md.get("header_ok"))
        hosts: List[str] = []
        if scan.ran:
            hosts = resource_update.scan_metadata_hosts(fobj, size)
        return scan, hosts
    finally:
        fobj.close()


def _scan_native(ctx: AnalysisContext, rules: detect.HotfixRules, unity: Dict[str, Any],
                 rel_names: List[str]) -> native_signals.NativeScan:
    total = native_signals.NativeScan()
    targets: List[str] = []
    binary = unity.get("binary") if isinstance(unity.get("binary"), dict) else {}
    if isinstance(binary.get("path"), str):
        targets.append(binary["path"])
    macho = ctx.results.get("macho")
    if isinstance(macho, dict):
        main = (macho.get("summary") or {}).get("main_binary")
        if isinstance(main, str):
            targets.append(main)
        lib_re = re.compile(rules.storage["native_lib_name_regex"], re.IGNORECASE)
        for b in macho.get("binaries") or []:
            if isinstance(b, dict) and isinstance(b.get("path"), str) and lib_re.search(b["path"]) \
                    and b.get("role") in ("framework", "dylib"):
                targets.append(b["path"])
    targets = list(dict.fromkeys(targets))[:_MAX_BINARIES]
    if not targets:
        total.notes.append("no native binary known (macho/engine.unity gave none)")
        return total
    local = ctx.extract(targets)
    for t in targets:
        p = local.get(t)
        if p is None:
            total.notes.append("%s could not be extracted; skipped" % t)
            continue
        total.merge(native_signals.scan_binary(p, rules, ref=t))
    return total


def _sniff_bytes_file(src: Any, info: Dict[str, Any]) -> Optional[storage.Blob]:
    """A ``*.bytes`` file of unknown kind: keep it only if its head is Lua bytecode or a .NET PE image."""
    head = storage._read_head(src, info["path"], storage.SAMPLE_BYTES)
    if head[:4] == b"\x1bLua" or head[:3] == b"\x1bLJ":
        return storage.Blob("lua", "loose", info["path"], info["path"].rsplit("/", 1)[-1], info.get("size"),
                            head[:storage.HEAD_BYTES], head, note="bytes_file")
    if head[:2] == b"MZ" and (info.get("size") or 0) <= storage.MAX_DLL_BYTES:
        try:
            with src.open(info["path"]) as fh:
                data = fh.read(storage.MAX_DLL_BYTES)
        except (KeyError, OSError, ValueError):
            return None
        if pe_cli.is_dotnet_assembly(data):
            return storage.Blob("dll", "loose", info["path"], info["path"].rsplit("/", 1)[-1], info.get("size"),
                                data[:storage.HEAD_BYTES], head, data=data, note="bytes_file")
    return None


def _addressables_version(ctx: AnalysisContext, files: List[Dict[str, Any]], disc: storage.Discovery) -> Optional[str]:
    for row in files:
        p = row.get("path", "")
        if isinstance(p, str) and p.endswith("aa/settings.json"):
            data = resource_update._read(ctx.source, p)
            doc = resource_update._json(data)
            if isinstance(doc, dict) and isinstance(doc.get("m_AddressablesVersion"), str):
                return doc["m_AddressablesVersion"]
    return None


def _add_unattributed(frameworks: List[Dict[str, Any]], blobs: Dict[str, List[storage.Blob]], named: Dict[str, int]) -> None:
    have = {k: any(f["kind"] == k and f["confidence"] >= 0.5 for f in frameworks) for k in ("lua", "csharp", "js")}
    spec = {"lua": ("lua_unattributed", "Lua scripts (binding not identified)"),
            "csharp": ("csharp_unattributed", "Hot-update C# assemblies (runtime not identified)"),
            "js": ("js_unattributed", "JavaScript scripts (binding not identified)")}
    for kind, (fid, name) in spec.items():
        n = len(blobs.get(kind, ()))
        if kind == "csharp":
            n = sum(1 for b in blobs["dll"] if b.source != "loose" or b.name.lower().endswith((".dll.bytes", ".dll.txt")))
        if have[kind] or (n == 0 and named.get(kind, 0) == 0):
            continue
        conf = 0.6 if n else 0.35
        frameworks.append({"id": fid, "name": name, "kind": kind, "confidence": conf, "version_hint": None,
                           "evidence": [Evidence("file", "storage", "%d candidate script file(s), %d named in containers" %
                                                 (n, named.get(kind, 0))).to_dict()],
                           "sources": ["file"], "backends": []})
    frameworks.sort(key=lambda f: (-f["confidence"], f["id"]))


# ---------------------------------------------------------------------------------- findings


def _evidence_of(fw: Dict[str, Any], limit: int = 8) -> List[Evidence]:
    return [Evidence.from_dict(e) for e in fw.get("evidence", [])[:limit]]


def _findings(frameworks, lua_block, js_block, cs_block, ru_block, prot, data, mscan, nscan, storage_block,
              any_lua, any_js, csharp_runtime, unreadable_all, all_bundles_sampled) -> List[Finding]:
    out: List[Finding] = []
    named_fw = [f for f in frameworks if not f["id"].endswith("_unattributed")]
    strong = [f for f in named_fw if f["confidence"] >= 0.7 and f["id"] != "custom_hotupdate"]
    weak = [f for f in named_fw if 0.35 <= f["confidence"] < 0.7 or f["id"] == "custom_hotupdate"]
    full_view = (mscan.ran and unreadable_all == 0 and all_bundles_sampled and not nscan.limited_by_encryption
                 and storage_block["loose_total"] == 0 and storage_block["in_bundles_total"] == 0)
    ev: List[Evidence] = []
    for f in (strong or weak)[:3]:
        ev.extend(_evidence_of(f, 4))
    names = ", ".join("%s (%.2f)" % (f["name"], f["confidence"]) for f in (strong or weak)) or "none"
    if strong:
        v, c = Verdict.YES, max(f["confidence"] for f in strong)
    elif weak or any(f["id"].endswith("_unattributed") for f in frameworks):
        v, c = Verdict.SUSPECTED, max([f["confidence"] for f in weak] + [0.4])
    elif full_view:
        v, c = Verdict.NO, 0.55
    else:
        v, c = Verdict.UNKNOWN, 0.3
    limit_note = "; ".join(data["degraded"])
    out.append(Finding("unity.hotfix.framework", v, c, "Hot-update framework",
                       summary="Detected: %s. %s%s" % (names, data["summary_text"], (" Limits: " + limit_note) if limit_note else ""),
                       params={"frameworks": names, "count": len(named_fw), "summary_text": data["summary_text"],
                               "limits": limit_note},
                       evidence=ev, remediation=_ENC_REMEDIATION if nscan.limited_by_encryption else "",
                       tags=["unity", "hotfix"]))

    # Lua
    lua_fw = [f for f in frameworks if f["kind"] == "lua"]
    lf = lua_block["files"]
    if lf["total"] or any(f["confidence"] >= 0.6 for f in lua_fw):
        lv = Verdict.YES if (lf["total"] or any(f["confidence"] >= 0.7 for f in lua_fw)) else Verdict.SUSPECTED
        lc = 0.9 if lf["total"] else max(f["confidence"] for f in lua_fw)
    elif lua_fw or any_lua:
        lv, lc = Verdict.SUSPECTED, 0.4
    elif full_view:
        lv, lc = Verdict.NO, 0.55
    else:
        lv, lc = Verdict.UNKNOWN, 0.3
    out.append(Finding("unity.hotfix.lua", lv, lc, "Lua hot-update scripts",
                       summary="Lua files inspected: %d plain, %d bytecode, %d compressed, %d suspected encrypted (of %d)." % (
                           lf["plain"], lf["bytecode"], lf["compressed"], lf["encrypted_suspected"], lf["total"]),
                       params={"plain": lf["plain"], "bytecode": lf["bytecode"], "compressed": lf["compressed"],
                               "encrypted_suspected": lf["encrypted_suspected"], "total": lf["total"],
                               "loose": lua_block["storage"]["loose"], "in_bundles": lua_block["storage"]["in_bundles"],
                               "in_serialized": lua_block["storage"]["in_serialized"]},
                       evidence=[Evidence("file", s["path"], "%s %s%s" % (s["source"], s["class"], (" " + s["version"]) if s["version"] else ""))
                                 for s in lua_block["samples"][:6]] + [e for f in lua_fw[:2] for e in _evidence_of(f, 3)],
                       tags=["unity", "hotfix", "lua"]))

    # Lua version
    bc = lua_block["bytecode"]
    rts = lua_block["runtime_versions"]
    strong_rt = [r for r in rts if r.get("confidence", 0) >= 0.8]
    if bc["by_version"] or rts:
        if bc["by_version"] or strong_rt:
            vv, vc = Verdict.YES, 0.9 if bc["by_version"] else 0.8
        else:
            vv, vc = Verdict.SUSPECTED, 0.5
        if not lua_block["consistency"]["ok"]:
            vc = min(vc, 0.6)
    elif lf["total"] and lf["plain"] and lua_block["dialect_hints"]:
        vv, vc = Verdict.SUSPECTED, 0.4
    elif lf["total"] or any_lua:
        vv, vc = Verdict.UNKNOWN, 0.3
    elif lv == Verdict.UNKNOWN:
        vv, vc = Verdict.UNKNOWN, 0.3
    else:
        vv, vc = Verdict.NA, 0.5
    ver_ev = [Evidence("heuristic", "bytecode", "%s x%d" % kv) for kv in sorted(bc["by_version"].items())]
    ver_ev += [Evidence("string", r.get("ref", ""), "%s %s (%s)" % (r["flavor"], r["version"], r["source"])) for r in rts[:4]]
    out.append(Finding("unity.hotfix.lua_version", vv, vc, "Lua version profile",
                       summary="Bytecode versions: %s; runtime strings: %s; bits: %s; stripped: %d. %s" % (
                           ", ".join("%s x%d" % kv for kv in sorted(bc["by_version"].items())) or "none",
                           ", ".join("%s %s" % (r["flavor"], r["version"]) for r in rts[:3]) or "none",
                           ", ".join("%s x%d" % kv for kv in sorted(bc["arch_bits"].items())) or "unknown",
                           bc["stripped_count"], " ".join(lua_block["consistency"]["notes"] + lua_block["notes"][:1])),
                       params={"by_version": bc["by_version"], "runtime": ", ".join("%s %s" % (r["flavor"], r["version"]) for r in rts[:3]) or "-",
                               "consistent": lua_block["consistency"]["ok"], "custom_suspected": lua_block["custom_lua_suspected"],
                               "notes": " ".join(lua_block["consistency"]["notes"])},
                       evidence=ver_ev[:8], tags=["unity", "hotfix", "lua"]))

    # C# assemblies
    ents = cs_block["assemblies"]
    hot = [e for e in ents if e["kind"] == "hot"]
    if hot:
        cv, cc = Verdict.YES, 0.85
    elif ents or csharp_runtime:
        cv, cc = Verdict.SUSPECTED, 0.5
    elif full_view:
        cv, cc = Verdict.NO, 0.5
    else:
        cv, cc = (Verdict.UNKNOWN, 0.3) if (unreadable_all or nscan.limited_by_encryption or not mscan.ran) else (Verdict.NO, 0.45)
    out.append(Finding("unity.hotfix.csharp_dll", cv, cc, "C# hot-update assemblies",
                       summary="%d assembly candidate(s): %d hot, %d AOT supplemental metadata; formats: %s. Report only: nothing is decrypted." % (
                           len(ents), len(hot), sum(1 for e in ents if e["kind"] == "aot_meta"),
                           ", ".join("%s x%d" % kv for kv in sorted(cs_block["counts"]["by_format"].items())) or "none"),
                       params={"total": len(ents), "hot": len(hot), "aot_meta": sum(1 for e in ents if e["kind"] == "aot_meta"),
                               "formats": ", ".join("%s x%d" % kv for kv in sorted(cs_block["counts"]["by_format"].items())) or "-",
                               "hot_names": ", ".join(e["name"] for e in hot[:6]) or "-"},
                       evidence=[Evidence("file", e.get("path", e["name"]), "%s %s %s" % (e["source"], e["format"], e["kind"])) for e in ents[:6]],
                       tags=["unity", "hotfix", "csharp"]))

    # JS
    jf = js_block["files"]
    js_fw = [f for f in frameworks if f["kind"] == "js"]
    if jf["total"] or any(f["confidence"] >= 0.7 for f in js_fw):
        jv, jc = Verdict.YES, 0.85
    elif js_fw or any_js:
        jv, jc = Verdict.SUSPECTED, 0.45
    elif full_view:
        jv, jc = Verdict.NO, 0.5
    else:
        jv, jc = (Verdict.UNKNOWN, 0.3) if (unreadable_all or nscan.limited_by_encryption or not mscan.ran) else (Verdict.NO, 0.45)
    out.append(Finding("unity.hotfix.js", jv, jc, "JavaScript hot-update scripts",
                       summary="JS files: %d plain, %d binary non-text, %d suspected encrypted; backends: %s." % (
                           jf["plain"], jf["binary_non_text"], jf["encrypted_suspected"],
                           ", ".join(b["id"] for b in js_block["backends"]) or "none identified"),
                       params={"plain": jf["plain"], "binary_non_text": jf["binary_non_text"],
                               "encrypted_suspected": jf["encrypted_suspected"], "total": jf["total"],
                               "backends": ", ".join(b["id"] for b in js_block["backends"]) or "-"},
                       evidence=[e for f in js_fw[:2] for e in _evidence_of(f, 3)], tags=["unity", "hotfix", "js"]))

    # resource update
    res_fw = [f for f in frameworks if f["kind"] == "resource" and f["id"] != "custom_hotupdate"]
    if any(f["confidence"] >= 0.7 for f in res_fw):
        rv, rc = Verdict.YES, max(f["confidence"] for f in res_fw)
    elif res_fw or any(f["id"] == "custom_hotupdate" for f in frameworks) or ru_block["manifests"] or ru_block["catalogs"]:
        rv, rc = Verdict.SUSPECTED, 0.5
    elif full_view:
        rv, rc = Verdict.NO, 0.5
    else:
        rv, rc = (Verdict.UNKNOWN, 0.3) if (unreadable_all or not mscan.ran) else (Verdict.NO, 0.4)
    res_names = ", ".join(f["name"] + ((" " + f["version_hint"]) if f.get("version_hint") else "") for f in res_fw) or "none"
    custom = next((f for f in frameworks if f["id"] == "custom_hotupdate"), None)
    out.append(Finding("unity.hotfix.resource_update", rv, rc, "Resource hot-update",
                       summary="Resource-update frameworks: %s; %d catalog file(s), %d manifest(s); CDN-like hosts (domain only): %s. %s" % (
                           res_names, len(ru_block["catalogs"]), len(ru_block["manifests"]),
                           ", ".join(ru_block["hosts"][:5]) or "none found", "; ".join(ru_block["layout_hints"][:3])),
                       params={"frameworks": res_names, "catalogs": len(ru_block["catalogs"]), "manifests": len(ru_block["manifests"]),
                               "hosts": ", ".join(ru_block["hosts"]) or "-", "layout": "; ".join(ru_block["layout_hints"][:3]) or "-"},
                       evidence=[e for f in (res_fw + ([custom] if custom else []))[:3] for e in _evidence_of(f, 3)],
                       tags=["unity", "hotfix", "resource"]))

    # script protection
    sp = data["script_protection"]
    from_hint = [h for k in prot.values() for h in k.get("hint_identifiers", [])]
    over = summary.overall_protection(prot)
    ov = Verdict(over["verdict"])
    pe: List[Evidence] = []
    for kind, v in prot.items():
        pe.append(Evidence("heuristic", kind, "%s: %s (%s)" % (kind, v["verdict"], v["reason"])))
    for h in data["protection_hints"][:4]:
        pe.append(Evidence("string", h["identifier"], "identifier naming hint (%s): not proof" % h["id"]))
    out.append(Finding("unity.hotfix.script_protection", ov, over["confidence"], "Hot-update script protection",
                       summary="lua=%s, js=%s, csharp=%s. Plain/compiled scripts are not protected; compression is not encryption; "
                               "high entropy alone is only suspected; a sample is not the population." % (sp["lua"], sp["js"], sp["csharp"]),
                       params={"lua": sp["lua"], "js": sp["js"], "csharp": sp["csharp"],
                               "hints": ", ".join(dict.fromkeys(from_hint + [h["identifier"] for h in data["protection_hints"][:3]])) or "-"},
                       evidence=pe[:10], remediation=_PROTECTION_REMEDIATION if ov in (Verdict.SUSPECTED, Verdict.UNKNOWN) else "",
                       tags=["unity", "hotfix", "protection"]))
    return out
