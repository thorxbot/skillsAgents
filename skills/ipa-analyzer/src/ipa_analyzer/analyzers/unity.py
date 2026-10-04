"""Stage ``engine.unity`` (WP5): Unity version / backend, IL2CPP metadata and AssetBundle protection verdicts,
Mono assemblies, il2cpp pre-checks and the automatic il2cpp dump.

Everything decided here is heuristic evidence (see ``references/unity-assetbundle.md`` and
``references/unity-il2cpp-metadata.md``); nothing is decrypted.  A failing dump never discards the verdicts
reached before it: the stage then ends ``partial``.  Facts for the hot-fix stage are exposed in
``ctx.results["engine.unity"]`` (``metadata.string_region``, ``bundles.paths_sample``, ``binary.path``).
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Tuple

from ..context import AnalysisContext
from ..engines.api import DetectResult
from ..il2cpp import Il2CppErrorCode, Il2CppRunRequest, run_il2cpp_dump, summarize_dump
from ..il2cpp.errors import remediation_for
from ..macho import MachOError, NotMachO, parse as macho_parse, scan_file, write_thin
from ..macho.scan import UNITY_VERSION_RE
from ..models import Evidence, Finding, StageResult, Verdict
from ..registry import register
from ..unity import bundles as ub
from ..unity import metadata as um
from ..unity import mono as umono
from ..unity import precheck as upre
from ..unity import version as uver
from ..util.filetypes import load_inventory_files

log = logging.getLogger(__name__)

NAME = "engine.unity"
FRAMEWORK_BIN = "Frameworks/UnityFramework.framework/UnityFramework"
METADATA_SUFFIX = "/Managed/Metadata/global-metadata.dat"
MAX_SERIALIZED_SOURCES = 12
_IL2CPP_RE = re.compile(rb"il2cpp_[a-z_]{3,40}")


def _ev(kind: str, ref: str, detail: str = "") -> Evidence:
    return Evidence(kind, ref, detail)


# --- discovery --------------------------------------------------------------------------------------------
def _app_files(ctx: AnalysisContext) -> List[Tuple[Dict[str, Any], str]]:
    inv = ctx.results.get("inventory") or {}
    out: List[Tuple[Dict[str, Any], str]] = []
    out_dir = ctx.out_dir if ctx.is_bound else None
    for row in load_inventory_files(inv, out_dir):
        path = row.get("path")
        if not isinstance(path, str):
            continue
        rel = ctx.rel(path)
        if rel is not None:
            out.append((row, rel))
    return out


def _find_metadata(files: List[Tuple[Dict[str, Any], str]]) -> Optional[Tuple[str, int]]:
    cands = [(row["path"], int(row.get("size") or 0)) for row, rel in files
             if ("/" + rel).lower().endswith(METADATA_SUFFIX.lower())]
    if not cands:
        cands = [(row["path"], int(row.get("size") or 0)) for row, rel in files
                 if rel.lower().endswith("global-metadata.dat")]
    return sorted(cands)[0] if cands else None


def _pick_binary(ctx: AnalysisContext, files: List[Tuple[Dict[str, Any], str]]) -> Dict[str, Any]:
    """The il2cpp-carrying Mach-O: UnityFramework if present, else the main executable (architecture 4.3)."""
    macho = ctx.results.get("macho") or {}
    binaries = [b for b in macho.get("binaries") or [] if isinstance(b, dict)]
    fw_path = ctx.app_path(FRAMEWORK_BIN)
    chosen: Optional[Dict[str, Any]] = next((b for b in binaries if b.get("path") == fw_path), None)
    if chosen is None:
        main = (macho.get("summary") or {}).get("main_binary")
        chosen = next((b for b in binaries if b.get("path") == main), None) if main else None
    if chosen is not None:
        slices = [s for s in chosen.get("slices") or [] if isinstance(s, dict)]
        pick = next((s for s in slices if str(s.get("arch", "")).startswith("arm64")), slices[0] if slices else None)
        return {"path": chosen["path"], "slice": pick.get("arch") if pick else None,
                "encrypted": bool(pick.get("encrypted")) if pick else None}
    names = {row["path"] for row, _rel in files}
    if fw_path in names:
        return {"path": fw_path, "slice": None, "encrypted": None}
    return {"path": None, "slice": None, "encrypted": None}


# --- version ---------------------------------------------------------------------------------------------
def _serialized_sources(ctx: AnalysisContext, files: List[Tuple[Dict[str, Any], str]]) -> List[Dict[str, Any]]:
    cands: List[Tuple[int, str, str, str]] = []
    for row, rel in files:
        if not rel.startswith("Data/") or "/" in rel[5:] and not rel.startswith("Data/Resources/"):
            continue
        kind = uver.serialized_source_kind(rel)
        if kind:
            cands.append((uver.SOURCE_PRIORITY.get(kind, 9), rel, kind, row["path"]))
    cands.sort()
    out: List[Dict[str, Any]] = []
    for _prio, rel, kind, path in cands[:MAX_SERIALIZED_SOURCES]:
        try:
            head = ctx.source.read_head(path, 512)  # type: ignore[union-attr]
        except (KeyError, OSError, ValueError):
            continue
        parsed = uver.parse_serialized_header(head)
        if parsed:
            out.append({"source": kind, "value": parsed["unity_version"], "ref": path,
                        "format_version": parsed["format_version"], "target_platform": parsed["target_platform"]})
    return out


def _scan_binary(local: Path) -> Tuple[Optional[int], List[Tuple[str, int]]]:
    """(count of ``il2cpp_*`` strings, [(Unity version string, count)]) of an unencrypted Mach-O file."""
    res = scan_file(local, [_IL2CPP_RE, UNITY_VERSION_RE], limit=200)
    il = res.counts.get(_IL2CPP_RE.pattern, 0)
    counts: Dict[str, int] = {}
    for h in res.get(UNITY_VERSION_RE.pattern, []):
        v = h.data.decode("ascii", "replace")
        counts[v] = counts.get(v, 0) + 1
    return il, sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


# --- findings ---------------------------------------------------------------------------------------------
def _version_finding(version: Dict[str, Any]) -> Finding:
    val = version.get("value")
    real = [c for c in version.get("conflicts", []) if c["kind"] == "real"]
    if not val:
        return Finding("unity.version", Verdict.UNKNOWN, 0.2, "Unity version not determined",
                       "No SerializedFile header, bundle header or binary string yielded a Unity version.",
                       {"version": "-", "sources": 0, "conflicts": 0, "kinds": "-"}, [], tags=["unity"])
    kinds = {s["source"].split(":")[0] for s in version["sources"]}
    conf = 0.92 if len(version["sources"]) >= 2 and not real else 0.75
    if real:
        conf = 0.5
    ev = [_ev("file", s["ref"], "%s: %s" % (s["source"], s["value"])) for s in version["sources"][:8]]
    for c in version["conflicts"][:4]:
        ev.append(_ev("heuristic", c["sources"][0]["ref"], "%s conflict: %s vs adopted %s (%s)" % (
            c["kind"], c["other"], c["adopted"], c["note"])))
    text = "Unity %s (from %d source(s))" % (val, len(version["sources"]))
    if version["conflicts"]:
        text += "; %d disagreeing value(s), see evidence" % len(version["conflicts"])
    return Finding("unity.version", Verdict.YES, conf, "Unity version determined", text,
                   {"version": val, "sources": len(version["sources"]), "conflicts": len(version["conflicts"]),
                    "kinds": ", ".join(sorted(kinds))}, ev, tags=["unity"])


def _metadata_finding(meta: Dict[str, Any], analysis: um.MetadataAnalysis, path: str) -> Finding:
    verdict = Verdict(analysis.verdict)
    ev = [_ev(k, path, d) for k, d in um.evidence_lines(analysis)]
    reasons = ", ".join(analysis.reasons)
    summaries = {
        "no": "Magic, version, section table and string table are consistent and the entropy is normal; no sign "
              "of encryption. This is a heuristic, not proof.",
        "yes": "The file is not an IL2CPP metadata file and looks uniformly random: the metadata is most likely "
               "encrypted as a whole.",
        "suspected": "The file deviates from a plain IL2CPP metadata file (%s); it may be encrypted, modified or "
                     "simply newer than the known layouts." % reasons,
        "unknown": "The file could not be analysed (%s)." % reasons,
    }
    remediation = ""
    if verdict in (Verdict.YES, Verdict.SUSPECTED):
        remediation = ("Compare with references/unity-il2cpp-metadata.md; deobfuscation is out of scope. "
                       "--force-dump tries the dump anyway.")
    return Finding("unity.metadata.encrypted", verdict, analysis.confidence, "global-metadata.dat encryption check",
                   summaries.get(analysis.verdict, ""),
                   {"version": analysis.version if analysis.version is not None else "-",
                    "entropy": analysis.entropy if analysis.entropy is not None else "-", "reasons": reasons,
                    "header_ok": str(analysis.header_ok), "path": path}, ev, remediation, tags=["unity", "il2cpp"])


def _bundle_finding(b: Dict[str, Any]) -> Finding:
    verdict = Verdict(b["verdict"])
    by = b["by_class"]
    ev: List[Evidence] = []
    for cls, paths in b["samples"].items():
        for p in paths[:3]:
            ev.append(_ev("file", p, "class %s" % cls))
    for m in b.get("block_markers", [])[:2]:
        ev.append(_ev("heuristic", b["samples"].get("block_encrypted_suspected", [""])[0],
                      "marker %s in %d/%d blocks" % (m["marker_hex"], m["blocks_with_marker"], m["blocks_sampled"])))
    for h in b.get("xor_hypotheses", [])[:2]:
        ev.append(_ev("heuristic", b["samples"].get("xor_simple", [""])[0],
                      "XOR key hypothesis %s (period %d)" % (h["key_hex"], h["period"])))
    counts = ", ".join("%s=%d" % (k, v) for k, v in by.items() if v)
    notes = {
        "yes": "Most bundle-like files have no recognisable UnityFS header and look random: they are very likely "
               "encrypted or custom-packed.",
        "no": "All bundles carry standard headers and (sampled) decompress normally.",
        "suspected": "Bundles are mixed or partly non-standard (e.g. block-level encryption suspected).",
        "unknown": "No AssetBundle files were found.",
    }
    text = "%d candidate file(s): %s. %s" % (b["total"], counts or "-", notes.get(b["verdict"], ""))
    remediation = ""
    if verdict in (Verdict.YES, Verdict.SUSPECTED):
        remediation = "See references/unity-assetbundle.md for how to verify manually. Compression is not encryption."
    return Finding("unity.assetbundle.encryption", verdict, b["confidence"], "AssetBundle protection check", text,
                   {"total": b["total"], "population": b["population"], "counts": counts or "-",
                    "sampled": b["sampled"]}, ev, remediation, tags=["unity", "assetbundle"])


# --- dump -------------------------------------------------------------------------------------------------
def _rel_posix(path: Path, base: Path) -> str:
    return PurePosixPath(*Path(os.path.relpath(str(path), str(base))).parts).as_posix()


def _dump_failure(code: Il2CppErrorCode, message: str) -> Dict[str, Any]:
    return {"ran": False, "ok": False, "backend": "", "backend_version": "", "out_dir": None, "artifacts": {},
            "error_code": code.value, "remediation": remediation_for(code), "cached": False, "duration_s": 0.0,
            "namespaces": [], "summary": {}, "message": message}


def _run_dump(ctx: AnalysisContext, binary: Dict[str, Any], meta_path: str, meta_version: Optional[int],
              unity_version: Optional[str], force: bool) -> Dict[str, Any]:
    local = ctx.extract([binary["path"], meta_path])
    lb, lm = local.get(binary["path"]), local.get(meta_path)
    if lb is None or lm is None:
        return _dump_failure(Il2CppErrorCode.E_UNKNOWN, "cannot extract the binary or metadata")
    work = ctx.workdir / "unity"
    work.mkdir(parents=True, exist_ok=True)
    try:
        with macho_parse(lb) as mf:
            sl = mf.select_slice()
            if sl is not None and sl.is_encrypted:
                out = _dump_failure(Il2CppErrorCode.E_BINARY_FAIRPLAY, "selected slice is FairPlay-encrypted")
                out["binary_encrypted"] = True
                return out
            is_fat = mf.is_fat
        thin = write_thin(lb, work / "il2cpp_binary") if is_fat else lb
    except (NotMachO, MachOError, OSError, ValueError) as exc:
        log.debug("thin/parse failed", exc_info=True)
        thin = lb
        ctx.add_warning("unity: could not parse the il2cpp binary as Mach-O (%s); passing it as is" % exc)
    out_dir = ctx.out_dir / "il2cpp"
    req = Il2CppRunRequest(binary_path=Path(thin), metadata_path=Path(lm), out_dir=out_dir,
                           unity_version=unity_version, metadata_version=meta_version, force_dump=force,
                           timeout_s=ctx.cfg.il2cpp.timeout_s, work_dir=work / "run")
    try:
        res = run_il2cpp_dump(req, None, ctx.cfg)
    except Exception as exc:  # noqa: BLE001 - a dumper problem must never lose the earlier verdicts
        log.exception("il2cpp dump crashed")
        return _dump_failure(Il2CppErrorCode.E_UNKNOWN, "dump crashed: %s: %s" % (type(exc).__name__, exc))
    base = Path(res.out_dir) if res.out_dir else out_dir
    artifacts = {k: _rel_posix(base / v, ctx.out_dir) for k, v in (res.artifacts or {}).items()}
    for k, v in artifacts.items():
        ctx.register_artifact("il2cpp." + k, v)
    code = res.error_code.value if res.error_code else None
    dump: Dict[str, Any] = {
        "ran": True, "ok": bool(res.ok), "backend": res.backend, "backend_version": res.backend_version,
        "out_dir": _rel_posix(base, ctx.out_dir), "artifacts": artifacts, "error_code": code,
        "remediation": res.remediation or (remediation_for(res.error_code) if res.error_code else ""),
        "cached": bool(res.cached), "duration_s": round(float(res.duration_s), 2), "namespaces": [], "summary": {},
        "message": res.message, "attempts": list(res.attempts or []),
        "stdout_tail": list(res.stdout_tail or [])[-20:], "stderr_tail": list(res.stderr_tail or [])[-20:],
    }
    if res.ok:
        try:
            summ = summarize_dump(base)
            dump["namespaces"] = list(summ.namespaces)[:500]
            dump["summary"] = summ.to_dict()
            if summ.namespaces_file:
                dump["summary"]["namespaces_file"] = _rel_posix(base / summ.namespaces_file, ctx.out_dir)
        except Exception as exc:  # noqa: BLE001
            ctx.add_warning("unity: dump summary failed: %s" % exc)
    return dump


def _dump_params(dump: Dict[str, Any], state: str) -> Dict[str, Any]:
    s = dump.get("summary") or {}
    return {"state": state, "backend": dump.get("backend") or "-", "backend_version": dump.get("backend_version") or "-",
            "classes": s.get("classes", 0), "methods": s.get("methods", 0), "out_dir": dump.get("out_dir") or "-",
            "cached": bool(dump.get("cached")), "error_code": dump.get("error_code") or "-",
            "message": dump.get("message") or dump.get("skipped_reason") or "-"}


def _dump_finding(dump: Dict[str, Any], state: str, pre: Dict[str, Any]) -> Finding:
    """``state``: ``ran`` (a run was attempted), ``blocked`` (pre-check), ``n/a``."""
    if state == "n/a":
        return Finding("unity.il2cpp.dump", Verdict.NA, 0.9, "il2cpp dump not applicable",
                       "No dump: %s." % (dump.get("message") or dump.get("skipped_reason", "n/a")),
                       _dump_params(dump, "n/a"), [], tags=["unity", "il2cpp"])
    if dump.get("ok"):
        s = dump.get("summary") or {}
        return Finding("unity.il2cpp.dump", Verdict.YES, 0.95, "il2cpp dump produced",
                       "Dumped with %s %s: %s classes, %s methods." % (
                           dump.get("backend"), dump.get("backend_version"), s.get("classes", "?"), s.get("methods", "?")),
                       _dump_params(dump, "ok"), [_ev("file", dump.get("out_dir") or "il2cpp", "dump artifacts")],
                       tags=["unity", "il2cpp"])
    code = dump.get("error_code") or "E_UNKNOWN"
    ev = [_ev("heuristic", "precheck", r) for r in pre.get("reasons", [])[:4]]
    for ln in (dump.get("stdout_tail") or [])[-3:]:
        ev.append(_ev("tool_output", dump.get("backend") or "il2cpp", ln))
    return Finding("unity.il2cpp.dump", Verdict.NO, 0.9, "il2cpp dump not produced",
                   "No dump was produced (%s). %s" % (code, dump.get("message", "")),
                   _dump_params(dump, "blocked" if state == "blocked" else "failed"), ev, dump.get("remediation", ""),
                   tags=["unity", "il2cpp"])


def _obfuscation_finding(dump: Dict[str, Any], id_stats: Optional[Dict[str, Any]], meta_path: str) -> Optional[Finding]:
    levels = {"none": (Verdict.NO, 0.8), "low": (Verdict.SUSPECTED, 0.4), "medium": (Verdict.SUSPECTED, 0.65),
              "high": (Verdict.YES, 0.8)}
    obf = ((dump.get("summary") or {}).get("obfuscation")) if dump.get("ok") else None
    if obf and obf.get("level") in levels:
        v, c = levels[obf["level"]]
        return Finding("unity.il2cpp.names_obfuscated", v, c, "Identifier obfuscation",
                       "Identifier obfuscation level from the dump: %s (score %s)." % (obf["level"], obf.get("score")),
                       {"level": obf["level"], "score": obf.get("score", 0), "source": "dump"},
                       [_ev("tool_output", dump.get("out_dir") or "il2cpp", "non_standard_ratio=%s short_ratio=%s" % (
                           obf.get("non_standard_ratio"), obf.get("short_ratio")))], tags=["unity", "il2cpp"])
    if id_stats and id_stats.get("level") in levels:
        v, c = levels[id_stats["level"]]
        return Finding("unity.il2cpp.names_obfuscated", v, min(c, 0.6), "Identifier obfuscation",
                       "Identifier obfuscation level estimated from the metadata string table: %s." % id_stats["level"],
                       {"level": id_stats["level"], "score": id_stats["short_ratio"], "source": "metadata"},
                       [_ev("heuristic", meta_path, "short_ratio=%s non_ascii_ratio=%s over %s names" % (
                           id_stats["short_ratio"], id_stats["non_ascii_ratio"], id_stats["tokens"]))],
                       tags=["unity", "il2cpp"])
    return None


# --- stage --------------------------------------------------------------------------------------------------
@register(name='engine.unity', requires=('engine.detect', 'inventory'), after=('macho', 'meta'))
class EngineUnityStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        detect = DetectResult.from_dict(ctx.results.get("engine.detect") or {})
        cand = next((c for c in detect.candidates if c.id == "unity" and c.confidence > 0), None)
        if cand is None and detect.primary_id != "unity":
            return StageResult.skipped(NAME, "not a Unity app")
        if ctx.source is None:
            return StageResult.skipped(NAME, "no input source is open")
        findings: List[Finding] = []
        warnings: List[str] = []
        files = _app_files(ctx)
        paths_rel = [(row["path"], rel) for row, rel in files]
        data: Dict[str, Any] = {}

        # --- backend inputs ---------------------------------------------------------------------------
        meta_loc = _find_metadata(files)
        mono_names = umono.select_assemblies(paths_rel)
        if meta_loc and not mono_names:
            backend = "il2cpp"
        elif mono_names and not meta_loc:
            backend = "mono"
        else:
            backend = "unknown"
        data["backend"] = backend
        binary = _pick_binary(ctx, files)
        data["binary"] = dict(binary)

        # --- bundles ------------------------------------------------------------------------------------
        try:
            cands = ub.select_candidates((row for row, _rel in files), ctx.rel)
            bundles = ub.analyze_bundles(cands, ctx.source, deep_sample=ctx.cfg.unity.bundle_deep_sample)
            bundles["addressables"] = ub.detect_addressables(paths_rel)
        except Exception as exc:  # noqa: BLE001 - keep the other verdicts
            log.exception("bundle analysis failed")
            warnings.append("bundle analysis failed: %s" % exc)
            bundles = {"total": 0, "population": 0, "by_class": {c: 0 for c in ub.CLASSES}, "compression": {},
                       "unity_versions": {}, "samples": {}, "paths_sample": [], "sampled": 0,
                       "verdict": "unknown", "confidence": 0.0, "reasons": ["error"],
                       "addressables": {"catalog_found": False}}
        data["bundles"] = bundles

        # --- metadata -----------------------------------------------------------------------------------
        analysis: Optional[um.MetadataAnalysis] = None
        id_stats: Optional[Dict[str, Any]] = None
        meta: Dict[str, Any]
        if meta_loc:
            mpath, msize = meta_loc
            try:
                with ctx.source.open(mpath) as fh:
                    analysis = um.analyze_metadata(fh, msize or _size(ctx, mpath))
                    if analysis.string_region and analysis.string_assessment and analysis.string_assessment["readable"]:
                        id_stats = um.identifier_stats(um.string_region_info(fh, analysis.string_region))
            except (KeyError, OSError, ValueError) as exc:
                warnings.append("cannot read %s: %s" % (mpath, exc))
        if analysis is not None:
            ev = [_ev(k, meta_loc[0], d).to_dict() for k, d in um.evidence_lines(analysis)]
            meta = {"path": meta_loc[0], "present": True, "version": analysis.version,
                    "header_ok": analysis.header_ok, "entropy": analysis.entropy,
                    "string_region_ok": analysis.string_region_ok, "string_region": analysis.string_region,
                    "verdict": analysis.verdict, "confidence": analysis.confidence, "evidence": ev,
                    "reasons": list(analysis.reasons), "supported_by": list(analysis.supported_by),
                    "version_known": analysis.version_known, "magic_ok": analysis.magic_ok,
                    "hypotheses": list(analysis.hypotheses)}
            if id_stats:
                meta["identifier_stats"] = id_stats
        elif meta_loc:
            meta = {"path": meta_loc[0], "present": True, "version": None, "header_ok": None, "entropy": None,
                    "string_region_ok": None, "string_region": None, "verdict": "unknown", "confidence": 0.0,
                    "evidence": [], "reasons": ["unreadable"], "supported_by": []}
        else:
            meta = {"path": None, "present": False, "version": None, "header_ok": None, "entropy": None,
                    "string_region_ok": None, "string_region": None, "verdict": "n/a", "confidence": 0.0,
                    "evidence": [], "reasons": []}
        data["metadata"] = meta

        # --- binary scan + version -------------------------------------------------------------------
        il2cpp_markers: Optional[int] = None
        binary_versions: List[Tuple[str, int]] = []
        if binary["path"] and binary["encrypted"] is False:
            local = ctx.extract([binary["path"]]).get(binary["path"])
            if local is not None:
                try:
                    il2cpp_markers, binary_versions = _scan_binary(local)
                except OSError as exc:
                    warnings.append("cannot scan %s: %s" % (binary["path"], exc))
        sources: List[Dict[str, Any]] = _serialized_sources(ctx, files)
        for v, _n in binary_versions[:2]:
            sources.append({"source": "binary", "value": v, "ref": binary["path"]})
        for v, _n in sorted(bundles.get("unity_versions", {}).items(), key=lambda kv: (-kv[1], kv[0]))[:3]:
            sample = (bundles["samples"].get("standard") or bundles["paths_sample"] or [""])[0]
            sources.append({"source": "bundle", "value": v, "ref": sample})
        version = uver.resolve_version(sources)
        data["version"] = version
        data["version"]["china_variant_hint"] = uver.china_variant(version["value"])
        if binary["encrypted"] is True:
            warnings.append("main il2cpp binary is FairPlay-encrypted: binary strings were not used for the version")

        # --- mono -----------------------------------------------------------------------------------------
        mono = umono.analyze_mono(mono_names, ctx.source.open, lambda n: ctx.source.stat(n).size) if mono_names else {
            "assemblies": [], "verdict": "n/a", "confidence": 0.0, "reasons": ["no_managed_assemblies"]}
        mono["evidence"] = [_ev("file", a["path"], "%s%s" % (
            a["format"], " (valid PE/CLI)" if a["valid_pe_cli"] else "")).to_dict() for a in mono["assemblies"][:10]]
        data["mono"] = mono

        # --- precheck -------------------------------------------------------------------------------------
        support = um.backend_support(meta["version"])
        force = bool(ctx.cfg.il2cpp.force_dump)
        pre = upre.run_precheck(backend=backend, binary=binary, metadata=meta, il2cpp_markers=il2cpp_markers,
                                support=support, force_dump=force, unity_version=version["value"])
        data["precheck"] = pre

        # --- dump -----------------------------------------------------------------------------------------
        dump: Dict[str, Any]
        dump_state = "n/a"
        if backend != "il2cpp":
            dump = {"ran": False, "ok": False, "skipped_reason": "backend_%s" % backend,
                    "message": "the il2cpp dump needs an IL2CPP build with a metadata file"}
        elif not ctx.cfg.il2cpp.enabled:
            dump = {"ran": False, "ok": False, "skipped_reason": "disabled", "message": "disabled by --no-il2cpp"}
        elif not pre["ready"]:
            code = pre.get("error_code") or "E_UNKNOWN"
            dump_state = "blocked"
            dump = {"ran": False, "ok": False, "error_code": code,
                    "remediation": remediation_for(Il2CppErrorCode(code)) if code in Il2CppErrorCode.__members__ else "",
                    "message": "blocked by the pre-check: %s" % ", ".join(pre["reasons"]),
                    "backend": "", "backend_version": "", "out_dir": None, "artifacts": {}, "cached": False,
                    "duration_s": 0.0, "namespaces": [], "summary": {}}
        else:
            dump_state = "ran"
            dump = _run_dump(ctx, binary, meta["path"], meta["version"], _core(version["value"]),
                             force or bool(pre.get("forced")))
            if dump.get("binary_encrypted"):
                binary["encrypted"] = True
                pre["ready"], pre["error_code"] = False, "E_BINARY_FAIRPLAY"
                pre["reasons"] = ["binary_fairplay"]
        data["dump"] = dump

        # --- findings ---------------------------------------------------------------------------------------
        findings.append(Finding("unity.detected", Verdict.YES, cand.confidence if cand else 0.5, "Unity engine detected",
                                "Unity %s, backend %s." % (version["value"] or "(version unknown)", backend),
                                {"version": version["value"] or "-", "backend": backend},
                                [_ev("heuristic", "engine.detect", "unity candidate")], tags=["unity"]))
        findings.append(_version_finding(version))
        findings.append(self._backend_finding(backend, meta, mono_names, binary))
        findings.append(self._present_finding(meta, il2cpp_markers))
        if analysis is not None and meta_loc:
            findings.append(_metadata_finding(meta, analysis, meta_loc[0]))
        findings.append(self._fairplay_finding(binary))
        findings.append(self._precheck_finding(pre, backend))
        findings.append(_dump_finding(dump, dump_state if backend == "il2cpp" and ctx.cfg.il2cpp.enabled else "n/a", pre))
        ob = _obfuscation_finding(dump, id_stats, meta.get("path") or "")
        if ob is not None:
            findings.append(ob)
        findings.append(_bundle_finding(bundles))
        if mono["assemblies"]:
            findings.append(self._mono_finding(mono))

        # --- status -------------------------------------------------------------------------------------------
        warnings.extend("precheck: %s" % w for w in pre.get("warnings", []))
        failed_dump = dump_state == "ran" and not dump.get("ok")
        if failed_dump:
            return StageResult.partial(NAME, data, findings, warnings,
                                       reason="il2cpp dump failed: %s" % dump.get("error_code"))
        return StageResult.ok(NAME, data, findings, warnings)

    # --- small finding builders ------------------------------------------------------------------------
    @staticmethod
    def _backend_finding(backend: str, meta: Dict[str, Any], mono_names: List[str], binary: Dict[str, Any]) -> Finding:
        ev: List[Evidence] = []
        if meta.get("path"):
            ev.append(_ev("file", meta["path"], "global-metadata.dat present"))
        ev.extend(_ev("file", n, "managed assembly") for n in mono_names[:3])
        if binary.get("path"):
            ev.append(_ev("macho", binary["path"], "il2cpp-carrying binary candidate"))
        if backend == "il2cpp":
            return Finding("unity.backend", Verdict.YES, 0.95, "Scripting backend: IL2CPP",
                           "global-metadata.dat is present and no loose managed assemblies were found.",
                           {"backend": backend}, ev, tags=["unity"])
        if backend == "mono":
            return Finding("unity.backend", Verdict.YES, 0.9, "Scripting backend: Mono",
                           "Managed assemblies under Data/Managed and no global-metadata.dat.",
                           {"backend": backend}, ev, tags=["unity"])
        return Finding("unity.backend", Verdict.UNKNOWN, 0.3, "Scripting backend unknown",
                       "Neither (or both of) global-metadata.dat and Data/Managed assemblies were found.",
                       {"backend": backend}, ev, tags=["unity"])

    @staticmethod
    def _present_finding(meta: Dict[str, Any], il2cpp_markers: Optional[int]) -> Finding:
        if meta["present"]:
            return Finding("unity.metadata.present", Verdict.YES, 0.97, "global-metadata.dat found",
                           "Found %s." % meta["path"], {"path": meta["path"]},
                           [_ev("file", meta["path"], "global-metadata.dat")], tags=["unity", "il2cpp"])
        if il2cpp_markers:
            return Finding("unity.metadata.present", Verdict.UNKNOWN, 0.4, "global-metadata.dat not found",
                           "The binary carries il2cpp markers but no metadata file was found at the usual path; "
                           "it may be renamed or loaded from elsewhere.", {"path": "-"}, [], tags=["unity", "il2cpp"])
        return Finding("unity.metadata.present", Verdict.NO, 0.8, "global-metadata.dat not found",
                       "No global-metadata.dat in the app.", {"path": "-"}, [], tags=["unity", "il2cpp"])

    @staticmethod
    def _fairplay_finding(binary: Dict[str, Any]) -> Finding:
        enc = binary.get("encrypted")
        ev = [_ev("macho", binary["path"], "slice %s encrypted=%s" % (binary.get("slice"), enc))] if binary.get("path") else []
        if enc is True:
            return Finding("unity.binary.fairplay", Verdict.YES, 0.97, "il2cpp binary is FairPlay-encrypted",
                           "The Unity binary carries LC_ENCRYPTION_INFO with cryptid != 0; its code cannot be read. "
                           "This tool never decrypts.", {"path": binary["path"]}, ev,
                           "Provide an IPA that its owner has already decrypted.", tags=["unity", "fairplay"])
        if enc is False:
            return Finding("unity.binary.fairplay", Verdict.NO, 0.95, "il2cpp binary is not FairPlay-encrypted",
                           "The Unity binary is readable.", {"path": binary["path"]}, ev, tags=["unity", "fairplay"])
        return Finding("unity.binary.fairplay", Verdict.UNKNOWN, 0.3, "il2cpp binary encryption unknown",
                       "No Mach-O information was available for the Unity binary.", {"path": binary.get("path") or "-"},
                       ev, tags=["unity", "fairplay"])

    @staticmethod
    def _precheck_finding(pre: Dict[str, Any], backend: str) -> Finding:
        ev = [_ev("heuristic", "precheck", r) for r in pre.get("reasons", [])]
        ev += [_ev("heuristic", "precheck", "warning: " + w) for w in pre.get("warnings", [])]
        if backend != "il2cpp":
            return Finding("unity.il2cpp.precheck", Verdict.NA, 0.9, "il2cpp pre-check not applicable",
                           "The app does not use the IL2CPP backend (or it could not be determined).",
                           {"error_code": "-", "reasons": ", ".join(pre.get("reasons", [])) or "-", "backends": "-"},
                           ev, tags=["unity", "il2cpp"])
        if pre["ready"]:
            return Finding("unity.il2cpp.precheck", Verdict.YES, 0.9, "Ready for an il2cpp dump",
                           "Binary and metadata pass the pre-checks%s." % (" (forced)" if pre.get("forced") else ""),
                           {"error_code": "-", "reasons": ", ".join(pre["reasons"]) or "-",
                            "backends": ", ".join(pre["backends"]) or "-"}, ev, tags=["unity", "il2cpp"])
        code = pre.get("error_code") or "-"
        return Finding("unity.il2cpp.precheck", Verdict.NO, 0.9, "il2cpp dump is blocked by the pre-check",
                       "The dump was not attempted (%s)." % code,
                       {"error_code": code, "reasons": ", ".join(pre["reasons"]) or "-",
                        "backends": ", ".join(pre["backends"]) or "-"},
                       ev, remediation_for(Il2CppErrorCode(code)) if code in Il2CppErrorCode.__members__ else "",
                       tags=["unity", "il2cpp"])

    @staticmethod
    def _mono_finding(mono: Dict[str, Any]) -> Finding:
        v = Verdict(mono["verdict"]) if mono["verdict"] in {x.value for x in Verdict} else Verdict.UNKNOWN
        bad = [a for a in mono["assemblies"] if not a["valid_pe_cli"]]
        ev = [_ev("file", a["path"], a["format"]) for a in (bad or mono["assemblies"])[:6]]
        hints = mono.get("obfuscator_hints") or []
        text = "%d managed assembly(ies), %d invalid." % (len(mono["assemblies"]), len(bad))
        if hints:
            text += " Possible obfuscator markers: %s (low confidence)." % ", ".join(hints)
        return Finding("unity.mono.dll_encrypted", v, mono["confidence"], "Managed assembly integrity", text,
                       {"total": len(mono["assemblies"]), "invalid": len(bad), "hints": ", ".join(hints) or "-"},
                       ev, tags=["unity", "mono"])


def _size(ctx: AnalysisContext, name: str) -> int:
    try:
        return int(ctx.source.stat(name).size)  # type: ignore[union-attr]
    except (KeyError, OSError):
        return 0


def _core(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    p = uver.parse_unity_version(value)
    return p["core"] if p else value
