"""Egret and LayaAir checkers: script / resource form (plain, packed, suspected encrypted) and version hints.

Both engines publish JavaScript (``egret*.js`` / ``laya*.js`` plus game code) and data files that are normally plain
JSON / text (``*.res.json``, ``*.thm.json``, ``*.exml``, ``manifest.json``; ``.atlas``, ``.lh``, ``.lmat``, ``.ls``).
A file of such a type that is neither text nor a known format, or that carries a custom header, is reported as
suspected encryption / obfuscation; plain minified code is not.  See ``references/egret-laya.md`` for the file
names (most of them UNVERIFIED: the official documentation could not be fetched), thresholds are in
``data/engines_checks.json`` sections ``egret`` and ``laya``.  Detection only.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from ...models import Evidence, Status, Verdict
from ..api import CheckerResult, DetectResult, register_checker
from ..formats import common
from ..formats.common import FileIndex, ScriptTally


def _analyse(ctx: Any, idx: FileIndex, cfg: Dict[str, Any], engine_id: str, name: str,
             marker_regexes: List[str], data_exts: List[str], version_files: List[str],
             version_regexes: List[str]) -> CheckerResult:
    markers: List[str] = []
    for rx in marker_regexes:
        hits = idx.find(rx)
        if hits:
            markers.append(hits[0].rel)
    # --- scripts: every non-vendor .js (engine libs, game code, wrapped files)
    js = idx.not_vendor(idx.with_ext(".js", ".jsc"))
    sample, total = common.evenly_sample(js, cfg["script_sample_max"])
    stally = ScriptTally()
    for r in sample:
        blob, _ = common.classify_file(ctx, r)
        stally.add(r.rel, r.ext, blob)
    scripts = stally.to_dict(sampled=len(sample), of=total)
    # --- resources
    res = idx.not_vendor(idx.with_ext(*data_exts))
    rsample, rtotal = common.evenly_sample(res, cfg["resource_sample_max"])
    rtally = ScriptTally()
    for r in rsample:
        rtally.add(r.rel, r.ext, common.classify_resource(ctx, r))
    resources = rtally.to_dict(sampled=len(rsample), of=rtotal)
    clusters = common.find_wrapper_clusters(ctx, idx.not_vendor(idx.recs))
    version = None
    for rel in version_files:
        for rec in idx.find(rel)[:2]:
            if rec.size > cfg["version_scan_max_bytes"]:
                continue
            blob = common.read_head(ctx, rec.path, rec.size)
            for rx in version_regexes:
                m = re.search(rx.encode("ascii"), blob)
                if m:
                    version = {"value": m.group(1).decode("ascii", "replace"), "source": rec.rel}
                    break
            if version:
                break
        if version:
            break
    data: Dict[str, Any] = {
        "variant": engine_id, "markers": markers, "version_hint": version["value"] if version else None,
        "version_source": version["source"] if version else None, "scripts": scripts, "resources": resources,
        "wrapper_clusters": clusters,
    }
    if engine_id == "egret":
        data["manifest"] = _egret_manifest(ctx, idx)
    findings = []
    sv, sc, ss = common.verdict_from_tally(stally, total)
    note = ""
    ev: List[Evidence] = []
    if stally.kinds.get(common.K_PLAIN) and sv == Verdict.NO:
        note = "Plain JavaScript (possibly minified); minification is not encryption."
    for kk in (common.K_CUSTOM_HEADER, common.K_HIGH_ENTROPY, common.K_PLAIN):
        ev.extend(common.file_evidence(stally.samples.get(kk, []), kk, 2))
    findings.append(common.script_finding(engine_id, name, scripts, sv, sc, ss, ev, note))
    rv, rc, rs = common.verdict_from_tally(rtally, rtotal)
    rnote = ""
    rev: List[Evidence] = []
    if clusters and rv in (Verdict.NO, Verdict.NA, Verdict.UNKNOWN):
        rv, rc, rs = Verdict.SUSPECTED, 0.7, "suspected"
    if clusters:
        c0 = clusters[0]
        rnote = ("%d file(s) with a standard extension share the custom header '%s' (vendor not asserted)."
                 % (sum(c["files"] for c in clusters), c0["tag"]))
        rev.append(Evidence("heuristic", "custom header %s" % c0["tag"], "exts %s" % c0["exts"]))
    for kk in (common.K_CUSTOM_HEADER, common.K_HIGH_ENTROPY):
        rev.extend(common.file_evidence(rtally.samples.get(kk, []), kk, 2))
    findings.append(common.resource_finding(engine_id, name, resources, rv, rc, rs, rev, rnote))
    return CheckerResult(findings=findings, data=data, status=Status.OK)


def _egret_manifest(ctx: Any, idx: FileIndex) -> Optional[Dict[str, Any]]:
    rec = idx.get("manifest.json")
    if rec is None or rec.size > 1 << 20:
        return None
    try:
        doc = json.loads(common.read_head(ctx, rec.path, rec.size).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {"plain_json": False}
    if not isinstance(doc, dict):
        return {"plain_json": True}
    return {"plain_json": True, "initial": len(doc.get("initial") or []), "game": len(doc.get("game") or [])}


def _marker_applies(ctx: Any, cfg: Dict[str, Any]) -> bool:
    idx = FileIndex(ctx)
    if any(idx.find(rx) for rx in cfg["strong_markers"]):
        return True
    return sum(1 for rx in cfg["markers"] if idx.find(rx)) >= cfg["min_markers"]


@register_checker("egret")
class EgretChecker:
    engine_id = "egret"

    def applies(self, ctx: Any, detect: DetectResult) -> bool:
        if detect.has("egret"):
            return True
        return _marker_applies(ctx, common.checks("egret"))

    def run(self, ctx: Any, detect: DetectResult) -> CheckerResult:
        cfg = common.checks("egret")
        return _analyse(ctx, FileIndex(ctx), cfg, "egret", "Egret", cfg["markers"], cfg["data_exts"],
                        cfg["version_files"], cfg["version_regexes"])


@register_checker("laya")
class LayaChecker:
    engine_id = "laya"

    def applies(self, ctx: Any, detect: DetectResult) -> bool:
        if detect.has("layaair") or detect.has("laya"):
            return True
        return _marker_applies(ctx, common.checks("laya"))

    def run(self, ctx: Any, detect: DetectResult) -> CheckerResult:
        cfg = common.checks("laya")
        return _analyse(ctx, FileIndex(ctx), cfg, "laya", "LayaAir", cfg["markers"], cfg["data_exts"],
                        cfg["version_files"], cfg["version_regexes"])
