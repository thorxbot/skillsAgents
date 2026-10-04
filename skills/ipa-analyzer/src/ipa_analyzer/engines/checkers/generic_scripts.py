"""Fallback checker for engines nobody else describes: script-like files and custom file wrappers.

Runs when ``engine.detect`` names no engine handled by a dedicated checker (or flags a custom engine).  It
classifies ``.js`` / ``.lua`` / ``.luac`` / ``.py`` / ``.pyc`` / ``.json`` / ``.txt`` files outside SDK frameworks as
plain text, bytecode, compressed, or unidentified (custom 4-byte header / high entropy), and clusters files whose
extension names a standard format although the content is not that format and a shared custom header starts
them (``find_wrapper_clusters``).  The vendor or engine behind a custom header is never asserted.

``engine.script.encrypted``: ``suspected`` when scripts are neither text nor known bytecode; ``no`` only when all
examined script files are plain / bytecode / compressed.  ``engine.resource.encrypted`` (``suspected``) is added
when wrapper clusters cover non-script resources.  Detection only; nothing is decrypted.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ...models import Evidence, Status, Verdict
from ..api import CheckerResult, DetectResult, register_checker
from ..formats import common, lua_profile, xxtea_hint
from ..formats.common import FileIndex, ScriptTally


def _handled(detect: DetectResult, cfg: Dict[str, Any]) -> bool:
    """True when a dedicated checker is responsible for the detected engine."""
    ids = set(detect.candidate_ids(min_confidence=cfg["handled_min_confidence"]))
    if detect.primary_id:
        ids.add(detect.primary_id)
    return any(i in cfg["handled_ids"] or i.startswith("cocos") for i in ids)


@register_checker("generic_scripts")
class GenericScriptsChecker:
    engine_id = "generic_scripts"
    fallback = True     # only runs when no dedicated checker applies (see analyzers/engines_other.py)

    def applies(self, ctx: Any, detect: DetectResult) -> bool:
        cfg = common.checks("generic_scripts")
        if _handled(detect, cfg):
            return False
        idx = FileIndex(ctx)
        cands = idx.not_vendor([r for r in idx.recs if r.ext in cfg["script_exts"] and r.ext not in cfg["info_exts"]])
        if detect.custom.get("verdict") in ("yes", "suspected") and (cands or idx.header_clusters):
            return True
        if idx.header_clusters:
            return True
        return len(cands) >= cfg["min_script_files"]

    def run(self, ctx: Any, detect: DetectResult) -> CheckerResult:
        cfg = common.checks("generic_scripts")
        idx = FileIndex(ctx)
        script_exts = [e for e in cfg["script_exts"]]
        cands = idx.not_vendor([r for r in idx.recs if r.ext in script_exts or r.magic == "lua_bytecode"])
        sample, total = common.evenly_sample(cands, cfg["script_sample_max"])
        tally = ScriptTally()
        prof = lua_profile.LuaProfiler()
        heads_susp: List[bytes] = []
        sizes_susp: List[int] = []
        budget = cfg["lua_dialect_files"]
        for r in sample:
            blob, head = common.classify_file(ctx, r)
            tally.add(r.rel, r.ext, blob)
            if blob.bucket == "suspected_encrypted":
                heads_susp.append(head)
                sizes_susp.append(r.size)
            if r.ext in (".lua", ".luac") or blob.kind in (common.K_LUA_BC, common.K_LUA_BC_TAMPERED, common.K_LUA_XOR):
                text = None
                if blob.kind == common.K_PLAIN and budget > 0:
                    text = common.read_head(ctx, r.path, cfg["lua_dialect_bytes"])
                    budget -= 1
                prof.add(blob, text)
        scripts = tally.to_dict(sampled=len(sample), of=total)
        if prof.total:
            scripts["lua"] = prof.to_dict([])
        clusters = common.find_wrapper_clusters(ctx, idx.not_vendor(idx.recs))
        hint = xxtea_hint.script_hint(heads_susp, sizes_susp, cfg["xxtea"]) if heads_susp else None
        verdict, conf, state = common.verdict_from_tally(tally, total)
        ev: List[Evidence] = []
        for kk in (common.K_CUSTOM_HEADER, common.K_HIGH_ENTROPY, common.K_LUA_BC_TAMPERED, common.K_LUA_XOR,
                   common.K_ENCODED_TEXT, common.K_PLAIN):
            ev.extend(common.file_evidence(tally.samples.get(kk, []), kk, 2))
        note = ""
        if hint and hint["sign_prefix"]:
            sp = hint["sign_prefix"]
            note = "Shared leading bytes %s%s across the unidentified scripts%s." % (
                sp["hex"], " (%r)" % sp["ascii"] if sp["ascii"] else "",
                "; ciphertext-shaped sizes" if hint["xxtea_shape"] else "")
        findings = [common.script_finding("generic_scripts", "Generic scripts", scripts, verdict, conf, state, ev, note)]
        non_script = [c for c in clusters if set(c["exts"]) - set(script_exts)]
        if non_script:
            wrapped = sum(c["files"] for c in non_script)
            c0 = non_script[0]
            rev = [Evidence("heuristic", "custom header %s" % c0["tag"], "%d files, exts %s" % (c0["files"], c0["exts"]))]
            rev.extend(common.file_evidence(c0["examples"], "custom header", 2))
            rt = {"total": wrapped, "plain": 0, "suspected_encrypted": wrapped, "counts": {"sampled": wrapped}}
            findings.append(common.resource_finding(
                "generic_scripts", "Generic scripts", rt, Verdict.SUSPECTED, 0.7, "suspected", rev,
                "Files with standard extensions (%s) start with the custom header '%s' instead of the standard format "
                "(probable custom wrapping or encryption; vendor not asserted)." % (", ".join(sorted(c0["exts"])), c0["tag"])))
        data: Dict[str, Any] = {"scripts": scripts, "wrapper_clusters": clusters, "xxtea_hint": hint,
                                "inventory_header_clusters": idx.header_clusters[:cfg["max_inventory_clusters"]]}
        return CheckerResult(findings=findings, data=data, status=Status.OK)
