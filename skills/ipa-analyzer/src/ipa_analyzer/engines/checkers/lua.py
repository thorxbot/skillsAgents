"""Generic Lua / LuaJIT checker (self-made engines, Defold-like hosts, anything shipping ``.lua`` / ``.luac``).

Classifies every Lua-looking file as plain source, valid bytecode, tampered bytecode (signature is Lua but the
header deviates), Lua-after-XOR (a short repeating XOR key turns the head into a valid Lua header -- evidence
only, the key is not reported), compressed, or unidentified / high entropy, and renders the Lua version profile
shared with ``engine.unity.hotfix`` (``engines/formats/lua_profile.py``).  The Cocos checker has its own, richer
pass and the ``lua`` checker stays out of its way when ``engine.detect`` names a Cocos engine.
Headers are parsed by ``ipa_analyzer.formats.lua_bytecode``; bytecode is compiled code, not encryption.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ...models import Evidence, Status
from ..api import CheckerResult, DetectResult, register_checker
from ..formats import common, lua_profile
from ..formats.common import FileIndex, FileRec, ScriptTally


def _lua_files(idx: FileIndex, cfg: Dict[str, Any]) -> List[FileRec]:
    return idx.not_vendor([r for r in idx.recs if r.ext in cfg["lua_exts"] or r.magic == "lua_bytecode"])


@register_checker("lua")
class LuaChecker:
    engine_id = "lua"
    fallback = True     # only runs when no dedicated checker applies (see analyzers/engines_other.py)

    def applies(self, ctx: Any, detect: DetectResult) -> bool:
        if any(i.startswith("cocos") or i == "modified_cocos" for i in detect.candidate_ids()):
            return False
        cfg = common.checks("lua")
        return len(_lua_files(FileIndex(ctx), cfg)) >= cfg["min_files"]

    def run(self, ctx: Any, detect: DetectResult) -> CheckerResult:
        cfg = common.checks("lua")
        idx = FileIndex(ctx)
        files = _lua_files(idx, cfg)
        sample, total = common.evenly_sample(files, cfg["script_sample_max"])
        tally = ScriptTally()
        prof = lua_profile.LuaProfiler()
        text_budget = cfg["lua_dialect_files"]
        for r in sample:
            blob, head = common.classify_file(ctx, r)
            text = None
            if blob.kind == common.K_PLAIN and text_budget > 0:
                text = common.read_head(ctx, r.path, cfg["lua_dialect_bytes"])
                text_budget -= 1
            tally.add(r.rel, r.ext, blob)
            prof.add(blob, text)
        binary = common.scan_main_binary(ctx, lua_profile.RUNTIME_PATTERNS)
        runtime = lua_profile.runtime_from_hits(binary.hits)
        profile = prof.to_dict(runtime)
        scripts = tally.to_dict(sampled=len(sample), of=total)
        scripts["lua"] = profile
        verdict, conf, state = common.verdict_from_tally(tally, total)
        ev: List[Evidence] = []
        for kk in (common.K_LUA_BC_TAMPERED, common.K_LUA_XOR, common.K_CUSTOM_HEADER, common.K_HIGH_ENTROPY,
                   common.K_LUA_BC, common.K_PLAIN):
            ev.extend(common.file_evidence(tally.samples.get(kk, []), kk, 2))
        by = profile["bytecode"]["by_version"]
        notes = []
        if by:
            notes.append("Lua bytecode versions: %s (bytecode is compiled code, not encryption)." % ", ".join(
                "%s x%d" % kv for kv in by.items()))
        if profile["custom_lua_suspected"]:
            notes.append("Headers with Lua signatures that deviate from the official layout or look XOR-masked: a "
                         "modified Lua is possible (opcode re-ordering cannot be seen from headers).")
        if binary.status != "scanned":
            notes.append("Runtime version string: %s." % (binary.reason or binary.status))
        f = common.script_finding("lua", "Lua", scripts, verdict, conf, state, ev, " ".join(notes))
        data = {"scripts": scripts, "binary_scan": binary.to_dict()}
        return CheckerResult(findings=[f], data=data, status=Status.OK)
