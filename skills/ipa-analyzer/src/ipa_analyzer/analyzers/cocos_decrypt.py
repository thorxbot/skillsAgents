"""Stage ``cocos.decrypt`` (opt-in): recover the Cocos XXTEA key and decrypt Lua / ``.jsc`` scripts.

Runs only when ``Config.cocos.enabled`` (CLI ``--cocos-decrypt``) is set -- the default pipeline never decrypts.
It is for apps the operator owns or is authorised to assess: the key is the one the app ships in its own binary
to decrypt its own content at run time.  See ``crypto/cocos.py`` and ``references/cocos-family.md``.

Output: decrypted scripts under ``<out>/decrypted/`` (mirroring their in-app path) plus ``decrypted/manifest.json``.
On a FairPlay-encrypted binary the embedded key strings are ciphertext, so key recovery usually fails and the
stage reports that instead (supply ``--xxtea-key`` from an authorised source, or analyse a decrypted IPA).
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from ..context import AnalysisContext
from ..crypto import cocos as cdec
from ..engines.formats import common
from ..engines.formats.common import FileIndex, FileRec
from ..models import Evidence, StageResult, Verdict
from ..registry import register

log = logging.getLogger(__name__)

NAME = "cocos.decrypt"
ENGINE_ID = "cocos"
LUA_EXTS = (".lua", ".luac")
JSC_EXTS = (".jsc",)


def _read_bytes(ctx: AnalysisContext, path: str, cap: int) -> bytes:
    """Read up to ``cap`` bytes of an archive entry (whole file when smaller)."""
    return common.read_head(ctx, path, cap)


def _script_candidates(ctx: AnalysisContext, idx: FileIndex, sign: bytes,
                       cap: int) -> Tuple[List[FileRec], List[FileRec]]:
    """Split candidate scripts into (lua, jsc). A ``.lua``/``.luac`` counts only if it starts with ``sign``."""
    jsc = idx.not_vendor(idx.with_ext(*JSC_EXTS))
    lua: List[FileRec] = []
    for r in idx.not_vendor(idx.with_ext(*LUA_EXTS)):
        if not sign:
            lua.append(r)
            continue
        if _read_bytes(ctx, r.path, len(sign)) == sign:
            lua.append(r)
    return lua, jsc


def _samples(ctx: AnalysisContext, lua: List[FileRec], jsc: List[FileRec], n: int,
             cap: int) -> List[cdec.Sample]:
    """A handful of each scheme (smallest first, so key trials are cheap) to validate candidate keys against."""
    out: List[cdec.Sample] = []
    for scheme, recs in (("lua", lua), ("jsc", jsc)):
        for r in sorted(recs, key=lambda x: x.size)[: max(1, n // 2)]:
            data = _read_bytes(ctx, r.path, cap)
            if data:
                out.append(cdec.Sample(scheme, data))
    return out[:n]


def _binary_bytes(ctx: AnalysisContext, cap: int) -> Optional[bytes]:
    path = common.main_binary_path(ctx)
    if not path:
        return None
    local = ctx.extract([path]).get(path)
    if local is None:
        return None
    try:
        with open(local, "rb") as fh:
            return fh.read(cap)
    except OSError:
        return None


def _decrypt_all(ctx: AnalysisContext, lua: List[FileRec], jsc: List[FileRec], key: bytes, sign: bytes,
                 cap: int, max_files: int) -> Dict[str, Any]:
    """Decrypt every candidate (up to ``max_files``), writing results under ``<out>/decrypted/``."""
    entries: List[Dict[str, Any]] = []
    ok = failed = 0
    budget = max_files
    for scheme, recs in (("lua", lua), ("jsc", jsc)):
        for r in recs:
            if budget <= 0:
                break
            budget -= 1
            data = _read_bytes(ctx, r.path, cap)
            res = cdec.decrypt_lua(data, key, sign) if scheme == "lua" else cdec.decrypt_jsc(data, key)
            if not res.ok or res.plaintext is None:
                failed += 1
                entries.append({"path": r.rel, "scheme": scheme, "ok": False, "reason": res.reason})
                continue
            rel_out = "decrypted/" + r.rel
            try:
                dest = ctx.artifact_path(rel_out)
                with open(dest, "wb") as fh:
                    fh.write(res.plaintext)
            except (OSError, ValueError) as exc:
                failed += 1
                entries.append({"path": r.rel, "scheme": scheme, "ok": False, "reason": "write failed: %s" % exc})
                continue
            ok += 1
            entries.append({"path": r.rel, "scheme": scheme, "ok": True, "out": rel_out,
                            "bytes": len(res.plaintext), "gunzipped": res.gunzipped})
    return {"decrypted": ok, "failed": failed, "entries": entries}


def _write_manifest(ctx: AnalysisContext, manifest: Dict[str, Any]) -> str:
    rel = "decrypted/manifest.json"
    path = ctx.artifact_path(rel)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=1)
        fh.write("\n")
    ctx.register_artifact(rel, rel)
    return rel


@register(name=NAME, requires=("inventory",), after=("macho", "engine.other"))
class CocosDecryptStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        cc = ctx.cfg.cocos
        if not cc.enabled:
            return StageResult.skipped(NAME, "disabled (enable with --cocos-decrypt)")
        if ctx.source is None:
            return StageResult.skipped(NAME, "no input source is open")

        sign = cc.sign.encode("utf-8") if cc.sign else b""
        idx = FileIndex(ctx)
        lua, jsc = _script_candidates(ctx, idx, sign, cc.max_file_bytes)
        warnings: List[str] = []
        if not lua and not jsc:
            return StageResult.skipped(NAME, "no XXTEA-signed Lua or .jsc scripts found")

        samples = _samples(ctx, lua, jsc, cc.sample_files, cc.max_file_bytes)
        binary = _binary_bytes(ctx, ctx.cfg.limits.max_file_size) if cc.scan_binary_for_key else None
        if cc.scan_binary_for_key and binary is None:
            warnings.append("cocos.decrypt: main binary unavailable; key recovery limited to --xxtea-key")

        provided = [k.encode("utf-8") for k in cc.keys]
        rec = cdec.recover_key(samples, provided_keys=provided, binary=binary, sign=sign,
                               binary_candidate_cap=cc.binary_candidate_cap)
        data: Dict[str, Any] = {
            "enabled": True, "sign": cc.sign,
            "candidates": {"lua": len(lua), "jsc": len(jsc)},
            "key_recovery": rec.to_dict(),
        }

        total = len(lua) + len(jsc)
        if rec.key is None:
            summary = ("Found %d XXTEA-protected Cocos script(s) but no key decrypted them "
                       "(tried %d candidate(s)). Supply one with --xxtea-key, or the binary may be "
                       "FairPlay-encrypted." % (total, rec.tried))
            finding = common.make_finding(
                "engine.cocos.decrypt", Verdict.UNKNOWN, 0.3, ENGINE_ID, "Cocos scripts: key not recovered",
                summary, {"candidates": total, "tried": rec.tried, "decrypted": 0, "failed": 0, "key_source": "none"},
                [Evidence("heuristic", "key_recovery", "no candidate validated a sample")])
            return StageResult.partial(NAME, data=data, findings=[finding], warnings=warnings,
                                       reason="encrypted scripts present but key not recovered")

        result = _decrypt_all(ctx, lua, jsc, rec.key, sign, cc.max_file_bytes, cc.max_files)
        manifest = {"sign": cc.sign, "key_recovery": rec.to_dict(), "summary":
                    {"decrypted": result["decrypted"], "failed": result["failed"],
                     "candidates": {"lua": len(lua), "jsc": len(jsc)}}, "files": result["entries"]}
        manifest_rel = _write_manifest(ctx, manifest)
        data["output"] = {"dir": "decrypted/", "manifest": manifest_rel,
                          "decrypted": result["decrypted"], "failed": result["failed"]}

        summary = ("Recovered the XXTEA key (%s, from %s) and decrypted %d of %d Cocos script(s) to %s."
                   % (rec.key.decode("ascii", "replace"), rec.source, result["decrypted"],
                      len(lua) + len(jsc), "decrypted/"))
        ev = [Evidence("heuristic", "xxtea key", "%s via %s; validated %d sample(s)"
                       % (rec.key.decode("ascii", "replace"), rec.source, rec.validated_samples))]
        ev.extend(common.file_evidence([e["path"] for e in result["entries"] if e["ok"]], "decrypted", 3))
        finding = common.make_finding(
            "engine.cocos.decrypt", Verdict.YES, 0.9, ENGINE_ID, "Cocos scripts decrypted", summary,
            {"decrypted": result["decrypted"], "failed": result["failed"], "candidates": total,
             "tried": rec.tried, "key_source": rec.source}, ev)
        status_warn = warnings
        if result["failed"]:
            status_warn = warnings + ["cocos.decrypt: %d script(s) did not decrypt with the recovered key"
                                      % result["failed"]]
        return StageResult.ok(NAME, data=data, findings=[finding], warnings=status_warn)
