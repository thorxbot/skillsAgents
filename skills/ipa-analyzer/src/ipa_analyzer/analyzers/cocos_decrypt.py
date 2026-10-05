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
from ..crypto import ccz as cccz
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
CCZ_EXTS = (".ccz",)


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


def _ccz_candidates(idx: FileIndex) -> List[FileRec]:
    """Encrypted-or-plain ``.ccz`` textures (by magic or extension)."""
    seen: Dict[str, FileRec] = {}
    for r in idx.with_magic("ccz") + idx.with_ext(*CCZ_EXTS):
        seen.setdefault(r.rel, r)
    return list(seen.values())


def _decrypt_textures(ctx: AnalysisContext, recs: List[FileRec], parts, cap: int,
                      max_files: int) -> Dict[str, Any]:
    """Decrypt ``CCZp`` textures (and inflate plain ``CCZ!``) to ``<out>/decrypted/`` as ``<rel>.bin``."""
    entries: List[Dict[str, Any]] = []
    ok = failed = 0
    budget = max_files
    for r in recs:
        if budget <= 0:
            break
        budget -= 1
        raw = cccz.decrypt_ccz(_read_bytes(ctx, r.path, cap), parts)
        if raw is None:
            failed += 1
            entries.append({"path": r.rel, "scheme": "ccz", "ok": False, "reason": "wrong key or not CCZ/CCZp"})
            continue
        rel_out = "decrypted/" + r.rel + ".bin"
        try:
            dest = ctx.artifact_path(rel_out)
            with open(dest, "wb") as fh:
                fh.write(raw)
        except (OSError, ValueError) as exc:
            failed += 1
            entries.append({"path": r.rel, "scheme": "ccz", "ok": False, "reason": "write failed: %s" % exc})
            continue
        ok += 1
        entries.append({"path": r.rel, "scheme": "ccz", "ok": True, "out": rel_out, "bytes": len(raw)})
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
        ccz = _ccz_candidates(idx) if cc.pvr_key else []
        warnings: List[str] = []
        if not lua and not jsc and not ccz:
            if _ccz_candidates(idx):
                return StageResult.skipped(NAME, "found .ccz textures but no --pvr-key; no scripts to decrypt")
            return StageResult.skipped(NAME, "no XXTEA-signed Lua / .jsc scripts or .ccz textures to decrypt")

        total_scripts = len(lua) + len(jsc)
        data: Dict[str, Any] = {
            "enabled": True, "sign": cc.sign,
            "candidates": {"lua": len(lua), "jsc": len(jsc), "ccz": len(ccz)},
            "key_recovery": None,
        }
        findings = []
        script_result: Dict[str, Any] = {"decrypted": 0, "failed": 0, "entries": []}
        rec = None

        # --- scripts (XXTEA, key recovered or supplied) ----------------------------------------------
        if lua or jsc:
            samples = _samples(ctx, lua, jsc, cc.sample_files, cc.max_file_bytes)
            binary = _binary_bytes(ctx, ctx.cfg.limits.max_file_size) if cc.scan_binary_for_key else None
            if cc.scan_binary_for_key and binary is None:
                warnings.append("cocos.decrypt: main binary unavailable; key recovery limited to --xxtea-key")
            provided = [k.encode("utf-8") for k in cc.keys]
            rec = cdec.recover_key(samples, provided_keys=provided, binary=binary, sign=sign,
                                   binary_candidate_cap=cc.binary_candidate_cap)
            data["key_recovery"] = rec.to_dict()
            if rec.key is not None:
                script_result = _decrypt_all(ctx, lua, jsc, rec.key, sign, cc.max_file_bytes, cc.max_files)
                ev = [Evidence("heuristic", "xxtea key", "%s via %s; validated %d sample(s)"
                               % (rec.key.decode("ascii", "replace"), rec.source, rec.validated_samples))]
                ev.extend(common.file_evidence([e["path"] for e in script_result["entries"] if e["ok"]], "decrypted", 3))
                findings.append(common.make_finding(
                    "engine.cocos.decrypt", Verdict.YES, 0.9, ENGINE_ID, "Cocos scripts decrypted",
                    "Recovered the XXTEA key (%s, from %s) and decrypted %d of %d Cocos script(s) to decrypted/."
                    % (rec.key.decode("ascii", "replace"), rec.source, script_result["decrypted"], total_scripts),
                    {"decrypted": script_result["decrypted"], "failed": script_result["failed"],
                     "candidates": total_scripts, "tried": rec.tried, "key_source": rec.source}, ev))
                if script_result["failed"]:
                    warnings.append("cocos.decrypt: %d script(s) did not decrypt with the recovered key"
                                    % script_result["failed"])
            else:
                findings.append(common.make_finding(
                    "engine.cocos.decrypt", Verdict.UNKNOWN, 0.3, ENGINE_ID, "Cocos scripts: key not recovered",
                    "Found %d XXTEA-protected Cocos script(s) but no key decrypted them (tried %d candidate(s)). "
                    "Supply one with --xxtea-key, or the binary may be FairPlay-encrypted." % (total_scripts, rec.tried),
                    {"candidates": total_scripts, "tried": rec.tried, "decrypted": 0, "failed": 0, "key_source": "none"},
                    [Evidence("heuristic", "key_recovery", "no candidate validated a sample")]))

        # --- textures (CCZp/PVR, operator-supplied 4-part key) ---------------------------------------
        texture_result: Dict[str, Any] = {"decrypted": 0, "failed": 0, "entries": []}
        if ccz:
            try:
                parts = cccz.parse_key(cc.pvr_key)
            except ValueError as exc:
                warnings.append("cocos.decrypt: invalid --pvr-key: %s" % exc)
                parts = None
            if parts is not None:
                texture_result = _decrypt_textures(ctx, ccz, parts, cc.max_file_bytes, cc.max_files)
                data["pvr_key"] = {"ascii_hex": "".join("%08x" % p for p in parts)}
                ev = common.file_evidence([e["path"] for e in texture_result["entries"] if e["ok"]], "decrypted ccz", 3)
                findings.append(common.make_finding(
                    "engine.cocos.decrypt", Verdict.YES if texture_result["decrypted"] else Verdict.UNKNOWN,
                    0.9 if texture_result["decrypted"] else 0.3, ENGINE_ID, "Cocos CCZp textures decrypted",
                    "Decrypted %d of %d .ccz texture(s) with the supplied PVR key to decrypted/."
                    % (texture_result["decrypted"], len(ccz)),
                    {"decrypted": texture_result["decrypted"], "failed": texture_result["failed"],
                     "candidates": len(ccz), "tried": 1, "key_source": "pvr_key"}, ev))
                if texture_result["failed"]:
                    warnings.append("cocos.decrypt: %d texture(s) did not decrypt with the --pvr-key"
                                    % texture_result["failed"])

        entries = script_result["entries"] + texture_result["entries"]
        dec_total = script_result["decrypted"] + texture_result["decrypted"]
        fail_total = script_result["failed"] + texture_result["failed"]
        manifest = {"sign": cc.sign, "key_recovery": (rec.to_dict() if rec is not None else None),
                    "pvr_key_used": bool(ccz and data.get("pvr_key")),
                    "summary": {"decrypted": dec_total, "failed": fail_total,
                                "candidates": {"lua": len(lua), "jsc": len(jsc), "ccz": len(ccz)}},
                    "files": entries}
        manifest_rel = _write_manifest(ctx, manifest)
        data["output"] = {"dir": "decrypted/", "manifest": manifest_rel, "decrypted": dec_total, "failed": fail_total}

        if dec_total == 0 and (rec is None or rec.key is None) and not texture_result["decrypted"]:
            return StageResult.partial(NAME, data=data, findings=findings, warnings=warnings,
                                       reason="encrypted content present but nothing decrypted (missing/invalid key)")
        return StageResult.ok(NAME, data=data, findings=findings, warnings=warnings)
