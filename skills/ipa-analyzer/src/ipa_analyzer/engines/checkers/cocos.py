"""Cocos family checker: variant, version hints and script / resource protection (detection only).

Variants (ids follow ``data/engines/*.json``): ``cocos2dx_cpp``, ``cocos2dx_lua``, ``cocos2dx_js``,
``cocos_creator_2x``, ``cocos_creator_3x``, ``cocos2d_iphone``.  The layout rules and the facts behind them are in
``references/cocos-family.md`` (with the sources and the UNVERIFIED items); thresholds and patterns are in
``data/engines_checks.json`` (section ``cocos``).

Judgements:

* scripts: plain ``.lua`` / ``.js`` -> ``no``; Lua bytecode -> ``no`` and labelled "compiled"; Cocos Creator ``.jsc``
  -> ``yes`` (documented as XXTEA ciphertext in ``cocos-engine``); high-entropy / custom-header scripts ->
  ``suspected`` with the XXTEA footprint (shared sign prefix + ciphertext size shape + symbols in the binary).
* resources: ``CCZp`` textures are encrypted by definition (``ZipUtils.cpp``) -> ``yes``; unidentifiable files with
  a structured extension and a shared custom header -> ``suspected``.

Never decrypts, never extracts keys.  On a FairPlay-encrypted main binary the string-based hints are missing and
the report says so.
"""
from __future__ import annotations

import json
import re
import struct
from typing import Any, Dict, List, Optional, Tuple

from ...models import Evidence, Finding, Status, Verdict
from ..api import CheckerResult, DetectResult, register_checker
from ..formats import common, jsc, lua_profile, plist_atlas, xxtea_hint
from ..formats.common import BlobInfo, FileIndex, FileRec, ScriptTally

ENGINE_ID = "cocos"
NAME = "Cocos"
VARIANT_ORDER = ("cocos_creator_3x", "cocos_creator_2x", "cocos2dx_lua", "cocos2dx_js", "cocos2d_iphone",
                 "cocos2dx_cpp")
CCZ_HEADER = struct.Struct(">4sHHII")        # sig, compression_type, version, reserved, len  (cocos2d-x ZipUtils.h)
CCON_MAGIC = b"CCON"


# ---------------------------------------------------------------------------------------------- layout
def _any(idx: FileIndex, rels: List[str]) -> Optional[str]:
    for r in rels:
        if idx.exists(r):
            return r
    return None


def quick_signals(idx: FileIndex, cfg: Dict[str, Any]) -> bool:
    """Cheap, content-free check used by ``applies``: strong Cocos markers only (plist + png alone never count)."""
    if idx.with_magic("ccz") or idx.with_ext(*cfg["strong_resource_exts"]):
        return True
    if idx.exists("application.js") and (idx.has_dir("jsb-adapter") or idx.exists("src/import-map.json")
                                         or idx.exists("src/settings.json")):
        return True
    if _any(idx, ["src/settings.js", "src/settings.jsc"]) and (idx.has_dir("jsb-adapter") or idx.has_dir("res/import")
                                                               or _any(idx, ["src/project.js", "src/project.jsc"])):
        return True
    if _any(idx, ["script/jsb_boot.js", "script/jsb_boot.jsc"]):
        return True
    return any(idx.find(p) for p in cfg["lua_framework_markers"])


def layout_scores(idx: FileIndex, cfg: Dict[str, Any]) -> Tuple[Dict[str, float], Dict[str, List[str]]]:
    """Score every variant from file / directory markers.  Returns ``(scores, signals)``."""
    s: Dict[str, float] = {v: 0.0 for v in VARIANT_ORDER}
    sig: Dict[str, List[str]] = {v: [] for v in VARIANT_ORDER}

    def hit(variant: str, weight: float, what: str) -> None:
        s[variant] += weight
        sig[variant].append(what)

    # Cocos Creator 3.x -- verified on a real sample (SeaWorld) and cocos-engine v3.8 sources.
    if idx.exists("application.js"):
        hit("cocos_creator_3x", 2, "application.js")
    for rel in ("src/import-map.json", "src/system.bundle.js", "src/system.bundle.jsc", "src/settings.json"):
        if idx.exists(rel):
            hit("cocos_creator_3x", 2, rel)
    if idx.has_dir("cocos-js"):
        hit("cocos_creator_3x", 1, "cocos-js/")
    # Creator 2.x (UNVERIFIED layout, see references/cocos-family.md)
    for rel in ("src/settings.js", "src/settings.jsc"):
        if idx.exists(rel):
            hit("cocos_creator_2x", 2, rel)
    for rel in ("src/project.js", "src/project.jsc", "src/project.dev.js"):
        if idx.exists(rel):
            hit("cocos_creator_2x", 2, rel)
    if idx.has_dir("res/import"):
        hit("cocos_creator_2x", 2, "res/import/")
    if idx.has_dir("res/raw-assets"):
        hit("cocos_creator_2x", 1, "res/raw-assets/")
    # shared by Creator 2.x and 3.x
    if idx.has_dir("jsb-adapter"):
        hit("cocos_creator_2x", 1, "jsb-adapter/")
        hit("cocos_creator_3x", 1, "jsb-adapter/")
    for rel in ("main.js", "main.jsc"):
        if idx.exists(rel):
            hit("cocos_creator_2x", 0.5, rel)
            hit("cocos_creator_3x", 0.5, rel)
            break
    bundles = _creator_bundle_dirs(idx)
    if bundles:
        hit("cocos_creator_3x", 1, "assets/<bundle>/{import,native}/ (%d)" % len(bundles))
        hit("cocos_creator_2x", 0.5, "assets/<bundle>/{import,native}/ (%d)" % len(bundles))
    # cocos2d-x Lua (template: src/main.lua, src/config.lua, src/app/, src/64bit/ -- verified from the repo template)
    for rx in cfg["lua_framework_markers"]:
        m = idx.find(rx)
        if m:
            hit("cocos2dx_lua", 3, m[0].rel)
            break
    for rel in ("src/main.lua", "src/main.luac", "main.lua", "main.luac", "src/config.lua", "src/config.luac"):
        if idx.exists(rel):
            hit("cocos2dx_lua", 2, rel)
    if idx.has_dir("src/app") and idx.find(r"^src/app/.*\.luac?$"):
        hit("cocos2dx_lua", 1, "src/app/")
    if idx.has_dir("src/64bit") or idx.has_dir("src/32bit"):
        hit("cocos2dx_lua", 1, "src/64bit|32bit/")
    # cocos2d-x JS bindings (template: script/jsb_boot.js, main.js, project.json with jsList -- from the repo template)
    for rel in ("script/jsb_boot.js", "script/jsb_boot.jsc"):
        if idx.exists(rel):
            hit("cocos2dx_js", 3, rel)
    for rel in ("script/jsb.js", "script/jsb.jsc"):
        if idx.exists(rel):
            hit("cocos2dx_js", 1, rel)
    if idx.exists("project.json") and (idx.exists("main.js") or idx.exists("main.jsc")) and not idx.has_dir("jsb-adapter"):
        hit("cocos2dx_js", 1, "project.json + main.js")
    # cocos2d-iphone / SpriteBuilder (UNVERIFIED names)
    if idx.with_ext(".ccbi"):
        hit("cocos2d_iphone", 2, ".ccbi")
    for d in cfg["iphone_dirs"]:
        if idx.has_dir(d):
            hit("cocos2d_iphone", 2, d)
    # cocos2d-x C++ (resources only)
    ccz = idx.with_magic("ccz") or idx.with_ext(".ccz")
    if ccz:
        hit("cocos2dx_cpp", 3, ".ccz (%d)" % len(ccz))
    for ext in (".csb", ".exportjson", ".tmx"):
        if idx.with_ext(ext):
            hit("cocos2dx_cpp", 1, ext)
    return s, {k: v for k, v in sig.items() if v}


def _creator_bundle_dirs(idx: FileIndex) -> List[str]:
    """``assets/<name>/`` directories that look like Creator asset bundles (``import/`` or ``native/`` inside)."""
    out = set()
    for r in idx.recs:
        parts = r.rel.split("/")
        if len(parts) >= 4 and parts[0] == "assets" and parts[2] in ("import", "native"):
            out.add(parts[1])
    return sorted(out)


def choose_variant(scores: Dict[str, float], detect: DetectResult, cfg: Dict[str, Any]) -> Tuple[Optional[str], float]:
    """Highest score above the threshold; a variant named by ``engine.detect`` breaks ties and lowers the threshold."""
    thr = cfg["variant_min_score"]
    best: Optional[str] = None
    for v in VARIANT_ORDER:
        sc = scores[v] + (1.0 if detect.has(v) else 0.0)
        if sc >= thr and (best is None or sc > scores[best] + (1.0 if detect.has(best) else 0.0)):
            best = v
    if best is None:
        return None, 0.0
    total = scores[best] + (1.0 if detect.has(best) else 0.0)
    return best, round(min(0.95, 0.5 + 0.1 * total), 2)


# ---------------------------------------------------------------------------------------------- helpers
def _is_script_candidate(rec: FileRec, cfg: Dict[str, Any]) -> bool:
    return rec.ext in cfg["script_exts"] or rec.magic == "lua_bytecode"


def _text_blob(ctx: Any, rec: FileRec, limit: int) -> bytes:
    return common.read_head(ctx, rec.path, limit)


def _scan_ccz(ctx: Any, idx: FileIndex, cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Classify ``.ccz`` headers.

    Stock layout (cocos2d-x ``ZipUtils.h`` / ``ZipUtils.cpp``): ``sig[4]`` ("CCZ!" plain / "CCZp" encrypted), u16 BE
    compression type (must be ``CCZ_COMPRESSION_ZLIB`` = 0), u16 BE version (<= 2 plain, <= 0 encrypted), u32 BE
    reserved (checksum for CCZp), u32 BE uncompressed length.  Files whose signature is CCZ but whose fields the stock
    ``inflateCCZBuffer`` would reject are counted as ``deviating`` (a modified format).
    """
    recs = [r for r in idx.recs if r.magic == "ccz" or r.ext == ".ccz"]
    sample, total = common.evenly_sample(recs, cfg["ccz_head_max_files"])
    plain = encrypted = bad = deviating = zlib_ok = 0
    ex_enc: List[str] = []
    ex_plain: List[str] = []
    shapes: Dict[str, int] = {}
    inner: Dict[str, int] = {}
    for r in sample:
        h = common.read_head(ctx, r.path, 24)
        if len(h) < 16 or h[:3] != b"CCZ" or h[3:4] not in (b"!", b"p"):
            bad += 1
            continue
        sig, comp, ver, _reserved, _ulen = CCZ_HEADER.unpack(h[:16])
        stock = comp == 0 and (ver <= 2 if sig[3:4] == b"!" else ver <= 0)
        if not stock:
            deviating += 1
        key = "%s comp=%d ver=%d" % (sig.decode("latin-1"), comp, ver)
        shapes[key] = shapes.get(key, 0) + 1
        tag = h[16:19]
        if len(tag) == 3 and all(65 <= b <= 90 for b in tag):
            inner[tag.decode("ascii")] = inner.get(tag.decode("ascii"), 0) + 1
        if sig[3:4] == b"p":
            encrypted += 1
            if len(ex_enc) < 5:
                ex_enc.append(r.rel)
        else:
            plain += 1
            if len(h) >= 18 and h[16] == 0x78:
                zlib_ok += 1
            if len(ex_plain) < 5:
                ex_plain.append(r.rel)
    scale = total / float(max(len(sample), 1))
    return {"total": total, "sampled": len(sample), "plain": plain, "encrypted": encrypted, "unreadable_or_bad": bad,
            "deviating_from_stock": deviating, "encrypted_estimate": int(round(encrypted * scale)),
            "plain_zlib_header_ok": zlib_ok, "header_shapes": dict(sorted(shapes.items())),
            "inner_tags_at_16": dict(sorted(inner.items())), "samples": {"encrypted": ex_enc, "plain": ex_plain}}


def _scan_plists(ctx: Any, idx: FileIndex, cfg: Dict[str, Any]) -> Dict[str, Any]:
    recs = [r for r in idx.not_vendor(idx.with_ext(".plist")) if 0 < r.size <= cfg["plist_max_bytes"]]
    sample, total = common.evenly_sample(recs, cfg["plist_sample_max"])
    kinds: Dict[str, int] = {}
    for r in sample:
        data = common.read_head(ctx, r.path, cfg["plist_max_bytes"])
        if not (data[:8] == b"bplist00" or data.lstrip()[:5] in (b"<?xml", b"<plis")):
            kinds["not_plist"] = kinds.get("not_plist", 0) + 1
            continue
        kind, _ = plist_atlas.classify_plist_bytes(data)
        kinds[kind] = kinds.get(kind, 0) + 1
    return {"total": total, "sampled": len(sample), "kinds": dict(sorted(kinds.items()))}


def _count_ext(idx: FileIndex, exts: List[str]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for e in exts:
        n = len(idx.with_ext(e))
        if n:
            out[e] = n
    return out


def _ccon_stats(ctx: Any, idx: FileIndex, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    recs = [r for r in idx.not_vendor(idx.with_ext(".bin", ".cconb")) if r.size >= 12]
    if not recs:
        return None
    sample, total = common.evenly_sample(recs, cfg["resource_sample_max"])
    valid = bad = 0
    for r in sample:
        h = common.read_head(ctx, r.path, 12)
        if h[:4] == CCON_MAGIC:
            ver, length = struct.unpack_from("<II", h, 4)
            if ver in (1, 2) and length == r.size:       # decodeCCONBinary: total length must equal the byte length
                valid += 1
            else:
                bad += 1
    return {"files": total, "sampled": len(sample), "valid_ccon": valid, "ccon_header_but_length_mismatch": bad}


def _bundle_info(ctx: Any, idx: FileIndex, cfg: Dict[str, Any], names: List[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for name in names[:cfg["bundle_list_max"]]:
        base = "assets/%s/" % name
        recs = [r for r in idx.recs if r.rel.startswith(base)]
        item: Dict[str, Any] = {
            "name": name, "path": base, "import_files": sum(1 for r in recs if r.rel.startswith(base + "import/")),
            "native_files": sum(1 for r in recs if r.rel.startswith(base + "native/")),
        }
        cfgs = [r for r in recs if re.match(r"(cc\.)?config(\.[0-9a-f]+)?\.json$", r.rel[len(base):])]
        scripts = [r for r in recs if re.match(r"(index|game)(\.[0-9a-f]+)?\.(js|jsc)$", r.rel[len(base):])]
        if cfgs:
            c = cfgs[0]
            item["config"] = c.rel[len(base):]
            h = common.read_head(ctx, c.path, cfg["bundle_config_max_bytes"])
            if h and c.size <= cfg["bundle_config_max_bytes"]:
                try:
                    doc = json.loads(h.decode("utf-8"))
                    if isinstance(doc, dict):
                        item["config_summary"] = {"name": doc.get("name"), "deps": len(doc.get("deps") or []),
                                                  "uuids": len(doc.get("uuids") or []),
                                                  "scenes": len(doc.get("scenes") or {}),
                                                  "packs": len(doc.get("packs") or {})}
                except (ValueError, UnicodeDecodeError):
                    item["config_not_plain_json"] = True
        if scripts:
            item["script"] = scripts[0].rel[len(base):]
        out.append(item)
    return out


_HASH_NAME = re.compile(r"(?:^|/)(?:[^/]+\.[0-9a-f]{5,8}\.(?:json|png|jpg|bin|js|jsc|astc|pvr|mp3|ogg|ttf)|config\.[0-9a-f]{5,8}\.json)$")


def _version_hints(ctx: Any, idx: FileIndex, binary: common.BinaryScan, cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for text in binary.hits.get("cocos2dx_version", []):
        m = re.search(r"cocos2d-x-?\s?(\d+\.\d+(?:\.\d+)?)", text)
        if m:
            out.append({"source": "main_binary_string", "value": m.group(1), "ref": text[:60]})
    # Creator 3.x settings.json: top-level "CocosEngine" (UNVERIFIED key name; only read when the file is plain text)
    rec = idx.get("src/settings.json")
    if rec is not None and rec.size <= cfg["settings_json_max_bytes"]:
        head = common.read_head(ctx, rec.path, rec.size)
        m = re.search(rb'"CocosEngine"\s*:\s*"([^"]{1,32})"', head)
        if m:
            out.append({"source": "src/settings.json", "value": m.group(1).decode("ascii", "replace"),
                        "ref": "CocosEngine"})
    for rel in cfg["creator2_engine_js"]:
        rec = idx.get(rel)
        if rec is None or rec.size > cfg["engine_js_max_bytes"]:
            continue
        data = common.read_head(ctx, rec.path, rec.size)
        v = _creator_js_version(data)
        if v:
            out.append({"source": rel, "value": v, "ref": "ENGINE_VERSION"})
            break
    return out


def _creator_js_version(data: bytes) -> Optional[str]:
    """``cc.ENGINE_VERSION = "x.y.z"`` or ``... = engineVersion`` with ``engineVersion = "x.y.z"`` (UNVERIFIED if minified)."""
    m = re.search(rb"ENGINE_VERSION\s*=\s*[\"']([0-9][^\"']{0,30})[\"']", data)
    if m:
        return m.group(1).decode("ascii", "replace")
    m = re.search(rb"ENGINE_VERSION\s*=\s*([A-Za-z_$][\w$]*)", data)
    if m:
        name = re.escape(m.group(1).decode("ascii"))
        m2 = re.search((r"(?:var|let|const)?\s*\b%s\s*=\s*[\"'](\d+\.\d+\.\d+[^\"']{0,20})[\"']" % name).encode("ascii"), data)
        if m2:
            return m2.group(1).decode("ascii", "replace")
    return None


# ----------------------------------------------------------------------------------------------- checker
@register_checker("cocos")
class CocosChecker:
    engine_id = "cocos"

    def applies(self, ctx: Any, detect: DetectResult) -> bool:
        cfg = common.checks("cocos")
        if any(i.startswith("cocos") or i == "modified_cocos" for i in detect.candidate_ids()) or \
                (detect.primary_id or "").startswith("cocos"):
            return True
        return quick_signals(FileIndex(ctx), cfg)

    def run(self, ctx: Any, detect: DetectResult) -> CheckerResult:
        cfg = common.checks("cocos")
        idx = FileIndex(ctx)
        warnings: List[str] = []
        scores, signals = layout_scores(idx, cfg)
        variant, vconf = choose_variant(scores, detect, cfg)
        detect_ids = [i for i in detect.candidate_ids() if i.startswith("cocos") or i == "modified_cocos"]

        # --- scripts -------------------------------------------------------------------------------
        cands = idx.not_vendor([r for r in idx.recs if _is_script_candidate(r, cfg)])
        s_sample, s_total = common.evenly_sample(cands, cfg["script_sample_max"])
        tally = ScriptTally()
        lua = lua_profile.LuaProfiler()
        heads_susp: List[bytes] = []
        sizes_susp: List[int] = []
        jsc_notes: Dict[str, int] = {}
        plain_lua_text = 0
        for r in s_sample:
            blob, head = common.classify_file(ctx, r)
            if r.ext == ".jsc" and blob.kind in (common.K_HIGH_ENTROPY, common.K_BINARY, common.K_CUSTOM_HEADER):
                info = jsc.classify_jsc(head, r.size, common.entropy_is_high(blob.entropy, len(head)))
                interp = jsc.interpret(variant or "", info)
                jsc_notes[interp] = jsc_notes.get(interp, 0) + 1
                blob = BlobInfo(common.K_HIGH_ENTROPY, {"jsc": interp}, blob.entropy)
            tally.add(r.rel, r.ext, blob)
            if blob.bucket == "suspected_encrypted":
                heads_susp.append(head)
                sizes_susp.append(r.size)
            if r.ext in cfg["lua_exts"] or blob.kind in (common.K_LUA_BC, common.K_LUA_BC_TAMPERED, common.K_LUA_XOR):
                text = None
                if blob.kind == common.K_PLAIN and plain_lua_text < cfg["lua_dialect_files"]:
                    text = common.read_head(ctx, r.path, cfg["lua_dialect_bytes"])
                    plain_lua_text += 1
                lua.add(blob, text)
        scripts = tally.to_dict(sampled=len(s_sample), of=s_total)

        # --- resources -------------------------------------------------------------------------------
        ccz = _scan_ccz(ctx, idx, cfg) if (idx.with_magic("ccz") or idx.with_ext(".ccz")) else None
        plists = _scan_plists(ctx, idx, cfg)
        clusters = common.find_wrapper_clusters(ctx, idx.not_vendor(idx.recs))
        ccon = _ccon_stats(ctx, idx, cfg) if variant and variant.startswith("cocos_creator") else None
        hashed = sum(1 for r in idx.recs if _HASH_NAME.search(r.rel))
        res_files = idx.not_vendor([r for r in idx.recs if r.ext in cfg["resource_exts"]])
        r_sample, r_total = common.evenly_sample(res_files, cfg["resource_sample_max"])
        rtally = ScriptTally()
        for r in r_sample:
            rtally.add(r.rel, r.ext, common.classify_resource(ctx, r))
        ccbi = idx.with_ext(".ccbi")
        resources: Dict[str, Any] = {
            "ccbi": {"files": len(ccbi), "ibcc_header": sum(1 for r in ccbi[:cfg["resource_sample_max"]]
                                                           if common.read_head(ctx, r.path, 4) == b"ibcc")} if ccbi else None,
            "ccz": ccz, "plists": plists, "counts": _count_ext(idx, cfg["resource_count_exts"]),
            "wrapper_clusters": clusters, "ccon": ccon, "md5_hashed_names": hashed,
            "classified": rtally.to_dict(sampled=len(r_sample), of=r_total),
        }

        # --- binary hints (degrade on FairPlay) ----------------------------------------------------------
        patterns = dict(cfg["binary_patterns"])
        patterns.update(lua_profile.RUNTIME_PATTERNS)
        binary = common.scan_main_binary(ctx, patterns)
        if binary.status in ("skipped_encrypted", "error", "unavailable"):
            warnings.append("cocos: binary-based hints limited (%s: %s)" % (binary.status, binary.reason))
        lua_runtime = lua_profile.runtime_from_hits(binary.hits)
        hint = xxtea_hint.script_hint(heads_susp, sizes_susp, cfg["xxtea"]) if heads_susp else \
            {"sign_prefix": None, "size_structure": {"files": 0}, "xxtea_shape": False, "consistent_sign_and_shape": False}
        deviations = xxtea_hint.deviations(hint, binary.hits)
        if binary.has("cocos_cpp") and variant is None:
            deviations.append("cocos_symbols_but_no_recognised_layout")
        res_deviations: List[str] = []
        if ccz and ccz["deviating_from_stock"]:
            res_deviations.append("ccz_header_deviates_from_stock")
        if clusters:
            res_deviations.append("custom_wrapper_header_on_resources")
        if clusters and tally.count("suspected_encrypted"):
            deviations.append("custom_wrapper_header_on_scripts")
        if variant is None and detect_ids:
            deviations.append("detect_says_cocos_but_layout_unrecognised")

        versions = _version_hints(ctx, idx, binary, cfg)
        # mixed projects (Cocos + own Lua framework / channel shell): report the distribution, never fail
        lua_profile_d = lua.to_dict(lua_runtime) if lua.total else None
        bundle_names = _creator_bundle_dirs(idx) if variant and variant.startswith("cocos_creator") else []
        bundles = _bundle_info(ctx, idx, cfg, bundle_names) if bundle_names else []

        data: Dict[str, Any] = {
            "variant": variant or "unknown", "variant_confidence": vconf, "variant_scores": scores,
            "variant_signals": signals, "detect_candidates": detect_ids,
            "version_hint": versions[0]["value"] if versions else None, "version_sources": versions,
            "scripts": dict(scripts, lua=lua_profile_d, jsc_interpretation=jsc_notes),
            "resources": resources, "xxtea_hint": dict(hint, binary=binary.to_dict(), deviations=deviations),
            "resource_deviations": res_deviations,
            "bundles": bundles, "bundle_total": len(bundle_names),
        }

        findings = self._findings(ctx, variant, vconf, versions, signals, scripts, tally, jsc_notes, hint, binary,
                                  deviations, resources, clusters, s_total, rtally, r_total, detect_ids)
        return CheckerResult(findings=findings, data=data, status=Status.OK, warnings=warnings)

    # ------------------------------------------------------------------------------------------------
    def _findings(self, ctx, variant, vconf, versions, signals, scripts, tally, jsc_notes, hint, binary, deviations,
                  resources, clusters, s_total, rtally, r_total, detect_ids) -> List[Finding]:
        out: List[Finding] = []
        # variant
        ver = versions[0]["value"] if versions else ""
        if variant:
            ev = [Evidence("file", s, "variant marker") for s in signals.get(variant, [])[:5]]
            for v in versions[:2]:
                ev.append(Evidence("string" if "binary" in v["source"] else "file", v["source"], "version %s" % v["value"]))
            out.append(common.make_finding(
                "engine.cocos.variant", Verdict.YES if vconf >= 0.7 else Verdict.SUSPECTED, vconf, ENGINE_ID,
                "Cocos variant: %s" % variant,
                "Cocos family variant %s%s, from file layout markers." % (variant, " (version hint %s)" % ver if ver else ""),
                {"variant": variant, "version": ver or "unknown", "engine": NAME}, ev))
        else:
            out.append(common.make_finding(
                "engine.cocos.variant", Verdict.UNKNOWN, 0.2, ENGINE_ID, "Cocos variant not determined",
                "Cocos signals were reported but the file layout does not match any known variant.",
                {"variant": "unknown", "version": ver or "unknown", "engine": NAME},
                [Evidence("heuristic", "engine.detect", "candidates: %s" % ", ".join(detect_ids))] if detect_ids else []))

        # scripts
        verdict, conf, state = common.verdict_from_tally(tally, s_total)
        jsc_documented = jsc_notes.get("creator_xxtea_documented", 0)
        note = ""
        ev: List[Evidence] = []
        if jsc_documented and jsc_documented == tally.count("suspected_encrypted"):
            verdict, conf, state = Verdict.YES, 0.85, "suspected"
            note = ("Cocos Creator .jsc files are XXTEA-encrypted by design (engine source: not bytecode); %d such "
                    "file(s) found." % jsc_documented)
            ev.append(Evidence("heuristic", ".jsc", "documented XXTEA format of Creator .jsc"))
        if jsc_notes.get("spidermonkey_bytecode_or_cipher"):
            note += (" %d .jsc file(s) of a cocos2d-x JS project: SpiderMonkey bytecode or ciphertext (not distinguishable "
                     "by content; bytecode alone would not be encryption)." % jsc_notes["spidermonkey_bytecode_or_cipher"])
        if verdict == Verdict.SUSPECTED and hint.get("consistent_sign_and_shape"):
            conf = max(conf, 0.85)
            sp = hint["sign_prefix"]
            note += " Shared leading bytes %s%s in %d of the high-entropy scripts and ciphertext-shaped sizes (multiple of 4)." % (
                sp["hex"], " (%r)" % sp["ascii"] if sp["ascii"] else "", sp["files"])
            ev.append(Evidence("heuristic", "script sign prefix", "length %d, support %.2f; XXTEA size shape" % (
                sp["length"], sp["support"])))
        for sym in ("xxtea_api", "xxtea_key_setter"):
            for t in binary.hits.get(sym, [])[:2]:
                ev.append(Evidence("symbol" if sym == "xxtea_api" else "string", t, "XXTEA hint in the main binary"))
        if binary.status != "scanned":
            note += " Binary-based hints: %s." % (binary.reason or binary.status)
        if deviations:
            note += " Deviations from stock Cocos XXTEA usage: %s." % ", ".join(deviations)
            ev.extend(Evidence("heuristic", d, "deviation") for d in deviations[:3])
        for k in ("suspected_encrypted", "bytecode", "plain"):
            kinds = [kk for kk in tally.kinds if common.BUCKET.get(kk) == k]
            for kk in kinds[:1]:
                ev.extend(common.file_evidence(tally.samples.get(kk, []), "%s (%s)" % (kk, k), 2))
        if tally.total == 0:
            note += " No script files in the archive (typical for a C++ project or scripts downloaded at run time)."
        out.append(common.script_finding(
            ENGINE_ID, NAME, scripts, verdict, conf, state, ev, note.strip(),
            "Encrypted scripts need the key from the app; this tool only reports the protection." if verdict in (
                Verdict.YES, Verdict.SUSPECTED) else ""))

        # resources
        ccz = resources.get("ccz")
        enc = (ccz or {}).get("encrypted_estimate", 0)
        rev: List[Evidence] = []
        r_note = ""
        wrapped = sum(c["files"] for c in clusters)
        r_verdict, r_conf, r_state = common.verdict_from_tally(rtally, r_total)
        if ccz and ccz["encrypted"]:
            r_verdict, r_conf, r_state = Verdict.YES, 0.97, "encrypted"
            rev.extend(common.file_evidence(ccz["samples"]["encrypted"], "CCZp (encrypted ccz, cocos2d-x ZipUtils)", 3))
            r_note = ("%d of %d .ccz files carry the encrypted CCZp signature (cocos2d-x ZipUtils); the key is supplied by "
                      "the app (setPvrEncryptionKey) and is not extracted." % (ccz["encrypted_estimate"], ccz["total"]))
            if ccz["deviating_from_stock"]:
                r_conf = 0.92
                shapes = "; ".join("%s x%d" % kv for kv in list(ccz["header_shapes"].items())[:3])
                r_note += (" %d of them have header fields that stock cocos2d-x would reject (header shapes: %s): a "
                           "modified CCZ format." % (ccz["deviating_from_stock"], shapes))
                rev.append(Evidence("heuristic", "ccz header shapes", shapes))
        elif ccz and ccz["plain"] and not clusters:
            if r_verdict in (Verdict.NA, Verdict.UNKNOWN):
                r_verdict, r_conf, r_state = Verdict.NO, 0.8, "plain"
            rev.extend(common.file_evidence(ccz["samples"]["plain"], "CCZ! (plain ccz)", 2))
            r_note = "All %d examined .ccz textures use the plain CCZ! form (zlib), not CCZp." % ccz["sampled"]
        if clusters:
            c0 = clusters[0]
            if r_verdict in (Verdict.NA, Verdict.NO, Verdict.UNKNOWN):
                r_verdict, r_conf, r_state = Verdict.SUSPECTED, 0.7, "suspected"
            r_note += (" %d file(s) with a standard extension carry a custom header '%s' instead of the standard format "
                       "(probable custom encryption or obfuscation; vendor not asserted)." % (wrapped, c0["tag"]))
            rev.append(Evidence("heuristic", "custom header %s" % c0["tag"], "%d files, exts %s" % (c0["files"], c0["exts"])))
            rev.extend(common.file_evidence(c0["examples"], "custom header", 2))
        elif r_verdict == Verdict.NO:
            r_conf = min(r_conf, 0.6)
        rd = dict(resources["classified"])
        rd["suspected_encrypted"] = max(rd.get("suspected_encrypted", 0), wrapped)
        rd["total"] = rd["total"] + (ccz["total"] if ccz else 0)
        out.append(common.resource_finding(
            ENGINE_ID, NAME, rd, r_verdict, r_conf, r_state, rev, r_note.strip(), encrypted=enc,
            remediation="Resource keys live in the app; this tool only reports the protection."
            if r_verdict in (Verdict.YES, Verdict.SUSPECTED) else ""))
        return out
