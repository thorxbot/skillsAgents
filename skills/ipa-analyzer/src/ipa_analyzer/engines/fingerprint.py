"""Engine-independent capability profile (``engine.fingerprint``, WP7).

Rules live in ``data/fingerprint.json`` (same signal grammar as the engine signatures, see
``engines/signatures.py``). On top of the rule matches this module adds checks that need more than a
pattern: Lua bytecode flavours, embedded-Python ``.pyc`` header validity, container analysis
(``engines/containers.py``), header clusters of custom-packed files and the host-shape summary.

Everything that depends on Mach-O contents degrades when the code is FairPlay encrypted: the profile
then relies on linked libraries, imported symbols, files and directories, and says so in ``extra``.
"""
from __future__ import annotations

import json
import logging
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..models import Evidence
from ..util.paths import resource_dir
from .api import EngineSignature, FingerprintHit, FingerprintResult, SignalSpec
from .containers import (STRUCTURED_EXTS, ContainerAnalysis, HeaderCluster, analyze_container, cluster_from_summary,
                         cluster_headers, select_candidates)
from .scoring import EvidenceBundle, match_signal, score_signature, signals_matched, to_evidence
from .signatures import _normalise, validate_signature_dict

log = logging.getLogger(__name__)

DIMENSIONS = ("render", "shader_formats", "script_vms", "physics", "audio", "animation", "network",
              "asset_formats")
CONTAINER_TIME_BUDGET_S = 60.0
LUA_HEAD_PROBES = 12
PYC_PROBES = 24
CPP_RATIO_MIN_SYMBOLS = 200       # defined symbols needed before a symbol ratio means anything (stripped builds have few)
THIN_SHELL_MAX_CLASSES = 12       # heuristic: a UIKit launcher shell defines only a handful of classes
CPP_HEAVY_RATIO = 0.4             # heuristic threshold used by engines/custom.py as well

# CPython .pyc: bytes 0-1 = magic number (little endian), bytes 2-3 = b"\r\n" (importlib._bootstrap_external).
# Plausible ranges (UNVERIFIED from memory of the version table): 3.x numbers are 3000..3999, 2.x about 62000..62300.
_PYC_RANGES = ((3000, 3999), (62000, 62300))


# --- rules ---------------------------------------------------------------------------------------------------
class FingerprintRules:
    def __init__(self) -> None:
        self.dimensions: Dict[str, List[EngineSignature]] = {d: [] for d in DIMENSIONS}
        self.main_loop: List[Dict[str, Any]] = []
        self.warnings: List[str] = []


def load_rules(data_dir: Optional[Path] = None) -> FingerprintRules:
    rules = FingerprintRules()
    path = (Path(data_dir) if data_dir is not None else resource_dir("data")) / "fingerprint.json"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        rules.warnings.append("fingerprint rules unavailable (%s)" % exc)
        return rules
    for dim in DIMENSIONS:
        for raw in (doc.get("dimensions") or {}).get(dim, []):
            d = dict(raw)
            d.setdefault("kind", "open_source_lib")
            d["confirm_threshold"] = d.get("confirm_threshold", 0.5)
            errs = validate_signature_dict(d)
            if errs:
                rules.warnings.append("fingerprint rule %s/%s ignored: %s" % (dim, raw.get("id"), "; ".join(errs[:2])))
                continue
            rules.dimensions[dim].append(_normalise(d)[0])
    for h in doc.get("main_loop_hints") or []:
        if isinstance(h, dict) and h.get("id") and h.get("type") and h.get("pattern"):
            rules.main_loop.append(h)
    return rules


# --- helpers ---------------------------------------------------------------------------------------------------
def _hit_from_score(bundle: EvidenceBundle, sig: EngineSignature) -> Optional[FingerprintHit]:
    sc = score_signature(bundle, sig)
    if not sc.confirmed:
        return None
    return FingerprintHit(id=sig.id, name=sig.name, confidence=sc.confidence, evidence=to_evidence(sc.matches),
                          extra={"signals": signals_matched(sc.matches), "threshold": sig.confirm_threshold})


def _merge_hit(hits: List[FingerprintHit], hit: FingerprintHit) -> None:
    for h in hits:
        if h.id == hit.id:
            h.confidence = min(0.99, max(h.confidence, hit.confidence) + 0.1)
            h.evidence.extend(hit.evidence)
            h.extra.update(hit.extra)
            return
    hits.append(hit)


def _read_heads(ctx: Any, paths: Sequence[str], n: int) -> List[Tuple[str, bytes]]:
    out: List[Tuple[str, bytes]] = []
    for p in paths:
        try:
            out.append((p, ctx.source.read_head(p, n)))
        except (KeyError, OSError, ValueError):
            continue
    return out


def lua_bytecode_profile(heads: Sequence[Tuple[str, bytes]]) -> Dict[str, Any]:
    """Classify Lua bytecode headers: PUC (ESC 'Lua' + version byte 0x51..0x54) vs LuaJIT (ESC 'LJ').

    Source: lundump.h / lj_bcdump.h signatures (see formats/lua_bytecode.py, WP3b); version byte is the
    BCD-style ``major*16+minor`` of the PUC header.
    """
    puc: Counter = Counter()
    jit = 0
    for _p, h in heads:
        if h[:4] == b"\x1bLua" and len(h) >= 5:
            puc["%d.%d" % (h[4] >> 4, h[4] & 15)] += 1
        elif h[:3] == b"\x1bLJ":
            jit += 1
    return {"puc": dict(sorted(puc.items())), "luajit": jit}


def pyc_profile(heads: Sequence[Tuple[str, bytes]]) -> Dict[str, Any]:
    """Check CPython bytecode headers (``u16 magic`` + ``\\r\\n``) of ``.pyc``-like files."""
    valid = bad_header = bad_number = 0
    numbers: Counter = Counter()
    examples: List[str] = []
    for p, h in heads:
        if len(h) < 4:
            continue
        num = h[0] | (h[1] << 8)
        numbers[num] += 1
        if h[2:4] != b"\r\n":
            bad_header += 1
            if len(examples) < 3:
                examples.append(p)
        elif not any(lo <= num <= hi for lo, hi in _PYC_RANGES):
            bad_number += 1
            if len(examples) < 3:
                examples.append(p)
        else:
            valid += 1
    return {"checked": valid + bad_header + bad_number, "valid": valid, "nonstandard_header": bad_header,
            "nonstandard_number": bad_number, "magic_numbers": dict(sorted(numbers.items())),
            "examples": examples,
            "opcode_scramble_suspected": bool(bad_header or bad_number)}


# --- containers ------------------------------------------------------------------------------------------------
def analyze_containers(ctx: Any, bundle: EvidenceBundle, *, limit: int,
                       warnings: List[str]) -> Tuple[List[FingerprintHit], Dict[str, Any]]:
    """Deep-analyse large unknown files and cluster custom-headed small files."""
    siblings = [f.path for f in bundle.files]
    src = ctx.source
    # 1. families of small custom-headed files (represented as one entry per header)
    clusters: List[HeaderCluster] = []
    mismatch: Counter = Counter()
    by_path = {f.path: f for f in bundle.files}
    heads: Dict[str, bytes] = {}
    entries: List[Tuple[str, int, str, bytes]] = []
    if bundle.inv_header_clusters is not None and src is not None:
        # the inventory already grouped unknown-magic files with structured extensions by their first 4 bytes
        for c in bundle.inv_header_clusters:
            try:
                head4 = bytes.fromhex(str(c.get("head_hex", "")))
            except ValueError:
                continue
            rows = [(p, by_path[p].size, by_path[p].ext) for p in c.get("examples", []) if p in by_path]
            try:
                cl = cluster_from_summary(head4, int(c.get("count") or 0), int(c.get("size") or 0),
                                          {str(k): int(v) for k, v in (c.get("exts") or {}).items()}, rows, src.read_head)
            except Exception as exc:  # noqa: BLE001
                warnings.append("header cluster skipped: %s" % exc)
                continue
            if cl is not None:
                clusters.append(cl)
                for e, n in cl.ext_mismatch.items():
                    mismatch[e] += n
        clusters = clusters[:8]
        unknown_total = sum(1 for f in bundle.files if f.magic == "unknown")
    else:
        try:
            heads = bundle.heads()
        except Exception as exc:  # noqa: BLE001 - never fail the stage for header sampling
            heads = {}
            warnings.append("header sampling failed: %s" % exc)
        for p, h in heads.items():
            f = by_path.get(p)
            if f is None or f.magic != "unknown" or len(h) < 4 or h[:4] == b"\x00\x00\x00\x00":
                continue
            entries.append((p, f.size, f.ext, h))
            if f.ext in STRUCTURED_EXTS:
                mismatch[f.ext] += 1
        if entries and src is not None:
            try:
                clusters = cluster_headers(entries, src.read_head)
            except Exception as exc:  # noqa: BLE001
                warnings.append("header clustering failed: %s" % exc)
        unknown_total = len(entries)
    keys = {bytes.fromhex(cl.header_hex) for cl in clusters}

    def in_cluster(f: Any) -> bool:
        if not keys:
            return False
        h = heads.get(f.path)
        if h is None and src is not None and f.magic == "unknown" and f.size >= 4:
            try:
                h = src.read_head(f.path, 4)
            except (KeyError, OSError, ValueError):
                h = b""
        return bytes((h or b"")[:4]) in keys

    # 2. individual large files, except members of a cluster
    rows = [{"path": f.path, "size": f.size, "ext": f.ext, "magic": f.magic, "category": f.category}
            for f in bundle.files if not (keys and f.magic == "unknown" and in_cluster(f))]
    cands, deep = select_candidates(rows, limit=limit)
    hits: List[FingerprintHit] = []
    analysed: List[ContainerAnalysis] = []
    deadline = time.monotonic() + CONTAINER_TIME_BUDGET_S
    for row in deep:
        if src is None:
            break
        if time.monotonic() > deadline:
            warnings.append("container analysis stopped early (time budget reached)")
            break
        try:
            with src.open(row["path"]) as fh:
                def read(off: int, n: int, _fh=fh) -> bytes:
                    _fh.seek(off)
                    return _fh.read(n)

                ca = analyze_container(read, row["size"], path=row["path"], ext=row["ext"], magic=row["magic"],
                                       siblings=siblings)
        except (KeyError, OSError, ValueError) as exc:
            warnings.append("container analysis skipped %s: %s" % (row["path"], exc))
            continue
        analysed.append(ca)
    for ca in analysed:
        hits.append(ca.to_hit())
    for cl in clusters:
        hits.append(cl.to_hit())
    hits.sort(key=lambda h: (-h.confidence, h.id))
    info = {"candidates_total": len(cands), "analyzed": len(analysed), "header_clusters": len(clusters),
            "ext_magic_mismatch": dict(sorted(mismatch.items())), "unknown_magic_files": unknown_total,
            "cluster_source": "inventory" if bundle.inv_header_clusters is not None else "own"}
    return hits, info


# --- host --------------------------------------------------------------------------------------------------------
def host_profile(bundle: EvidenceBundle, rules: FingerprintRules, render_found: bool) -> Dict[str, Any]:
    main = next((b for b in bundle.binaries if b.role == "main"), None)
    cpp_ratio = objc_swift_ratio = None
    thin: Optional[bool] = None
    if main is not None and main.defined_symbols >= CPP_RATIO_MIN_SYMBOLS:
        cpp_ratio = round(main.defined_cpp / main.defined_symbols, 3)
        objc_swift_ratio = round(main.defined_objc_swift / main.defined_symbols, 3)
    if main is not None and not main.encrypted and (main.own_classes or main.strings):
        thin = main.own_classes <= THIN_SHELL_MAX_CLASSES and render_found
    hints: List[str] = []
    for h in rules.main_loop:
        if match_signal(bundle, SignalSpec(h["type"], h["pattern"], 1.0)):
            hints.append(h["id"])
    return {"thin_uikit_shell": thin, "cpp_ratio": cpp_ratio, "objc_swift_ratio": objc_swift_ratio,
            "main_loop_hints": sorted(hints)}


# --- summary --------------------------------------------------------------------------------------------------
def _names(hits: Sequence[FingerprintHit], limit: int = 3) -> str:
    return ", ".join(h.name or h.id for h in hits[:limit])


def summarize(fp: FingerprintResult, limited: bool) -> Tuple[str, List[Dict[str, Any]]]:
    """English one-sentence profile plus structured parts for localisation."""
    parts: List[Tuple[str, Dict[str, Any], str]] = []
    host = fp.host or {}
    if host.get("cpp_ratio") is not None and host["cpp_ratio"] >= CPP_HEAVY_RATIO:
        parts.append(("host_cpp", {}, "Native C++ code"))
    elif host.get("thin_uikit_shell"):
        parts.append(("host_thin", {}, "Thin UIKit shell"))
    else:
        parts.append(("host_generic", {}, "Native app"))
    if fp.render:
        names = ", ".join(h.name or k for k, h in sorted(fp.render.items()))
        parts.append(("render", {"names": names}, "on %s" % names))
    if fp.script_vms:
        names = _names(fp.script_vms)
        parts.append(("script_vms", {"names": names}, "embedded %s" % names))
    if fp.physics:
        names = _names(fp.physics)
        parts.append(("physics", {"names": names}, "%s physics" % names))
    if fp.audio:
        names = _names(fp.audio)
        parts.append(("audio", {"names": names}, "%s audio" % names))
    conts = [h for h in fp.containers if h.extra.get("verdict") in ("custom_format", "encrypted_suspected", "compressed")]
    if conts:
        c0 = conts[0]
        comp = c0.extra.get("compression")
        desc = "%d custom container(s)" % len(conts) if len(conts) > 1 else "custom container"
        if comp:
            desc += " (%s blocks)" % comp
        parts.append(("containers", {"count": len(conts), "compression": comp or ""}, desc))
    text = parts[0][2] + "".join((" " if p[0] == "render" else ", ") + p[2] for p in parts[1:])
    if limited:
        text += " [binary FairPlay-encrypted: binary-based signals limited]"
    return text, [{"key": k, "params": p} for k, p, _ in parts]


# --- entry ----------------------------------------------------------------------------------------------------------
def build_fingerprint(ctx: Any, bundle: EvidenceBundle, *, rules: Optional[FingerprintRules] = None,
                      container_limit: int = 50) -> Tuple[FingerprintResult, Dict[str, Any], List[str]]:
    """Return ``(profile, extra, warnings)``."""
    rules = rules or load_rules()
    warnings: List[str] = list(rules.warnings)
    fp = FingerprintResult()
    for dim in DIMENSIONS:
        hits: List[FingerprintHit] = []
        for sig in rules.dimensions.get(dim, []):
            h = _hit_from_score(bundle, sig)
            if h is not None:
                hits.append(h)
        if dim == "render":
            fp.render = {h.id: h for h in hits}
        else:
            setattr(fp, dim, hits)

    # Lua bytecode flavours (header bytes of the files the inventory typed as lua_bytecode)
    if ctx.source is not None:
        lua_files = [f.path for f in bundle.files if f.magic == "lua_bytecode"][:LUA_HEAD_PROBES]
        if lua_files:
            prof = lua_bytecode_profile(_read_heads(ctx, lua_files, 8))
            total = bundle.count_magic("lua_bytecode")
            if prof["puc"]:
                _merge_hit(fp.script_vms, FingerprintHit(id="lua", name="Lua (PUC)", confidence=0.6, evidence=[Evidence(
                    "file", lua_files[0], "Lua %s bytecode header (%d of %d probed files)" % (
                        "/".join(prof["puc"]), sum(prof["puc"].values()), len(lua_files)))],
                    extra={"bytecode_versions": prof["puc"], "bytecode_files": total}))
            if prof["luajit"]:
                _merge_hit(fp.script_vms, FingerprintHit(id="luajit", name="LuaJIT", confidence=0.6, evidence=[Evidence(
                    "file", lua_files[0], "LuaJIT bytecode header (%d of %d probed files)" % (
                        prof["luajit"], len(lua_files)))], extra={"bytecode_files": total}))
        # embedded Python
        pyc_files = [f.path for ext in (".pyc", ".pyo", ".nxs") for f in bundle.files_with_ext(ext)][:PYC_PROBES]
        if pyc_files:
            pp = pyc_profile(_read_heads(ctx, pyc_files, 4))
            if pp["checked"]:
                ev = [Evidence("file", pyc_files[0], "%d of %d probed bytecode files have a valid CPython header" % (
                    pp["valid"], pp["checked"]))]
                conf = 0.5 if pp["valid"] else 0.3
                if pp["opcode_scramble_suspected"]:
                    ev.append(Evidence("heuristic", pp["examples"][0] if pp["examples"] else pyc_files[0],
                                       "%d file(s) with a non-standard bytecode header: possible customised Python "
                                       "(opcode shuffling) - suspected only" % (pp["nonstandard_header"] + pp["nonstandard_number"])))
                _merge_hit(fp.script_vms, FingerprintHit(id="python", name="Python (embedded)", confidence=conf, evidence=ev, extra={"pyc": pp}))

    hits, cinfo = analyze_containers(ctx, bundle, limit=container_limit, warnings=warnings)
    fp.containers = hits
    fp.host = host_profile(bundle, rules, bool(fp.render))
    limited = bool(bundle.visibility.get("limited"))
    fp.summary_text, parts = summarize(fp, limited)
    for dim in ("script_vms",):
        getattr(fp, dim).sort(key=lambda h: (-h.confidence, h.id))
    for dim in DIMENSIONS[1:]:
        getattr(fp, dim).sort(key=lambda h: (-h.confidence, h.id))
    extra = {"visibility": dict(bundle.visibility), "containers": cinfo, "summary_parts": parts,
             "binary_limited": limited, "rules_loaded": {d: len(v) for d, v in rules.dimensions.items()}}
    return fp, extra, warnings
