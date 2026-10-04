"""AssetBundle discovery, classification, deep validation and aggregation (``unity.assetbundle.encryption``).

Parsing is delegated to ``ipa_analyzer.formats`` (``unityfs`` header / BlocksInfo / probes, ``lz4``).  This
module only decides *what a file looks like* and aggregates the evidence.  Every conclusion is heuristic:
nothing is decrypted, and an XOR key or a block marker is only recorded as a hypothesis.

Classes (``by_class`` keys):

``standard``                 known UnityFS/UnityWeb/UnityRaw/UnityArchive signature at offset 0
``offset_prefix``            a signature with a plausible header inside the first 4 KiB, not at offset 0
``xor_simple``               the first bytes XOR the signature give a constant / short repeating key and the
                             header then decodes plausibly (key recorded as a hypothesis)
``high_entropy_unknown``     no known magic or compression container and head entropy >= 7.5 (7.0 below 4 KiB,
                             where the estimate is capped by the sample size)
``block_encrypted_suspected`` standard header, readable BlocksInfo, but the first LZ4/LZ4HC data block does not
                             decompress (Htp-style block encryption; see docs/05-REAL-SAMPLES-AND-HTP.md)
``other``                    claims to be a bundle (extension / category) but is a known other format
``unknown``                  unrecognised and low entropy
"""
from __future__ import annotations

import io
import logging
import math
import re
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from ..formats import lz4, unityfs
from ..formats.compress_sniff import sniff as sniff_compression
from ..util.entropy import shannon
from ..util.magic import sniff as sniff_magic

log = logging.getLogger(__name__)

__all__ = ["CLASSES", "HEAD_READ", "BundleRecord", "select_candidates", "classify_head", "deep_check",
           "find_common_marker", "analyze_bundles", "aggregate_verdict", "detect_addressables"]

CLASSES: Tuple[str, ...] = ("standard", "offset_prefix", "xor_simple", "high_entropy_unknown",
                            "block_encrypted_suspected", "other", "unknown")
HEAD_READ = 16384
ENTROPY_HIGH = 7.5
ENTROPY_HIGH_SMALL = 7.0          # files < 4 KiB: the Shannon estimate cannot exceed log2(size)
SMALL_FILE = 4096
MIN_CANDIDATE_SIZE = 32
MAX_DEEP_BLOCK = 16 * 1024 * 1024
MARKER_WINDOW = 256

# Extensions that claim to be an AssetBundle (a file with one of them stays in the bundle population even if
# unrecognised); ``.bytes`` files are examined but never counted against the population.
CLAIM_EXTS = frozenset((".bundle", ".ab", ".unity3d", ".assetbundle", ".b", ".assets_bundle"))
WEAK_EXTS = frozenset((".bytes",))
SKIP_EXTS = frozenset((".manifest", ".json", ".txt", ".xml", ".plist", ".hash", ".meta", ".md", ".csv", ".yaml",
                       ".yml", ".png", ".jpg", ".jpeg", ".gif", ".ogg", ".mp3", ".wav", ".mp4", ".mov", ".strings",
                       ".html", ".js", ".lua", ".dll", ".ttf", ".otf", ".atlas", ".log", ".resource", ".ress"))
LOCATION_DIRS = ("Data/Raw/", "aa/")
_KNOWN_UNITY_MAGIC = frozenset(("unityfs", "unityweb", "unityraw", "unityarchive"))
_NOT_A_FORMAT = frozenset(("unknown", "empty", ""))
_ADDR_CATALOG = re.compile(r"(^|/)(aa/)?catalog[^/]*\.(json|bin|hash)$", re.I)
_ADDR_SETTINGS = re.compile(r"(^|/)aa/settings\.json$", re.I)


@dataclass
class BundleRecord:
    path: str
    size: int
    cls: str = "unknown"
    in_population: bool = True
    why: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)
    unity_version: Optional[str] = None
    blocks_info_compression: Optional[int] = None
    format_version: Optional[int] = None
    size_matches: Optional[bool] = None
    deep: Optional[Dict[str, Any]] = None


# --- discovery -------------------------------------------------------------------------------------------
def select_candidates(files: Iterable[Dict[str, Any]], rel_of: Callable[[str], Optional[str]]
                      ) -> List[Dict[str, Any]]:
    """Inventory rows that could be AssetBundles, each annotated with ``why`` (magic / ext / category / location)."""
    out: List[Dict[str, Any]] = []
    for row in files:
        path = row.get("path")
        if not isinstance(path, str) or int(row.get("size") or 0) < MIN_CANDIDATE_SIZE:
            continue
        rel = rel_of(path)
        if rel is None:
            continue
        magic = str(row.get("magic") or "")
        leaf = rel.rsplit("/", 1)[-1]
        ext = ("." + leaf.rsplit(".", 1)[1].lower()) if "." in leaf else ""
        if leaf.lower().startswith("catalog") and ext in (".bin", ".json", ".hash"):
            continue                      # Addressables catalogs are reported separately
        why = ""
        if magic in _KNOWN_UNITY_MAGIC:
            why = "magic"
        elif row.get("category") == "assetbundle" or ext in CLAIM_EXTS:
            why = "ext"
        elif ext in WEAK_EXTS:
            why = "weak_ext"
        elif magic in _NOT_A_FORMAT and ext not in SKIP_EXTS and rel.startswith(LOCATION_DIRS):
            why = "location"
        if why:
            out.append({"path": path, "size": int(row.get("size") or 0), "magic": magic, "why": why, "rel": rel})
    out.sort(key=lambda r: r["path"])
    return out


# --- classification -------------------------------------------------------------------------------------
def _entropy_threshold(size: int) -> float:
    return ENTROPY_HIGH_SMALL if size < SMALL_FILE else ENTROPY_HIGH


def classify_head(head: bytes, size: int, magic_id: str = "") -> Tuple[str, Dict[str, Any]]:
    """Header-level class of one file from its first bytes (``size`` = full file size)."""
    if not head:
        return "unknown", {"reason": "empty"}
    variants = unityfs.probe_variants(head)
    for v in variants:
        if v.kind == "standard":
            return "standard", {"signature": v.signature}
    xors = [v for v in variants if v.kind.startswith("xor") and v.confidence >= 0.6]
    if xors:
        v = max(xors, key=lambda x: x.confidence)
        return "xor_simple", {"key_hex": v.key.hex(), "period": len(v.key), "confidence": v.confidence,
                              "signature": v.signature}
    pre = [v for v in variants if v.kind == "offset_prefix" and v.confidence >= 0.9]
    if pre:
        return "offset_prefix", {"offset": pre[0].offset, "signature": pre[0].signature}
    mid, mconf = sniff_magic(head[:512])
    if mid not in _NOT_A_FORMAT and mconf >= 0.6 and mid not in _KNOWN_UNITY_MAGIC:
        return "other", {"format": mid}
    if magic_id not in _NOT_A_FORMAT and magic_id not in _KNOWN_UNITY_MAGIC:
        return "other", {"format": magic_id}
    comp = sniff_compression(head)
    if comp.kind != "none" and comp.confidence >= 0.6:
        return "other", {"format": comp.kind, "container": True}
    ent = shannon(head)
    if ent >= _entropy_threshold(size):
        return "high_entropy_unknown", {"entropy": round(ent, 3)}
    return "unknown", {"entropy": round(ent, 3)}


def _shallow_header(head: bytes, size: int) -> Optional[unityfs.UnityFSHeader]:
    try:
        h = unityfs.parse_header(io.BytesIO(head))
    except unityfs.UnityFSError:
        return None
    h.file_size = size
    return h


# --- deep validation ---------------------------------------------------------------------------------------
def find_common_marker(chunks: Sequence[bytes], *, min_len: int = 4, max_len: int = 32,
                       fraction: float = 0.75) -> Optional[Dict[str, Any]]:
    """Longest byte sequence present in at least ``fraction`` of ``chunks`` (and >= 2 of them), or None.

    Used on the first 256 bytes of data blocks that fail to decompress: random ciphertext shares nothing,
    a fixed marker shows up in every block (possibly at a varying position).
    """
    chunks = [bytes(c) for c in chunks if len(c) >= min_len]
    n = len(chunks)
    if n < 2:
        return None
    need = max(2, int(math.ceil(fraction * n)))
    grams: Dict[bytes, Dict[int, int]] = {}
    for ci, c in enumerate(chunks):
        for p in range(len(c) - min_len + 1):
            grams.setdefault(c[p:p + min_len], {}).setdefault(ci, p)
    best: Optional[Tuple[int, int, bytes, Dict[int, int]]] = None
    for g, occ in grams.items():
        if len(occ) < need:
            continue
        cur = dict(occ)
        length = min_len
        while length < max_len:
            nxt: Dict[int, List[int]] = {}
            for ci, p in cur.items():
                if p + length < len(chunks[ci]):
                    nxt.setdefault(chunks[ci][p + length], []).append(ci)
            if not nxt:
                break
            byte, who = max(nxt.items(), key=lambda kv: (len(kv[1]), -kv[0]))
            if len(who) < need:
                break
            cur = {ci: cur[ci] for ci in who}
            length += 1
        cand = (length, len(cur), chunks[next(iter(cur))][cur[next(iter(cur))]:cur[next(iter(cur))] + length], cur)
        if best is None or (cand[0], cand[1]) > (best[0], best[1]):
            best = cand
    if best is None:
        return None
    length, count, marker, occ = best
    positions = sorted(set(occ.values()))
    return {"marker_hex": marker.hex(), "length": length, "blocks_with_marker": count, "blocks_sampled": n,
            "positions": positions[:8], "fixed_position": len(positions) == 1}


def _block_offsets(info: unityfs.BlocksInfo) -> List[int]:
    offs, pos = [], info.data_offset
    for b in info.blocks:
        offs.append(pos)
        pos += b.compressed_size
    return offs


def _test_block(fh: BinaryIO, info: unityfs.BlocksInfo, offs: List[int], idx: int) -> Tuple[str, Optional[str]]:
    """Decompress block ``idx``; returns (status, error_kind) with status ok / failed / skipped."""
    b = info.blocks[idx]
    comp = b.compression
    if b.uncompressed_size > MAX_DEEP_BLOCK or b.compressed_size > 2 * MAX_DEEP_BLOCK + 64:
        return "skipped", "large_block"
    fh.seek(offs[idx])
    raw = fh.read(b.compressed_size)
    if len(raw) != b.compressed_size:
        return "failed", "truncated"
    try:
        if comp in (unityfs.COMPRESSION_LZ4, unityfs.COMPRESSION_LZ4HC):
            lz4.decompress_block(raw, max_output=b.uncompressed_size, expected_size=b.uncompressed_size)
        elif comp == unityfs.COMPRESSION_LZMA:
            lz4.decompress_lzma_unity(raw, expected_size=b.uncompressed_size, max_output=b.uncompressed_size)
        elif comp == unityfs.COMPRESSION_NONE:
            if len(raw) != b.uncompressed_size:
                return "failed", "bad_sizes"
        else:
            return "skipped", "unsupported_compression"
    except lz4.CompressionError as exc:
        return "failed", exc.kind
    return "ok", None


def _comp_name(c: int) -> str:
    return {0: "none", 1: "lzma", 2: "lz4", 3: "lz4hc", 4: "lzham"}.get(c, "unknown_%d" % c)


def deep_check(fh: BinaryIO, size: int, *, test_last: bool = True) -> Dict[str, Any]:
    """Validate header sizes, BlocksInfo and the first / last data block of a standard bundle.

    ``test_last=False`` skips the last block (use it when seeking is expensive, e.g. deflated archive entries).

    ``status``: ``ok`` | ``block_encrypted`` | ``fail`` (+ ``error``) | ``unsupported`` | ``skipped``.
    """
    try:
        header = unityfs.parse_header(fh)
    except unityfs.UnityFSError as exc:
        return {"status": "fail", "error": exc.kind, "stage": "header"}
    out: Dict[str, Any] = {"unity_revision": header.unity_revision, "format_version": header.format_version,
                           "encryption_flag": bool(header.is_unityfs and header.encryption_flag)}
    if not header.is_unityfs:
        out["status"] = "unsupported"
        return out
    try:
        info = unityfs.read_blocks_info(fh, header)
    except unityfs.UnityFSError as exc:
        out.update(status="fail", error=exc.kind, stage="blocks_info")
        return out
    out["block_compression"] = sorted({_comp_name(b.compression) for b in info.blocks})
    out["blocks"] = len(info.blocks)
    if not info.blocks:
        out["status"] = "ok"
        return out
    offs = _block_offsets(info)
    idxs = sorted({0, len(info.blocks) - 1} if test_last else {0})
    lz4_first = info.blocks[0].compression in (unityfs.COMPRESSION_LZ4, unityfs.COMPRESSION_LZ4HC)
    skipped = 0
    for idx in idxs:
        status, err = _test_block(fh, info, offs, idx)
        if status == "skipped":
            skipped += 1
            continue
        if status == "failed":
            out["failed_block"] = idx
            out["error"] = err
            if idx == 0 and lz4_first:
                out["status"] = "block_encrypted"
                out["marker"] = _marker_evidence(fh, info, offs)
            else:
                out["status"] = "fail"
                out["stage"] = "block"
            return out
    out["status"] = "skipped" if skipped == len(idxs) else "ok"
    return out


def _marker_evidence(fh: BinaryIO, info: unityfs.BlocksInfo, offs: List[int]) -> Optional[Dict[str, Any]]:
    lz = [i for i, b in enumerate(info.blocks)
          if b.compression in (unityfs.COMPRESSION_LZ4, unityfs.COMPRESSION_LZ4HC) and b.compressed_size >= 16]
    if len(lz) > 8:
        step = len(lz) / 8.0
        lz = [lz[int(i * step)] for i in range(8)]
    chunks: List[bytes] = []
    for i in lz:
        fh.seek(offs[i])
        chunks.append(fh.read(min(MARKER_WINDOW, info.blocks[i].compressed_size)))
    return find_common_marker(chunks, min_len=6)


# --- addressables ------------------------------------------------------------------------------------------
def detect_addressables(paths: Iterable[Tuple[str, str]]) -> Dict[str, Any]:
    """``paths`` = ``(archive_name, app_relative_name)``; finds Addressables catalogs / settings / aa folder."""
    catalogs: List[str] = []
    settings: List[str] = []
    aa_files = 0
    for name, rel in paths:
        if _ADDR_SETTINGS.search(rel):
            settings.append(name)
        elif _ADDR_CATALOG.search(rel) and ("aa" in rel.lower().split("/") or "catalog_" in rel.lower()
                                            or rel.lower().rsplit("/", 1)[-1].startswith("catalog")):
            catalogs.append(name)
        if rel.startswith("Data/Raw/aa/") or "/aa/" in "/" + rel:
            aa_files += 1
    catalogs.sort()
    settings.sort()
    return {"catalog_found": bool(catalogs), "catalogs": catalogs[:20], "settings_found": bool(settings),
            "settings": settings[:5], "aa_files": aa_files}


# --- aggregation --------------------------------------------------------------------------------------------
def aggregate_verdict(counts: Dict[str, int], population: int, deep: Dict[str, int], std_total: int
                      ) -> Tuple[str, float, List[str]]:
    """Verdict, confidence and reason keys from class counts and the deep-check sample.

    ``deep``: counts of sample outcomes ``ok / block_encrypted / fail / unsupported / skipped``.
    """
    if population == 0:
        return "unknown", 0.0, ["no_bundles"]
    reasons: List[str] = []
    s = deep.get("sampled", 0)
    if s:
        # outcomes of the sample are extrapolated to all header-standard bundles
        est_ok = (deep.get("ok", 0) + deep.get("unsupported", 0) + deep.get("skipped", 0)) * std_total / s
        est_blk = deep.get("block_encrypted", 0) * std_total / s
        est_fail = deep.get("fail", 0) * std_total / s
    else:
        est_ok, est_blk, est_fail = float(std_total), 0.0, 0.0
    hard = counts.get("high_entropy_unknown", 0) + counts.get("xor_simple", 0)
    est_protected_soft = est_blk + est_fail
    ok_frac = est_ok / population
    hard_frac = hard / population
    soft_frac = est_protected_soft / population
    if hard_frac >= 0.5:
        reasons.append("majority_unreadable")
        return "yes", 0.9 if population >= 5 else 0.75, reasons
    if ok_frac >= 0.95 and hard == 0 and est_protected_soft < 1:
        reasons.append("all_standard")
        sampled_all = deep.get("sampled", 0) >= std_total
        return "no", 0.9 if (sampled_all or std_total < 20) else 0.8, reasons
    if hard_frac + soft_frac >= 0.5:
        reasons.append("majority_protected_suspected")
        return "suspected", 0.75, reasons
    reasons.append("mixed")
    return "suspected", 0.65, reasons


# --- main entry ---------------------------------------------------------------------------------------------
def analyze_bundles(candidates: Sequence[Dict[str, Any]], source: Any, *, deep_sample: int = 200,
                    paths_sample: int = 200, per_class_samples: int = 10) -> Dict[str, Any]:
    """Classify ``candidates`` (output of ``select_candidates``) read through ``source`` (``ArchiveSource``-like)."""
    recs: List[BundleRecord] = []
    for cand in candidates:
        path, size = cand["path"], int(cand["size"])
        why = cand.get("why", "")
        rec = BundleRecord(path, size, why=why)
        try:
            head = source.read_head(path, HEAD_READ)
        except (KeyError, OSError, ValueError) as exc:
            rec.cls, rec.detail = "unknown", {"reason": "unreadable: %s" % exc}
            recs.append(rec)
            continue
        rec.cls, rec.detail = classify_head(head, size, cand.get("magic", ""))
        if rec.cls == "standard":
            h = _shallow_header(head, size)
            if h is not None:
                rec.unity_version = h.unity_revision or None
                rec.blocks_info_compression = h.compression if h.is_unityfs else None
                rec.format_version = h.format_version
                rec.size_matches = (h.size == size) if h.is_unityfs else None
        if why == "weak_ext" and rec.cls in ("high_entropy_unknown", "unknown", "other"):
            rec.in_population = False
        elif why == "location" and rec.cls in ("unknown", "other"):
            rec.in_population = False
        recs.append(rec)

    # deep sample over header-standard bundles (deterministic, evenly spaced + the largest one)
    std = [r for r in recs if r.cls == "standard"]
    chosen: List[BundleRecord] = []
    if std:
        n = max(0, min(deep_sample, len(std)))
        if n:
            idxs = {(i * len(std)) // n for i in range(n)}
            chosen = [std[i] for i in sorted(idxs)]
            big = max(std, key=lambda r: (r.size, r.path))
            if big not in chosen:
                chosen.append(big)
    deep_counts: Dict[str, int] = {"sampled": len(chosen)}
    errors: Dict[str, int] = {}
    markers: List[Dict[str, Any]] = []
    flag_hits = 0
    block_comp: Dict[str, int] = {}
    for r in chosen:
        try:
            with source.open(r.path) as fh:
                res = deep_check(fh, r.size, test_last=_cheap_seek(source, r))
        except (KeyError, OSError, ValueError) as exc:
            res = {"status": "skipped", "error": "unreadable: %s" % exc}
        r.deep = res
        st = res.get("status", "skipped")
        deep_counts[st] = deep_counts.get(st, 0) + 1
        if res.get("encryption_flag"):
            flag_hits += 1
        if st in ("fail", "block_encrypted") and res.get("error"):
            errors[res["error"]] = errors.get(res["error"], 0) + 1
        for c in res.get("block_compression") or []:
            block_comp[c] = block_comp.get(c, 0) + 1
        if st == "block_encrypted":
            r.cls = "block_encrypted_suspected"
            if res.get("marker"):
                markers.append(res["marker"])
    std_total = len([r for r in recs if r.cls == "standard"]) + deep_counts.get("block_encrypted", 0)

    by_class = {c: 0 for c in CLASSES}
    for r in recs:
        by_class[r.cls] = by_class.get(r.cls, 0) + 1
    # population = files that behave like (or claim to be) bundles; weak-extension / location-only hits that
    # turned out to be something else stay out of it
    population = len([r for r in recs if r.in_population and (r.cls != "other" or r.why in ("ext", "magic"))])
    pop_counts = {c: 0 for c in CLASSES}
    for r in recs:
        if r.in_population:
            pop_counts[r.cls] += 1
    verdict, conf, reasons = aggregate_verdict(pop_counts, population, deep_counts, std_total)

    comp: Dict[str, int] = {}
    versions: Dict[str, int] = {}
    fmt: Dict[str, int] = {}
    size_mismatch = 0
    for r in recs:
        if r.cls in ("standard", "block_encrypted_suspected") and r.blocks_info_compression is not None:
            k = _comp_name(r.blocks_info_compression)
            comp[k] = comp.get(k, 0) + 1
        if r.unity_version:
            versions[r.unity_version] = versions.get(r.unity_version, 0) + 1
        if r.format_version is not None:
            fmt[str(r.format_version)] = fmt.get(str(r.format_version), 0) + 1
        if r.size_matches is False:
            size_mismatch += 1

    samples: Dict[str, List[str]] = {}
    for c in CLASSES:
        rows = sorted((r for r in recs if r.cls == c), key=lambda r: (-r.size, r.path))
        if rows:
            samples[c] = [r.path for r in rows[:per_class_samples]]
    order = {c: i for i, c in enumerate(("standard", "block_encrypted_suspected", "offset_prefix", "xor_simple",
                                         "high_entropy_unknown"))}
    pool = sorted((r for r in recs if r.cls in order), key=lambda r: (order[r.cls], r.path))
    if len(pool) > paths_sample:
        pool = [pool[(i * len(pool)) // paths_sample] for i in range(paths_sample)]
    xor_keys = sorted({(r.detail.get("key_hex"), r.detail.get("period")) for r in recs if r.cls == "xor_simple"})

    return {
        "total": len(recs), "population": population, "by_class": by_class, "compression": comp,
        "block_compression": block_comp, "unity_versions": versions, "format_versions": fmt,
        "samples": samples, "paths_sample": [r.path for r in pool], "sampled": len(chosen),
        "verdict": verdict, "confidence": conf, "reasons": reasons,
        "deep": {"sampled": len(chosen), "ok": deep_counts.get("ok", 0),
                 "block_encrypted": deep_counts.get("block_encrypted", 0), "fail": deep_counts.get("fail", 0),
                 "unsupported": deep_counts.get("unsupported", 0), "skipped": deep_counts.get("skipped", 0),
                 "errors": errors, "encryption_flag_hits": flag_hits, "size_field_mismatch": size_mismatch},
        "block_markers": markers[:5],
        "xor_hypotheses": [{"key_hex": k, "period": p} for k, p in xor_keys[:5] if k],
        "entropy_samples": _entropy_summary(recs),
    }


def _cheap_seek(source: Any, rec: BundleRecord) -> bool:
    """Random access is cheap for stored entries and small files; deflated big entries are read from the start."""
    if rec.size <= 8 * 1024 * 1024:
        return True
    try:
        st = source.stat(rec.path)
    except (KeyError, OSError, AttributeError):
        return False
    return bool(getattr(st, "compressed_size", 0) and st.compressed_size >= st.size)


def _entropy_summary(recs: Sequence[BundleRecord]) -> Dict[str, Any]:
    vals = [r.detail["entropy"] for r in recs if r.cls == "high_entropy_unknown" and "entropy" in r.detail]
    if not vals:
        return {}
    return {"high_entropy_files": len(vals), "min": min(vals), "max": max(vals),
            "mean": round(sum(vals) / len(vals), 3)}
