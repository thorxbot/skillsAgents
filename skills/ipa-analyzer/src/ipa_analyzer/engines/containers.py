"""Generic container analysis for unknown large files and for families of custom-headed small files (WP7).

Question answered per file: *compressed, encrypted-looking, plain or a custom container?*
Entropy alone cannot separate compression from encryption, so internal structure is checked first:

1. integers in the header that form a monotonic offset table (optionally with a record stride) and size
   fields equal to the file size;
2. compression streams inside the file, validated by actually inflating them with the standard library
   (zlib / gzip / LZMA-alone; the checksum of a zlib stream must verify) or by distinctive magic (zstd, LZ4
   frame) -- nothing is ever executed or written, output of the trial inflation is discarded;
3. block-wise entropy and byte distribution (only when no structure explains the data);
4. a known-plaintext XOR probe on the first bytes (single byte or short repeating key). It records a
   *hypothesis* in the evidence; the file is never decoded as a whole.

Conclusions are capped at ``suspected`` (verdict strings below are hypotheses, confidence <= ``MAX_CONFIDENCE``).
Verdicts: ``compressed`` | ``custom_format`` | ``encrypted_suspected`` | ``plain`` | ``unknown``.
"""
from __future__ import annotations

import logging
import lzma
import re
import struct
import zlib
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from ..formats.compress_sniff import sniff as sniff_compression
from ..models import Evidence
from ..util.entropy import shannon
from ..util.magic import is_texty, sniff as sniff_magic
from .api import FingerprintHit

log = logging.getLogger(__name__)

# --- tunables; each constant states its basis ------------------------------------------------------------
MAX_CONFIDENCE = 0.8              # conclusions never exceed "suspected"
MIN_CANDIDATE_SIZE = 1 << 20      # work-package rule: >= 1 MiB and unknown magic
DEFAULT_DEEP_LIMIT = 50           # work-package default for deep analyses
HEAD_READ = 4096                  # header window for integer / magic analysis
SAMPLE_BLOCKS = 16                # evenly spaced sample blocks (same as util.entropy.sampled_entropy)
SAMPLE_BLOCK_SIZE = 4096
SCAN_WINDOW = 256 * 1024          # bytes searched for compression streams (head of the file)
ENTROPY_HIGH = 7.5                # architecture doc 4.5: >= 7.5 bits/byte = compressed or encrypted
ENTROPY_PLAIN = 6.0               # below this, uncompressed structured data is far more likely
MIN_OFFSET_RUN = 8                # P(random 32-bit words give 8 increasing in-file values) is negligible
MAX_STRIDE = 16                   # words per record in an index table
TRIAL_INPUT = 256 * 1024          # input handed to a trial inflation
TRIAL_OUTPUT = 4 * 1024 * 1024    # trial inflation output cap (zip-bomb guard)
MAX_STREAM_TRIALS = 64
MIN_CLUSTER = 20                  # header cluster = at least this many files sharing the first 4 bytes
CLUSTER_PROBES = 12
PAYLOAD_HEADER_SIZES = (4, 8, 12, 16, 20, 24, 32)

#: Extensions that make a file a container candidate regardless of size/magic (no external source).
SUSPICIOUS_EXTS = frozenset({".pak", ".pck", ".pkg", ".pkx", ".npk", ".dat", ".bin", ".data", ".obb", ".arc",
                             ".arcd", ".arci", ".res", ".bytes", ".sc", ".lib", ".blob", ".pack", ".bundle"})
#: Inventory categories that are known formats (or signing data) and never container candidates.
KNOWN_FORMAT_CATEGORIES = frozenset({"assetbundle", "engine_data", "signing", "executable", "framework", "dylib",
                                     "plugin", "assets_car", "localization", "plist", "font"})
INDEX_EXTS = (".idx", ".index", ".list", ".lst", ".toc", ".pkx", ".arci", ".dmanifest", ".manifest")
PAIRED_EXTS = {".pck": ".pkx", ".arcd": ".arci", ".pak": ".pkx", ".pack": ".idx"}
#: Extensions that normally imply a standard header; unknown magic behind them is noteworthy.
STRUCTURED_EXTS = frozenset({".json", ".png", ".jpg", ".jpeg", ".astc", ".ktx", ".pvr", ".js", ".ogg", ".mp3",
                             ".plist", ".xml", ".atlas", ".skel", ".webp", ".ttf", ".lua"})

# Known plaintext prefixes for the XOR probe. Sources: PNG spec, PKWARE APPNOTE, Lua lundump.h,
# UnityFS signature, RFC 3533 (Ogg), RFC 1952 (gzip), SQLite file format doc, Apple bplist.
_PLAINTEXTS: Tuple[Tuple[str, bytes], ...] = (
    ("png", b"\x89PNG\r\n\x1a\n"), ("unityfs", b"UnityFS\x00"), ("sqlite", b"SQLite format 3\x00"),
    ("bplist", b"bplist00"), ("zip", b"PK\x03\x04"), ("lua_bytecode", b"\x1bLua"), ("ogg", b"OggS"),
    ("gzip", b"\x1f\x8b\x08"), ("xml", b"<?xml"),
)
_ZLIB_HEADER = re.compile(rb"\x78[\x01\x5e\x9c\xda]")
_GZIP_HEADER = re.compile(rb"\x1f\x8b\x08")
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_LZ4_MAGIC = b"\x04\x22\x4d\x18"
_LZMA_HEADER = re.compile(rb"\x5d\x00\x00")


# --- result type ---------------------------------------------------------------------------------------
@dataclass
class ContainerAnalysis:
    path: str
    size: int
    ext: str = ""
    magic: str = "unknown"
    verdict: str = "unknown"
    confidence: float = 0.0
    compression: Optional[str] = None
    entropy: Optional[float] = None
    header: Dict[str, Any] = field(default_factory=dict)
    streams: Dict[str, Any] = field(default_factory=dict)
    xor_hypothesis: Optional[Dict[str, Any]] = None
    payload_hypothesis: Optional[str] = None
    block_entropy: Dict[str, float] = field(default_factory=dict)
    evidence: List[Evidence] = field(default_factory=list)

    def to_hit(self) -> FingerprintHit:
        extra: Dict[str, Any] = {"size": self.size, "magic": self.magic, "verdict": self.verdict,
                                 "compression": self.compression,
                                 "entropy": round(self.entropy, 3) if self.entropy is not None else None,
                                 "header": self.header, "xor_hypothesis": self.xor_hypothesis,
                                 "streams": self.streams, "payload_hypothesis": self.payload_hypothesis,
                                 "block_entropy": self.block_entropy, "ext": self.ext}
        name = self.path.rsplit("/", 1)[-1]
        return FingerprintHit(id=self.path, confidence=self.confidence, name=name, evidence=list(self.evidence),
                              extra=extra)


# --- helpers ------------------------------------------------------------------------------------------------
def _ascii_tag(b: bytes) -> Optional[str]:
    if len(b) >= 4 and all(0x30 <= c <= 0x39 or 0x41 <= c <= 0x5A or 0x61 <= c <= 0x7A or c in (0x20, 0x5F, 0x2D)
                           for c in b[:4]) and any(0x41 <= c <= 0x5A or 0x61 <= c <= 0x7A for c in b[:4]):
        return b[:4].decode("ascii")
    return None


def _words(data: bytes, width: int, endian: str) -> List[int]:
    n = len(data) // width
    if n == 0:
        return []
    fmt = endian + ("I" if width == 4 else "Q") * n
    return list(struct.unpack(fmt, data[:n * width]))


def find_offset_table(head: bytes, file_size: int) -> Optional[Dict[str, Any]]:
    """Longest strictly increasing in-file run in a strided word sequence of ``head`` (None if < ``MIN_OFFSET_RUN``).

    Tries 32/64-bit words in both byte orders and record strides 1..``MAX_STRIDE``; the column of the record
    holding the offset is searched. Values must lie inside the file, so random data almost never qualifies.
    """
    best: Optional[Dict[str, Any]] = None
    for width in (4, 8):
        for endian in ("<", ">"):
            words = _words(head, width, endian)
            if len(words) < MIN_OFFSET_RUN:
                continue
            for stride in range(1, MAX_STRIDE + 1):
                for col in range(stride):
                    seq = words[col::stride]
                    start, length = _best_run(seq, file_size)
                    if length < MIN_OFFSET_RUN or seq[start + length - 1] < 256:
                        continue
                    cand = {"width": width, "endian": endian, "stride": stride, "column": col,
                            "start_index": start * stride + col, "run": length,
                            "first": seq[start], "last": seq[start + length - 1],
                            "offsets": seq[start:start + min(length, 16)]}
                    if best is None or (cand["run"], -cand["stride"]) > (best["run"], -best["stride"]):
                        best = cand
    return best


def _best_run(seq: Sequence[int], size: int) -> Tuple[int, int]:
    """(start, length) of the longest strictly increasing run of in-file values (0 < v <= size)."""
    best = (0, 0)
    i, n = 0, len(seq)
    while i < n:
        if not 0 < seq[i] <= size:
            i += 1
            continue
        j = i + 1
        while j < n and 0 < seq[j] <= size and seq[j] > seq[j - 1]:
            j += 1
        if j - i > best[1]:
            best = (i, j - i)
        i = j
    return best


def find_size_field(head: bytes, file_size: int) -> Optional[Dict[str, Any]]:
    """A header word equal to the file size (or size minus 4/8/16) -> sign of a self-describing header."""
    for width in (4, 8):
        for endian in ("<", ">"):
            for i, v in enumerate(_words(head[:128], width, endian)):
                if v in (file_size, file_size - 4, file_size - 8, file_size - 16) and v > 64:
                    return {"width": width, "endian": endian, "index": i, "value": v}
    return None


def xor_probe(head: bytes) -> Optional[Dict[str, Any]]:
    """Known-plaintext probe: does ``head`` equal a well-known magic XOR a single byte / short repeating key?"""
    if len(head) < 8:
        return None
    for fmt, magic in _PLAINTEXTS:
        if head[:len(magic)] == magic:
            continue                       # not obfuscated at all
        key = bytes(a ^ b for a, b in zip(head, magic))
        if len(set(key)) == 1 and key[0] != 0 and len(magic) >= 4:
            if fmt == "png" and len(head) >= 16 and bytes(c ^ key[0] for c in head[12:16]) != b"IHDR":
                continue
            return {"format": fmt, "kind": "single_byte", "key_hex": key[:1].hex(), "confidence": 0.6,
                    "note": "header equals the %s signature XOR 0x%s" % (fmt, key[:1].hex())}
        if len(magic) >= 8:
            for period in (2, 3, 4):
                if len(key) >= 2 * period and all(key[i] == key[i % period] for i in range(len(key))) \
                        and len(set(key[:period])) > 1:
                    return {"format": fmt, "kind": "repeating", "key_hex": key[:period].hex(), "confidence": 0.5,
                            "note": "header equals the %s signature XOR a %d-byte repeating key" % (fmt, period)}
    return None


def _trial_zlib(data: bytes, wbits: int) -> Tuple[str, int]:
    """Inflate ``data``: ``("verified", n)`` when the stream ends with a good checksum, ``("probable", n)`` when it
    inflated >= 4 KiB of input without error, else ``("no", n)``."""
    d = zlib.decompressobj(wbits)
    out = 0
    try:
        out = len(d.decompress(data[:TRIAL_INPUT], TRIAL_OUTPUT))
    except zlib.error:
        return "no", out
    if d.eof:
        return "verified", out
    consumed = min(len(data), TRIAL_INPUT) - len(d.unconsumed_tail)
    if out >= 64 and consumed >= 4096:
        return "probable", out
    return "no", out


def _trial_lzma(data: bytes) -> Tuple[str, int]:
    d = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    try:
        out = len(d.decompress(data[:TRIAL_INPUT], 1 << 20))
    except (lzma.LZMAError, EOFError, ValueError):
        return "no", 0
    return ("verified", out) if d.eof else (("probable", out) if out >= 256 else ("no", out))


def find_streams(window: bytes, base: int = 0, *, anchored: bool = False) -> List[Dict[str, Any]]:
    """Compression streams starting inside ``window`` (absolute offset = ``base`` + position).

    ``anchored=True`` only accepts a stream that starts at position 0 of ``window``."""
    found: List[Dict[str, Any]] = []
    trials = 0

    def hits(rx: "re.Pattern[bytes]") -> List["re.Match[bytes]"]:
        if anchored:
            m0 = rx.match(window)
            return [m0] if m0 else []
        return list(rx.finditer(window))

    for m in hits(_ZLIB_HEADER):
        if trials >= MAX_STREAM_TRIALS:
            break
        trials += 1
        status, out = _trial_zlib(window[m.start():], 15)
        if status != "no":
            found.append({"kind": "zlib", "offset": base + m.start(), "status": status, "out": out})
    for m in hits(_GZIP_HEADER):
        if trials >= MAX_STREAM_TRIALS:
            break
        trials += 1
        status, out = _trial_zlib(window[m.start():], 31)
        if status != "no":
            found.append({"kind": "gzip", "offset": base + m.start(), "status": status, "out": out})
    for m in hits(_LZMA_HEADER):
        if trials >= MAX_STREAM_TRIALS:
            break
        trials += 1
        status, out = _trial_lzma(window[m.start():])
        if status != "no":
            found.append({"kind": "lzma", "offset": base + m.start(), "status": status, "out": out})
    for magic, kind in ((_ZSTD_MAGIC, "zstd"), (_LZ4_MAGIC, "lz4_frame")):
        pos = window.find(magic) if not anchored else (0 if window.startswith(magic) else -1)
        n = 0
        while pos >= 0 and n < 8:
            found.append({"kind": kind, "offset": base + pos, "status": "magic", "out": 0})
            pos = window.find(magic, pos + 1) if not anchored else -1
            n += 1
    found.sort(key=lambda s: s["offset"])
    return found


def find_companions(path: str, siblings: Iterable[str]) -> List[str]:
    """Index / partner files next to ``path`` (same directory and stem, index-like extension)."""
    d, _, base = path.rpartition("/")
    stem, dot, ext = base.rpartition(".")
    if not dot:
        stem, ext = base, ""
    low_ext = ("." + ext.lower()) if ext else ""
    out: List[str] = []
    want = set(INDEX_EXTS)
    if low_ext in PAIRED_EXTS:
        want.add(PAIRED_EXTS[low_ext])
    for s in siblings:
        sd, _, sb = s.rpartition("/")
        if sd != d or s == path:
            continue
        sstem, sdot, sext = sb.rpartition(".")
        if sdot and sstem == stem and ("." + sext.lower()) in want:
            out.append(s)
    return sorted(out)[:4]


def _sample_offsets(size: int) -> List[int]:
    if size <= SAMPLE_BLOCKS * SAMPLE_BLOCK_SIZE:
        return [0]
    span = size - SAMPLE_BLOCK_SIZE
    return sorted({(span * i) // (SAMPLE_BLOCKS - 1) for i in range(SAMPLE_BLOCKS)})


# --- main entry ---------------------------------------------------------------------------------------------
def analyze_container(read: Callable[[int, int], bytes], size: int, *, path: str = "", ext: str = "",
                      magic: str = "unknown", siblings: Sequence[str] = ()) -> ContainerAnalysis:
    """Deep analysis of one file. ``read(offset, n)`` returns up to ``n`` bytes at ``offset``."""
    res = ContainerAnalysis(path=path, size=size, ext=ext, magic=magic)
    if size <= 0:
        res.verdict, res.confidence = "unknown", 0.1
        return res
    head = read(0, min(size, max(HEAD_READ, SCAN_WINDOW)))
    h4k = head[:HEAD_READ]
    if not head:
        res.evidence.append(Evidence("heuristic", path, "file could not be read"))
        return res

    # block samples -> entropy
    blocks: List[bytes] = []
    if size <= SAMPLE_BLOCKS * SAMPLE_BLOCK_SIZE:
        blocks = [head if len(head) >= size else read(0, size)]
    else:
        for off in _sample_offsets(size):
            b = read(off, SAMPLE_BLOCK_SIZE)
            if b:
                blocks.append(b)
    sample = b"".join(blocks)
    res.entropy = shannon(sample) if sample else None
    ents = [shannon(b) for b in blocks if b]
    if ents:
        res.block_entropy = {"min": round(min(ents), 3), "max": round(max(ents), 3),
                             "mean": round(sum(ents) / len(ents), 3)}
        uniq = len(set(sample))
        res.block_entropy["unique_bytes"] = uniq

    # header structure
    tag = _ascii_tag(h4k)
    res.header = {"magic_hex": h4k[:8].hex(), "magic_ascii": tag, "u32_le": list(struct.unpack("<4I", h4k[:16]))
                  if len(h4k) >= 16 else []}
    table = find_offset_table(h4k, size)
    if table:
        res.header["offset_table"] = table
        res.evidence.append(Evidence("heuristic", path, "monotonic offset table: %d entries, stride %d words, "
                                     "first %d last %d (all inside the file)" %
                                     (table["run"], table["stride"], table["first"], table["last"])))
    sizef = find_size_field(h4k, size)
    if sizef:
        res.header["size_field"] = sizef
        res.evidence.append(Evidence("heuristic", path, "header word #%d equals the file size" % sizef["index"]))
    if tag:
        res.evidence.append(Evidence("heuristic", path, "header starts with ASCII tag %r" % tag))
    comps = find_companions(path, siblings) if path and siblings else []
    if comps:
        res.header["companions"] = comps
        res.evidence.append(Evidence("file", comps[0], "index / partner file next to the container"))

    # compression streams
    streams = find_streams(head[:SCAN_WINDOW])
    if table:   # follow the table: its offsets point at the blocks
        seen = {s["offset"] for s in streams}
        for off in table["offsets"][:12]:
            if off in seen or off >= size:
                continue
            block = read(off, TRIAL_INPUT)
            for s in find_streams(block, off, anchored=True):
                if s["offset"] == off and s["offset"] not in seen:
                    streams.append(s)
                    seen.add(s["offset"])
        streams.sort(key=lambda s: s["offset"])
    ok = [s for s in streams if s["status"] in ("verified", "magic")]
    probable = [s for s in streams if s["status"] == "probable"]
    kinds = Counter(s["kind"] for s in ok + probable)
    res.streams = {"verified": sum(1 for s in streams if s["status"] == "verified"),
                   "magic_only": sum(1 for s in streams if s["status"] == "magic"),
                   "probable": len(probable), "kinds": dict(sorted(kinds.items())),
                   "offsets": [s["offset"] for s in (ok + probable)[:8]]}
    if kinds:
        res.compression = kinds.most_common(1)[0][0]
        res.evidence.append(Evidence("heuristic", path, "contains %s compression structure (%d stream(s) checked "
                                     "in the first %d KiB; compressed is not encrypted)" %
                                     (res.compression, sum(kinds.values()), SCAN_WINDOW // 1024)))

    res.xor_hypothesis = xor_probe(h4k)
    if res.xor_hypothesis:
        res.evidence.append(Evidence("heuristic", path, res.xor_hypothesis["note"]))

    ent = res.entropy if res.entropy is not None else 0.0
    structured = bool(table or sizef or tag or comps)
    res.verdict, res.confidence, res.payload_hypothesis = _decide(res, head, structured, ent, bool(ok or probable))
    res.confidence = min(res.confidence, MAX_CONFIDENCE)
    return res


def _decide(res: ContainerAnalysis, head: bytes, structured: bool, ent: float, has_streams: bool) -> Tuple[str, float, Optional[str]]:
    streams = res.streams
    verified = streams.get("verified", 0) + streams.get("magic_only", 0)
    first_stream = streams["offsets"][0] if streams.get("offsets") else None
    if res.xor_hypothesis:
        return "encrypted_suspected", res.xor_hypothesis["confidence"], "xor_obfuscation"
    if is_texty(head[:2048]) and ent < ENTROPY_HIGH:
        return "plain", 0.8, None
    if has_streams and structured:
        return "custom_format", 0.7, res.compression
    if has_streams and first_stream is not None and first_stream <= 64:
        return "compressed", 0.75, res.compression
    if has_streams and verified >= 3:
        return "custom_format", 0.6, res.compression
    if has_streams and ent >= ENTROPY_HIGH:
        return "compressed", 0.45, res.compression
    if structured and ent >= ENTROPY_HIGH:
        return "custom_format", 0.55, "high_entropy_unknown"
    if structured:
        return "custom_format", 0.5, "uncompressed_or_unknown"
    if ent >= ENTROPY_HIGH:
        return "encrypted_suspected", 0.55, "high_entropy_without_structure"
    if ent < ENTROPY_PLAIN:
        return "plain", 0.5, None
    return "unknown", 0.3, None


# --- candidate selection ---------------------------------------------------------------------------------------
def is_candidate(path: str, size: int, ext: str, magic: str, category: str = "other",
                 *, min_size: int = MIN_CANDIDATE_SIZE) -> bool:
    """Large file with unknown magic, or a file with a container-like extension (known magics excluded)."""
    if magic not in ("unknown", "empty"):
        return False
    if category in KNOWN_FORMAT_CATEGORIES:
        return False
    return size >= min_size or (ext.lower() in SUSPICIOUS_EXTS and size >= 4096)


def select_candidates(files: Iterable[Dict[str, Any]], *, limit: int = DEFAULT_DEEP_LIMIT,
                      min_size: int = MIN_CANDIDATE_SIZE) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """``(all candidates, deep-analysis subset)``; the subset holds the ``limit`` largest, one per distinct
    ``(directory, extension)`` first so that many sibling shards do not crowd out other containers."""
    cands = [f for f in files if is_candidate(f["path"], int(f.get("size") or 0), str(f.get("ext") or ""),
                                              str(f.get("magic") or "unknown"), str(f.get("category") or "other"),
                                              min_size=min_size)]
    cands.sort(key=lambda f: (-int(f.get("size") or 0), f["path"]))
    first: List[Dict[str, Any]] = []
    rest: List[Dict[str, Any]] = []
    seen = set()
    for f in cands:
        key = (f["path"].rpartition("/")[0], str(f.get("ext") or ""))
        (rest if key in seen else first).append(f)
        seen.add(key)
    deep = (first + rest)[:max(0, limit)]
    return cands, deep


# --- header clusters (many small files sharing a custom header) ----------------------------------------------------
@dataclass
class HeaderCluster:
    header_hex: str
    header_ascii: Optional[str]
    count: int
    total_size: int
    exts: Dict[str, int]
    size_min: int
    size_median: int
    size_max: int
    ext_mismatch: Dict[str, int] = field(default_factory=dict)
    payload: Dict[str, Any] = field(default_factory=dict)
    samples: List[str] = field(default_factory=list)
    verdict: str = "custom_format"
    confidence: float = 0.0
    evidence: List[Evidence] = field(default_factory=list)

    @property
    def id(self) -> str:
        return "header-cluster:%s" % (self.header_ascii or self.header_hex)

    def to_hit(self) -> FingerprintHit:
        extra = {"kind": "header_cluster", "count": self.count, "size": self.total_size, "magic": self.header_hex,
                 "magic_ascii": self.header_ascii, "verdict": self.verdict, "compression": self.payload.get("compression"),
                 "entropy": self.payload.get("entropy"), "xor_hypothesis": None, "exts": self.exts,
                 "ext_mismatch": self.ext_mismatch, "size_range": [self.size_min, self.size_median, self.size_max],
                 "payload": self.payload, "samples": self.samples}
        return FingerprintHit(id=self.id, confidence=self.confidence, name=self.header_ascii or self.header_hex,
                              evidence=list(self.evidence), extra=extra)


def cluster_headers(entries: Sequence[Tuple[str, int, str, bytes]],
                    read_head: Callable[[str, int], bytes], *, min_count: int = MIN_CLUSTER,
                    max_clusters: int = 8) -> List[HeaderCluster]:
    """Group ``(path, size, ext, head)`` rows of unknown-magic files by their first 4 bytes.

    For each large group probe a few members: strip a candidate header length (4..32 bytes) and check
    whether the remainder is a *standard* format (``util.magic``), a compression stream, or opaque data.
    """
    groups: Dict[bytes, List[Tuple[str, int, str]]] = {}
    head_of: Dict[str, bytes] = {}
    for path, size, ext, head in entries:
        if len(head) >= 4:
            groups.setdefault(bytes(head[:4]), []).append((path, size, ext))
            head_of[path] = bytes(head)
    out: List[HeaderCluster] = []
    for key, rows in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        if len(rows) < min_count:
            break
        sizes = sorted(r[1] for r in rows)
        exts = Counter(r[2] for r in rows)
        mismatch = {e: n for e, n in exts.items() if e in STRUCTURED_EXTS}
        cl = HeaderCluster(header_hex=key.hex(), header_ascii=_ascii_tag(key), count=len(rows),
                           total_size=sum(sizes), exts=dict(sorted(exts.items())), size_min=sizes[0],
                           size_median=sizes[len(sizes) // 2], size_max=sizes[-1], ext_mismatch=mismatch,
                           samples=[r[0] for r in rows[:5]])
        if _profile_cluster(cl, rows, head_of, read_head):
            out.append(cl)
        if len(out) >= max_clusters:
            break
    return out


def cluster_from_summary(head4: bytes, count: int, total_size: int, exts: Dict[str, int],
                         example_rows: Sequence[Tuple[str, int, str]], read_head: Callable[[str, int], bytes]) -> Optional[HeaderCluster]:
    """Build a cluster from an ``inventory.header_clusters`` entry (counts for all members, a few example files).

    Size statistics and the payload / size-field probes use the examples only (``size_range`` is sampled).
    """
    if count < MIN_CLUSTER or len(head4) < 4:
        return None
    key = bytes(head4[:4])
    sizes = sorted(r[1] for r in example_rows) or [0]
    head_of: Dict[str, bytes] = {}
    for p, _s, _e in example_rows:
        try:
            head_of[p] = read_head(p, 16)
        except (KeyError, OSError, ValueError):
            continue
    cl = HeaderCluster(header_hex=key.hex(), header_ascii=_ascii_tag(key), count=count, total_size=total_size,
                       exts=dict(sorted(exts.items())), size_min=sizes[0], size_median=sizes[len(sizes) // 2],
                       size_max=sizes[-1], ext_mismatch={e: n for e, n in exts.items() if e in STRUCTURED_EXTS},
                       samples=[r[0] for r in example_rows[:5]])
    cl.payload["sampled_from"] = len(example_rows)
    return cl if _profile_cluster(cl, example_rows, head_of, read_head, count=count) else None


def _profile_cluster(cl: HeaderCluster, rows: Sequence[Tuple[str, int, str]], head_of: Dict[str, bytes],
                     read_head: Callable[[str, int], bytes], *, count: Optional[int] = None) -> bool:
    """Fill payload / evidence / verdict of ``cl``; False when it is not a container family."""
    key = bytes.fromhex(cl.header_hex)
    tag = cl.header_ascii
    if not tag and cl.size_median < 256:
        return False                      # tiny binary records: not a container family
    sampled = cl.payload.get("sampled_from")
    cl.payload.update(_probe_payload(rows, read_head))
    sf = _cluster_size_field(rows, head_of)
    if sf:
        cl.payload["size_field"] = sf
    exts = cl.exts
    first = rows[0][0] if rows else cl.header_hex
    cl.evidence.append(Evidence("heuristic", first, "%d files share the 4-byte header %s%s; extensions: %s" %
                                (cl.count, key.hex(), " (%r)" % tag if tag else "",
                                 ", ".join("%s x%d" % (e or "(none)", n) for e, n in sorted(exts.items(), key=lambda kv: (-kv[1], kv[0]))[:4]))))
    if cl.ext_mismatch:
        cl.evidence.append(Evidence("heuristic", first, "extensions %s normally imply a standard header, "
                                    "but none of these files has one" % ", ".join(sorted(cl.ext_mismatch))))
    p = cl.payload
    n_all = count or cl.count
    if p.get("size_field"):
        cl.evidence.append(Evidence("heuristic", first, "bytes %d..%d hold the file size in %d%% of the %s probed files "
                                    "(self-describing header)" % (p["size_field"]["offset"], p["size_field"]["offset"] + 4,
                                                                 round(p["size_field"]["fraction"] * 100),
                                                                 sampled if sampled else n_all)))
    if p.get("standard_after_header"):
        cl.evidence.append(Evidence("heuristic", first, "after a %d-byte header the content is %s "
                                    "(%d of %d probes)" % (p["header_len"], p["standard_after_header"],
                                                           p["agree"], p["probed"])))
        cl.verdict, cl.confidence = "custom_format", 0.7
    elif p.get("compression"):
        cl.evidence.append(Evidence("heuristic", first, "after a %d-byte header the content looks like %s "
                                    "compression" % (p["header_len"], p["compression"])))
        cl.verdict, cl.confidence = "custom_format", 0.65
    elif p.get("entropy") is not None and p["entropy"] >= 7.0:
        cl.evidence.append(Evidence("heuristic", first, "payload after the header has high entropy (%.2f); "
                                    "compression and encryption cannot be told apart from entropy" % p["entropy"]))
        cl.verdict, cl.confidence = "custom_format", 0.5
    else:
        cl.verdict, cl.confidence = "custom_format", 0.4
    if p.get("size_field") and tag:
        cl.confidence = max(cl.confidence, 0.65)
    cl.confidence = min(cl.confidence, MAX_CONFIDENCE)
    return True


def _cluster_size_field(rows: Sequence[Tuple[str, int, str]], head_of: Dict[str, bytes]) -> Optional[Dict[str, Any]]:
    """Header word (offset 4, 8 or 12, little endian) that equals the file size for most members."""
    best: Optional[Dict[str, Any]] = None
    for off in (4, 8, 12):
        ok = tot = 0
        for p, size, _e in rows:
            h = head_of.get(p, b"")
            if len(h) < off + 4:
                continue
            tot += 1
            v = struct.unpack_from("<I", h, off)[0]
            if v in (size, size - 4, size - 8, size - 16):
                ok += 1
        if tot and ok / tot >= 0.9 and (best is None or ok / tot > best["fraction"]):
            best = {"offset": off, "fraction": round(ok / tot, 3), "probed": tot}
    return best


def _probe_payload(rows: Sequence[Tuple[str, int, str]], read_head: Callable[[str, int], bytes]) -> Dict[str, Any]:
    probes = [r for r in rows if r[1] >= 48][:CLUSTER_PROBES]
    data: List[bytes] = []
    for p, _s, _e in probes:
        try:
            data.append(read_head(p, 4096))
        except (KeyError, OSError, ValueError):
            continue
    result: Dict[str, Any] = {"probed": len(data)}
    if not data:
        return result
    best: Optional[Tuple[int, int, str]] = None
    comp_best: Optional[Tuple[int, int, str]] = None
    for hl in PAYLOAD_HEADER_SIZES:
        magics: Counter = Counter()
        comps: Counter = Counter()
        for d in data:
            body = d[hl:hl + 512]
            m, conf = sniff_magic(body) if body else ("unknown", 0.0)
            if m not in ("unknown", "empty", "text") and conf >= 0.6:
                magics[m] += 1
            elif m in ("json",) and conf >= 0.6:
                magics[m] += 1
            g = sniff_compression(body)
            if g.kind != "none" and g.confidence >= 0.6:
                comps[g.kind] += 1
        if magics:
            m, n = magics.most_common(1)[0]
            if best is None or n > best[0]:
                best = (n, hl, m)
        if comps:
            m, n = comps.most_common(1)[0]
            if comp_best is None or n > comp_best[0]:
                comp_best = (n, hl, m)
    half = max(1, len(data) // 2)
    if best and best[0] >= half:
        result.update({"standard_after_header": best[2], "header_len": best[1], "agree": best[0]})
    elif comp_best and comp_best[0] >= half:
        result.update({"compression": comp_best[2], "header_len": comp_best[1], "agree": comp_best[0]})
    body = b"".join(d[16:] for d in data)
    if body:
        result["entropy"] = round(shannon(body), 3)
        result.setdefault("header_len", 16)
    return result
