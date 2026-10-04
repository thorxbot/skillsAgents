"""Shared building blocks of the engine checkers (WP7b).

* ``checks(section)``      thresholds / file patterns from ``data/engines_checks.json`` (no magic numbers in code)
* ``FileIndex``            read-only view of ``ctx.results["inventory"]`` (falls back to the archive listing)
* ``classify_blob``        header + entropy based classification of one script / resource blob
* ``ScriptTally``          counts + samples per bucket and the verdict derived from them
* ``find_wrapper_clusters``custom 4-byte file headers in front of otherwise standard content
* ``scan_main_binary``     string / symbol hints from the main Mach-O (degrades on FairPlay-encrypted binaries)
* ``make_finding``         Finding with the ``engine:<id>`` tag and an English fallback text

Principles: bytecode is not encryption, compression is not encryption, high entropy alone is not proof.
Nothing is decrypted and no key material is extracted or reported.
"""
from __future__ import annotations

import json
import logging
import re
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Pattern, Sequence, Tuple, Union

from ...models import Evidence, Finding, Verdict
from ...util import magic as _magic
from ...util.entropy import shannon
from ...util.filetypes import load_inventory_files
from ...util.paths import resource_dir
from ...formats import compress_sniff, lua_bytecode

log = logging.getLogger(__name__)

CHECKS_FILE = "engines_checks.json"
_CHECKS: Dict[str, Dict[str, Any]] = {}

# Blob kinds produced by ``classify_blob``.
K_EMPTY = "empty"
K_PLAIN = "plain_text"
K_ENCODED_TEXT = "encoded_text"
K_LUA_BC = "lua_bytecode"
K_LUA_BC_TAMPERED = "lua_bytecode_tampered"
K_LUA_XOR = "lua_xor_suspected"
K_HERMES = "hermes_bytecode"
K_ASSEMBLY = "assembly_pe_cli"
K_COMPRESSED = "compressed"
K_KNOWN = "known_format"
K_CUSTOM_HEADER = "custom_header"
K_HIGH_ENTROPY = "high_entropy"
K_BINARY = "binary_unknown"

#: kind -> reporting bucket
BUCKET = {
    K_EMPTY: "empty", K_PLAIN: "plain", K_ENCODED_TEXT: "suspected_encrypted", K_LUA_BC: "bytecode",
    K_LUA_BC_TAMPERED: "suspected_encrypted", K_LUA_XOR: "suspected_encrypted", K_HERMES: "bytecode",
    K_ASSEMBLY: "bytecode",
    K_COMPRESSED: "compressed", K_KNOWN: "other", K_CUSTOM_HEADER: "suspected_encrypted",
    K_HIGH_ENTROPY: "suspected_encrypted", K_BINARY: "other",
}
BUCKETS = ("plain", "bytecode", "compressed", "suspected_encrypted", "other", "empty")


# --------------------------------------------------------------------------------------- configuration
def load_checks(path: Optional[Path] = None) -> Dict[str, Dict[str, Any]]:
    """Load (and cache) ``data/engines_checks.json``."""
    p = Path(path) if path else resource_dir("data") / CHECKS_FILE
    key = str(p)
    if key not in _CHECKS:
        with open(p, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        _CHECKS[key] = {k: v for k, v in doc.items() if isinstance(v, dict)}
    return _CHECKS[key]


def checks(section: str) -> Dict[str, Any]:
    """Settings of one checker section (``common`` is merged underneath)."""
    allv = load_checks()
    merged = dict(allv.get("common", {}))
    merged.update(allv.get(section, {}))
    return merged


def compile_list(patterns: Iterable[str], flags: int = 0) -> List[Pattern[str]]:
    return [re.compile(p, flags) for p in patterns]


# ------------------------------------------------------------------------------------------- file index
@dataclass
class FileRec:
    path: str                 # archive name
    rel: str                  # relative to the .app root (POSIX)
    size: int
    ext: str                  # lower case, with dot
    magic: str = "unknown"
    category: str = "other"
    entropy: Optional[float] = None


class FileIndex:
    """Files inside the .app (``ctx.results["inventory"]``), with cheap lookups.

    Directory entries are not included.  Files outside the .app (``iTunesMetadata.plist`` ...) are ignored.
    """

    def __init__(self, ctx: Any) -> None:
        self.ctx = ctx
        self.recs: List[FileRec] = []
        self.by_rel: Dict[str, FileRec] = {}
        self._dirs: set = set()
        self.header_clusters: List[Dict[str, Any]] = []
        self.from_inventory = False
        inv = ctx.results.get("inventory") if getattr(ctx, "results", None) is not None else None
        rows: List[Dict[str, Any]] = []
        if isinstance(inv, dict) and inv.get("files") is not None:
            out_dir = None
            try:
                out_dir = ctx.out_dir if ctx.is_bound else None
            except Exception:  # noqa: BLE001
                out_dir = None
            rows = load_inventory_files(inv, out_dir)
            self.from_inventory = True
            self.header_clusters = list(inv.get("header_clusters") or [])
        elif getattr(ctx, "source", None) is not None:
            for e in ctx.source.namelist():
                if not e.is_dir:
                    rows.append({"path": e.name, "size": e.size, "ext": _ext(e.name)})
        for r in rows:
            path = str(r.get("path", ""))
            rel = ctx.rel(path)
            if not rel:
                continue
            rec = FileRec(path=path, rel=rel, size=int(r.get("size") or 0), ext=str(r.get("ext") or _ext(path)),
                          magic=str(r.get("magic") or "unknown"), category=str(r.get("category") or "other"),
                          entropy=r.get("entropy"))
            self.recs.append(rec)
            self.by_rel[rel] = rec
            parts = rel.split("/")
            for i in range(1, len(parts)):
                self._dirs.add("/".join(parts[:i]) + "/")
        self.recs.sort(key=lambda x: x.rel)

    def __len__(self) -> int:
        return len(self.recs)

    def get(self, rel: str) -> Optional[FileRec]:
        return self.by_rel.get(rel)

    def exists(self, rel: str) -> bool:
        return rel in self.by_rel

    def has_dir(self, rel_dir: str) -> bool:
        return (rel_dir if rel_dir.endswith("/") else rel_dir + "/") in self._dirs

    def find(self, pattern: Union[str, Pattern[str]]) -> List[FileRec]:
        rx = re.compile(pattern) if isinstance(pattern, str) else pattern
        return [r for r in self.recs if rx.search(r.rel)]

    def with_ext(self, *exts: str) -> List[FileRec]:
        want = {e.lower() for e in exts}
        return [r for r in self.recs if r.ext in want]

    def with_magic(self, *ids: str) -> List[FileRec]:
        want = set(ids)
        return [r for r in self.recs if r.magic in want]

    def top_dirs(self) -> List[str]:
        return sorted(d for d in self._dirs if d.count("/") == 1)

    def not_vendor(self, recs: Iterable[FileRec], rx: Optional[Pattern[str]] = None) -> List[FileRec]:
        rx = rx or re.compile(checks("common")["vendor_regex"])
        return [r for r in recs if not rx.search(r.rel)]


def _ext(name: str) -> str:
    base = name.rsplit("/", 1)[-1]
    i = base.rfind(".")
    return base[i:].lower() if i > 0 else ""


# ------------------------------------------------------------------------------------------ bounded reads
def read_head(ctx: Any, path: str, n: int) -> bytes:
    """First ``n`` bytes of an archive entry; ``b""`` on any error."""
    try:
        return bytes(ctx.source.read_head(path, n))
    except Exception:  # noqa: BLE001 - unreadable entries are reported as such by the caller
        log.debug("read_head failed for %s", path, exc_info=True)
        return b""


def read_at(ctx: Any, path: str, offset: int, n: int) -> bytes:
    try:
        with ctx.source.open(path) as fh:
            fh.seek(max(offset, 0))
            return bytes(fh.read(n))
    except Exception:  # noqa: BLE001
        log.debug("read_at failed for %s", path, exc_info=True)
        return b""


def read_tail(ctx: Any, path: str, size: int, n: int) -> bytes:
    return read_at(ctx, path, max(size - n, 0), n)


def evenly_sample(items: Sequence[Any], limit: int) -> Tuple[List[Any], int]:
    """Deterministic, evenly spaced sample of at most ``limit`` items; returns ``(sample, total)``."""
    total = len(items)
    if limit <= 0 or total <= limit:
        return list(items), total
    step = total / float(limit)
    return [items[int(i * step)] for i in range(limit)], total


# -------------------------------------------------------------------------------------- classification
def entropy_is_high(entropy: Optional[float], nbytes: int, cfg: Optional[Dict[str, Any]] = None) -> Optional[bool]:
    """Whether ``entropy`` looks like compressed / encrypted data; ``None`` if the sample is too small to say."""
    c = cfg or checks("common")
    if entropy is None or nbytes < c["min_bytes_for_entropy"]:
        return None
    limit = c["entropy_high_min"] if nbytes >= c["entropy_large_sample_bytes"] else c["entropy_high_min_small"]
    return entropy >= limit


@dataclass
class BlobInfo:
    kind: str
    detail: Dict[str, Any] = field(default_factory=dict)
    entropy: Optional[float] = None

    @property
    def bucket(self) -> str:
        return BUCKET.get(self.kind, "other")


_B64_RE = re.compile(rb"[A-Za-z0-9+/=\r\n]+\Z")
_HEX_RE = re.compile(rb"[0-9A-Fa-f\r\n]+\Z")


def looks_like_header_magic(head: bytes) -> Optional[bytes]:
    """The first four bytes if they are all printable ASCII letters / digits (custom container tag), else None."""
    tag = bytes(head[:4])
    if len(tag) == 4 and all(48 <= b <= 57 or 65 <= b <= 90 or 97 <= b <= 122 or b == 95 for b in tag):
        return tag
    return None


def classify_blob(head: bytes, size: int, entropy: Optional[float] = None) -> BlobInfo:
    """Classify the leading bytes of a script-like blob (see module docstring for the principles).

    Order: empty -> Lua bytecode -> Hermes -> text -> compression container -> other known format ->
    Lua-after-XOR -> custom 4-byte tag -> high entropy -> unknown binary.
    """
    head = bytes(head)
    if size == 0 or not head:
        return BlobInfo(K_EMPTY)
    cfg = checks("common")
    if entropy is None and len(head) >= cfg["min_bytes_for_entropy"]:
        entropy = round(shannon(head), 4)
    if head.startswith(lua_bytecode.LUA_SIGNATURE) or head.startswith(lua_bytecode.LUAJIT_SIGNATURE):
        info = lua_bytecode.parse_header(head)
        return BlobInfo(K_LUA_BC if info.valid else K_LUA_BC_TAMPERED, {"lua": info}, entropy)
    if head.startswith(b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f") or head.startswith(bytes(b ^ 0xFF for b in b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f")):
        return BlobInfo(K_HERMES, {}, entropy)
    if _magic.is_texty(head[:1024] if len(head) > 1024 else head):
        body = head.strip()
        if len(body) >= cfg["encoded_text_min_bytes"] and (_B64_RE.match(body) or _HEX_RE.match(body)) \
                and b" " not in body:
            return BlobInfo(K_ENCODED_TEXT, {"alphabet": "hex" if _HEX_RE.match(body) else "base64"}, entropy)
        return BlobInfo(K_PLAIN, {}, entropy)
    guess = compress_sniff.sniff(head)
    if guess.kind != "none" and guess.confidence >= cfg["compress_min_confidence"]:
        return BlobInfo(K_COMPRESSED, {"compression": guess.kind, "confidence": guess.confidence}, entropy)
    mid, mconf = _magic.sniff(head)
    if mid not in ("unknown", "text", "json", "empty") and mconf >= cfg["magic_min_confidence"]:
        return BlobInfo(K_KNOWN, {"magic": mid, "confidence": mconf}, entropy)
    xor = lua_bytecode.looks_like_lua_after_xor(head)
    if xor is not None:
        return BlobInfo(K_LUA_XOR, {"xor_period": len(xor.key), "flavor": xor.flavor, "confidence": xor.confidence},
                        entropy)
    tag = looks_like_header_magic(head)
    if tag is not None:
        return BlobInfo(K_CUSTOM_HEADER, {"tag": tag.decode("ascii")}, entropy)
    if entropy_is_high(entropy, len(head), cfg):
        return BlobInfo(K_HIGH_ENTROPY, {}, entropy)
    return BlobInfo(K_BINARY, {}, entropy)


def classify_file(ctx: Any, rec: FileRec) -> Tuple[BlobInfo, bytes]:
    """Read the head of ``rec`` and classify it; returns ``(info, head)``.  Unreadable files count as ``other``."""
    cfg = checks("common")
    head = read_head(ctx, rec.path, cfg["head_bytes"])
    if rec.size and not head:
        return BlobInfo(K_BINARY, {"unreadable": True}), b""
    return classify_blob(head, rec.size, rec.entropy if rec.entropy is not None else None), head


def classify_resource(ctx: Any, rec: FileRec) -> BlobInfo:
    """Classify a resource file whose extension names a standard format.

    The inventory already identified known formats and text (``magic`` not ``unknown``): those count as plain.  Only
    unidentified files are read: a custom 4-byte tag or high entropy means "suspected encrypted / obfuscated".
    """
    if rec.size == 0:
        return BlobInfo(K_EMPTY)
    if rec.magic not in ("unknown", ""):
        return BlobInfo(K_PLAIN, {"magic": rec.magic}, rec.entropy)
    blob, _ = classify_file(ctx, rec)
    return blob


# ----------------------------------------------------------------------------------------------- tallies
class ScriptTally:
    """Counts, per-extension counts and a few sample paths per blob kind / bucket."""

    def __init__(self, samples_per_kind: Optional[int] = None) -> None:
        self.limit = samples_per_kind if samples_per_kind is not None else checks("common")["max_samples"]
        self.kinds: Counter = Counter()
        self.buckets: Counter = Counter()
        self.by_ext: Dict[str, Counter] = {}
        self.samples: Dict[str, List[str]] = {}
        self.total = 0

    def add(self, rel: str, ext: str, blob: BlobInfo) -> None:
        self.total += 1
        self.kinds[blob.kind] += 1
        self.buckets[blob.bucket] += 1
        self.by_ext.setdefault(ext or "(none)", Counter())[blob.bucket] += 1
        lst = self.samples.setdefault(blob.kind, [])
        if len(lst) < self.limit:
            lst.append(rel)

    def count(self, bucket: str) -> int:
        return self.buckets.get(bucket, 0)

    def to_dict(self, *, sampled: Optional[int] = None, of: Optional[int] = None) -> Dict[str, Any]:
        n = self.total
        out: Dict[str, Any] = {b: self.buckets.get(b, 0) for b in BUCKETS if b != "empty"}
        out["total"] = of if of is not None else n
        out["counts"] = {"by_kind": dict(sorted(self.kinds.items())),
                         "by_ext": {e: dict(sorted(c.items())) for e, c in sorted(self.by_ext.items())},
                         "sampled": n if sampled is None else sampled,
                         "of": n if of is None else of}
        out["samples"] = {k: list(v) for k, v in sorted(self.samples.items())}
        return out


def verdict_from_tally(tally: ScriptTally, total_files: int) -> Tuple[Verdict, float, str]:
    """``(verdict, confidence, state)`` for "are these scripts/resources protected?".

    ``state``: ``none`` (nothing to judge) | ``plain`` | ``compiled`` | ``compressed`` | ``mixed`` |
    ``suspected`` | ``unknown``.  A ``no`` is only returned when every classified file is plain text, bytecode
    or a compression container; sampling lowers the confidence.
    """
    n = tally.total
    if n == 0:
        return Verdict.NA, 0.0, "none"
    plain, bc, comp = tally.count("plain"), tally.count("bytecode"), tally.count("compressed")
    susp, other = tally.count("suspected_encrypted"), tally.count("other")
    judged = plain + bc + comp + susp
    if susp:
        frac = susp / float(max(judged, 1))
        conf = min(0.9, 0.5 + 0.4 * frac)
        return Verdict.SUSPECTED, round(conf, 2), "suspected" if frac >= 0.5 else "mixed"
    if judged == 0:
        return Verdict.UNKNOWN, 0.2, "unknown"
    cover = n / float(max(total_files, n))
    base = 0.85 if other == 0 else 0.7
    conf = round(base * (0.8 + 0.2 * cover), 2)
    if bc and not plain and not comp:
        state = "compiled"
    elif comp and not plain and not bc:
        state = "compressed"
    elif plain and not bc and not comp:
        state = "plain"
    else:
        state = "mixed"
    return Verdict.NO, conf, state


# ------------------------------------------------------------------------------------ custom containers
def _u32le(b: bytes, off: int) -> Optional[int]:
    return struct.unpack_from("<I", b, off)[0] if len(b) >= off + 4 else None


def find_wrapper_clusters(ctx: Any, recs: Sequence[FileRec], *, min_files: Optional[int] = None,
                          structured_exts: Optional[Sequence[str]] = None,
                          max_probe: Optional[int] = None) -> List[Dict[str, Any]]:
    """Group files by a shared custom 4-byte header although their extension names a standard format.

    A file qualifies when the inventory could not identify its content (``magic`` unknown), its extension is in
    ``structured_exts`` and its first four bytes are printable ASCII.  Per cluster the layout is probed:
    does u32 LE at offset 4 equal the file size, which later offsets are constant, what does the payload look
    like (entropy, compression container / plain text at a fixed offset), and whether a constant single-byte XOR
    relation to a PNG signature exists (reported as a count only, never as key material).
    """
    cfg = checks("common")
    min_files = cfg["wrapper_cluster_min_files"] if min_files is None else min_files
    exts = set(structured_exts if structured_exts is not None else cfg["structured_exts"])
    cand = [r for r in recs if r.ext in exts and r.magic in ("unknown", "") and r.size >= 16]
    sample, total = evenly_sample(cand, max_probe or cfg["wrapper_probe_max_files"])
    groups: Dict[bytes, List[Tuple[FileRec, bytes]]] = {}
    for r in sample:
        h = read_head(ctx, r.path, cfg["wrapper_probe_bytes"])
        tag = looks_like_header_magic(h)
        if tag is not None and not _magic.is_texty(h[:256]):
            groups.setdefault(tag, []).append((r, h))
    scale = total / float(max(len(sample), 1))
    out: List[Dict[str, Any]] = []
    for tag, items in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        if len(items) * scale < min_files:
            continue
        out.append(_describe_cluster(tag, items, scale, cfg))
    return out


def _describe_cluster(tag: bytes, items: List[Tuple[FileRec, bytes]], scale: float, cfg: Dict[str, Any]) -> Dict[str, Any]:
    n = len(items)
    exts: Counter = Counter(r.ext for r, _ in items)
    size_field = None
    for off in (4, 8):
        match = sum(1 for r, h in items if _u32le(h, off) == r.size)
        if match / float(n) >= 0.9:
            size_field = off
            break
    const_offsets = []
    for off in range(4, 32, 4):
        vals = Counter(_u32le(h, off) for _, h in items if _u32le(h, off) is not None)
        if vals and vals.most_common(1)[0][1] / float(n) >= 0.9 and n >= 3:
            const_offsets.append(off)
    ents = [shannon(h[16:]) for _, h in items if len(h) >= 16 + cfg["min_bytes_for_entropy"]]
    payload: Optional[Dict[str, Any]] = None
    for off in cfg["wrapper_payload_offsets"]:
        hits: Counter = Counter()
        for _, h in items:
            seg = h[off:]
            if len(seg) < 8:
                continue
            g = compress_sniff.sniff(seg)
            if g.kind != "none" and g.confidence >= cfg["compress_min_confidence"]:
                hits["compressed:" + g.kind] += 1
            elif _magic.is_texty(seg[:256]):
                hits["plain_text"] += 1
            else:
                mid, mc = _magic.sniff(seg)
                if mid not in ("unknown", "text", "json", "empty") and mc >= cfg["magic_min_confidence"]:
                    hits["format:" + mid] += 1
        if hits:
            kind, cnt = hits.most_common(1)[0]
            if cnt / float(n) >= 0.5:
                payload = {"offset": off, "kind": kind, "share": round(cnt / float(n), 2)}
                break
    xor = _png_xor_relation(items, cfg)
    return {
        "tag": tag.decode("ascii"), "files": int(round(n * scale)), "sampled": n,
        "exts": dict(sorted(exts.items())), "size_field_offset": size_field, "constant_u32_offsets": const_offsets,
        "payload_entropy_mean": round(sum(ents) / len(ents), 2) if ents else None,
        "payload_probe": payload, "xor_relation": xor,
        "examples": [r.rel for r, _ in items[:cfg["max_samples"]]],
    }


def _png_xor_relation(items: List[Tuple[FileRec, bytes]], cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Count wrapped ``.png`` files whose bytes at a fixed offset equal the PNG signature XOR a constant byte."""
    sig = b"\x89PNG\r\n\x1a\n"
    pngs = [h for r, h in items if r.ext == ".png"]
    if not pngs:
        return None
    best: Optional[Dict[str, Any]] = None
    for off in cfg["wrapper_payload_offsets"]:
        cnt = 0
        for h in pngs:
            seg = h[off:off + 8]
            if len(seg) == 8 and len({a ^ b for a, b in zip(seg, sig)}) == 1:
                cnt += 1
        if cnt and (best is None or cnt > best["files"]):
            best = {"offset": off, "files": cnt, "of": len(pngs), "kind": "single_byte_xor_of_png_signature"}
    return best


# ----------------------------------------------------------------------------------------- findings
def make_finding(fid: str, verdict: Verdict, confidence: float, engine_id: str, title: str, summary: str,
                 params: Optional[Dict[str, Any]] = None, evidence: Optional[List[Evidence]] = None,
                 remediation: str = "", extra_tags: Sequence[str] = ()) -> Finding:
    """Finding tagged ``engine:<engine_id>`` with evidence capped at ``max_evidence`` entries."""
    cap = checks("common")["max_evidence"]
    return Finding(id=fid, verdict=verdict, confidence=confidence, title=title, summary=summary,
                   params=dict(params or {}), evidence=list(evidence or [])[:cap], remediation=remediation,
                   tags=["engine:%s" % engine_id] + list(extra_tags))


def file_evidence(rels: Iterable[str], detail: str = "", limit: Optional[int] = None) -> List[Evidence]:
    lim = limit if limit is not None else checks("common")["max_samples"]
    out: List[Evidence] = []
    for r in rels:
        out.append(Evidence("file", r, detail))
        if len(out) >= lim:
            break
    return out


# -------------------------------------------------------------------------------- main binary hints
@dataclass
class BinaryScan:
    """Outcome of ``scan_main_binary``: which hint names matched (with the matching string) and how reliable."""

    status: str = "unavailable"        # scanned | scanned_symbols_only | skipped_encrypted | unavailable | error
    reason: str = ""
    binary: Optional[str] = None
    encrypted: Optional[bool] = None
    strings_scanned: bool = False
    symbols_scanned: bool = False
    hits: Dict[str, List[str]] = field(default_factory=dict)

    def has(self, name: str) -> bool:
        return bool(self.hits.get(name))

    def to_dict(self) -> Dict[str, Any]:
        return {"status": self.status, "reason": self.reason, "binary": self.binary, "encrypted": self.encrypted,
                "strings_scanned": self.strings_scanned, "symbols_scanned": self.symbols_scanned,
                "hits": {k: v[:5] for k, v in sorted(self.hits.items())}}


def main_binary_path(ctx: Any) -> Optional[str]:
    m = ctx.results.get("macho")
    if isinstance(m, dict):
        mb = (m.get("summary") or {}).get("main_binary")
        if mb:
            return str(mb)
    meta = ctx.results.get("meta")
    if isinstance(meta, dict):
        exe = ((meta.get("identity") or {}).get("executable"))
        if exe:
            return ctx.app_path(str(exe))
    return None


def _combined(patterns: Dict[str, str]) -> Pattern[str]:
    return re.compile("|".join("(?P<%s>%s)" % (k, v) for k, v in patterns.items()))


def scan_main_binary(ctx: Any, patterns: Dict[str, str]) -> BinaryScan:
    """``scan_binary`` on the main executable."""
    path = main_binary_path(ctx)
    if not path:
        res = BinaryScan()
        res.reason = "main binary unknown"
        return res
    return scan_binary(ctx, path, patterns)


def scan_binary(ctx: Any, path: str, patterns: Dict[str, str]) -> BinaryScan:
    """Look for ``patterns`` (name -> regex) in C strings and symbol names of the Mach-O at archive name ``path``.

    FairPlay-encrypted ranges hold ciphertext, so C-string sections inside them are skipped (and the result says
    so); the symbol table lives in ``__LINKEDIT`` which is not part of the encrypted range, so it is still read.
    Never raises.
    """
    from ... import macho

    res = BinaryScan()
    res.binary = path
    cfg = checks("common")
    try:
        rec_size = ctx.source.stat(path).size
    except Exception:  # noqa: BLE001
        res.reason = "main binary not found in the archive"
        return res
    if rec_size > cfg["binary_scan_max_mb"] * 1024 * 1024:
        res.status, res.reason = "unavailable", "main binary larger than the scan limit"
        return res
    got = ctx.extract([path])
    local = got.get(path)
    if local is None:
        res.reason = "main binary could not be extracted"
        return res
    rx = _combined(patterns)
    try:
        with macho.parse(local) as mf:
            sl = mf.select_slice()
            if sl is None:
                res.status, res.reason = "unavailable", "no readable Mach-O slice"
                return res
            res.encrypted = bool(sl.is_encrypted)

            def note(text: str) -> None:
                m = rx.search(text)
                if m and m.lastgroup:
                    lst = res.hits.setdefault(m.lastgroup, [])
                    if len(lst) < 5 and text[:160] not in lst:
                        lst.append(text[:160])

            n = 0
            for s in sl.iter_cstrings(min_len=4, skip_encrypted=True):
                note(s)
                n += 1
                if n >= cfg["binary_scan_max_strings"]:
                    break
            res.strings_scanned = not res.encrypted
            n = 0
            for sym in sl.iter_symbols():
                note(sym.name)
                n += 1
                if n >= cfg["binary_scan_max_symbols"]:
                    break
            res.symbols_scanned = True
    except Exception as exc:  # noqa: BLE001 - hostile or odd binary: degrade instead of failing the checker
        res.status, res.reason = "error", "%s: %s" % (type(exc).__name__, exc)
        return res
    if res.encrypted:
        res.status = "skipped_encrypted"
        res.reason = ("main binary is FairPlay-encrypted: C strings are ciphertext and were skipped; only the symbol "
                      "table (outside the encrypted range) was read, so binary-based hints are incomplete")
    else:
        res.status = "scanned"
    return res




# ------------------------------------------------------------------------------ standard finding builders
NO_CAVEAT = "Compiled or compressed content is not encrypted content, and a missing protection marker is not proof of absence."


def _caveat(summary: str, verdict: Verdict) -> str:
    return summary + " " + NO_CAVEAT if verdict == Verdict.NO else summary


_STATE_TEXT = {
    "none": "no files of this kind were found",
    "plain": "all examined files are plain text (minified or not), which is not encrypted",
    "compiled": "all examined files are compiled bytecode; bytecode is not encryption",
    "compressed": "all examined files are in a compression container; compression is not encryption",
    "mixed": "the examined files are a mix of plain text, bytecode / compression containers and files that could not be "
             "identified",
    "suspected": "most examined files are neither plain text, known bytecode nor a known compression container "
                 "(high entropy and / or a custom header); this fits encryption or obfuscation but is not proof",
    "unknown": "the examined files could not be classified",
    "encrypted": "the files use a container that is encrypted by definition",
}


def script_finding(engine_id: str, engine_name: str, tally: Dict[str, Any], verdict: Verdict, confidence: float,
                   state: str, evidence: Sequence[Evidence], note: str = "", remediation: str = "") -> Finding:
    """``engine.script.encrypted`` with the standard parameter set (zh text in ``engine_checkers.json``)."""
    counts = tally.get("counts", {})
    params = {"engine": engine_name, "total": tally.get("total", 0), "plain": tally.get("plain", 0),
              "bytecode": tally.get("bytecode", 0), "compressed": tally.get("compressed", 0),
              "suspected": tally.get("suspected_encrypted", 0), "sampled": counts.get("sampled", 0), "state": state}
    summary = "%s: %d script file(s) (%d examined): %d plain, %d bytecode, %d compressed, %d suspected encrypted or " \
              "obfuscated. %s." % (engine_name, params["total"], params["sampled"], params["plain"], params["bytecode"],
                                   params["compressed"], params["suspected"], _STATE_TEXT.get(state, state))
    if note:
        summary += " " + note
    return make_finding("engine.script.encrypted", verdict, confidence, engine_id,
                        "%s script protection" % engine_name, _caveat(summary, verdict), params, list(evidence),
                        remediation)


def resource_finding(engine_id: str, engine_name: str, tally: Dict[str, Any], verdict: Verdict, confidence: float,
                     state: str, evidence: Sequence[Evidence], note: str = "", encrypted: int = 0,
                     remediation: str = "") -> Finding:
    """``engine.resource.encrypted`` with the standard parameter set."""
    counts = tally.get("counts", {})
    params = {"engine": engine_name, "total": tally.get("total", 0), "plain": tally.get("plain", 0),
              "suspected": tally.get("suspected_encrypted", 0), "encrypted": encrypted,
              "sampled": counts.get("sampled", 0), "state": state}
    summary = "%s: %d resource file(s) examined, %d with a documented encrypted container, %d suspected encrypted or " \
              "obfuscated, %d plain. %s." % (engine_name, params["sampled"], encrypted, params["suspected"],
                                             params["plain"], _STATE_TEXT.get(state, state))
    if note:
        summary += " " + note
    return make_finding("engine.resource.encrypted", verdict, confidence, engine_id,
                        "%s resource protection" % engine_name, _caveat(summary, verdict), params, list(evidence),
                        remediation)


def pak_finding(engine_id: str, engine_name: str, verdict: Verdict, confidence: float, containers: int, encrypted: int,
                unknown: int, evidence: Sequence[Evidence], note: str = "", remediation: str = "") -> Finding:
    """``engine.pak.encrypted`` with the standard parameter set."""
    params = {"engine": engine_name, "containers": containers, "encrypted": encrypted, "unknown": unknown}
    summary = "%s: %d resource container(s) examined, %d with an encryption flag, %d could not be judged." % (
        engine_name, containers, encrypted, unknown)
    if note:
        summary += " " + note
    return make_finding("engine.pak.encrypted", verdict, confidence, engine_id,
                        "%s package encryption" % engine_name, _caveat(summary, verdict), params, list(evidence),
                        remediation)
