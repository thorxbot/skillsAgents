"""Scan the identifier pool of ``global-metadata.dat`` for hot-update frameworks (no dumper needed).

IL2CPP metadata keeps type, namespace, method and assembly names as NUL-separated strings in one
region of the file.  When the metadata is not encrypted this region can be streamed and matched
against ``data/hotfix.json`` without running Il2CppDumper, and it is unaffected by FairPlay (the
metadata is an ordinary file).  The region comes from the ``engine.unity`` stage
(``metadata.string_region``); because its header layout is version specific, the region is checked
for plausibility and, when it does not look like an identifier pool, located again here with a
version-agnostic heuristic (a header ``(offset, size)`` pair whose bytes are NUL-separated identifiers).

Nothing is decrypted: when the metadata verdict is ``yes`` / ``suspected`` the scan is skipped and the
caller degrades to other evidence.
"""
from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Dict, Iterator, List, Optional, Tuple

from .detect import HotfixRules, Observation

log = logging.getLogger(__name__)

__all__ = ["MetadataScan", "scan_metadata", "locate_string_pool", "iter_pool_tokens", "pool_looks_valid"]

MAX_REGION = 256 * 1024 * 1024
_CHUNK = 4 * 1024 * 1024
_ANCHORS = (b"mscorlib", b"Assembly-CSharp", b"<Module>", b"UnityEngine", b"System")
_IDENT = re.compile(rb"^[\x20-\x7e]{1,300}$")
_MAX_TOKEN = 300
_MAX_ASSEMBLIES = 400
_MAX_HINTS = 20


@dataclass
class MetadataScan:
    ran: bool = False
    skipped_reason: Optional[str] = None
    region_source: str = "none"      # stage | locator | none
    region: Optional[Dict[str, int]] = None
    tokens: int = 0
    observations: List[Observation] = field(default_factory=list)
    assemblies: List[str] = field(default_factory=list)
    protection_hints: List[Dict[str, str]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"ran": self.ran, "skipped_reason": self.skipped_reason, "region_source": self.region_source,
                "region": self.region, "tokens": self.tokens, "assemblies_seen": len(self.assemblies),
                "notes": list(self.notes)}


def pool_looks_valid(sample: bytes) -> bool:
    """True if ``sample`` looks like a NUL-separated identifier pool (readable, many separators)."""
    if len(sample) < 256:
        return False
    printable = sum(1 for b in sample if 0x20 <= b < 0x7F or b in (0, 9, 10, 13))
    if printable / len(sample) < 0.97:
        return False
    nuls = sample.count(0)
    if nuls * 40 < len(sample):          # at least one separator per 40 bytes on average
        return False
    toks = [t for t in sample.split(b"\0") if t]
    if not toks:
        return False
    good = sum(1 for t in toks if _IDENT.match(t))
    return good / len(toks) >= 0.9


def _read_at(fobj: BinaryIO, offset: int, n: int) -> bytes:
    fobj.seek(offset)
    return fobj.read(n)


def locate_string_pool(fobj: BinaryIO, size: int, *, header_bytes: int = 512) -> Optional[Dict[str, int]]:
    """Find the identifier pool using header ``(offset, size)`` pairs; layout independent.

    Considers every aligned pair of consecutive header words, keeps the ones that lie inside the file,
    start after the header and look like an identifier pool at their start and in the middle, and
    returns the largest.  Returns ``None`` when nothing plausible exists (e.g. encrypted metadata).
    """
    head = _read_at(fobj, 0, header_bytes)
    n = len(head) // 4
    words = struct.unpack_from("<%dI" % n, head, 0) if n else ()
    best: Optional[Tuple[int, int]] = None
    for i in range(2, max(2, n - 1)):
        off, ln = words[i], words[i + 1]
        if ln < 1024 or off < 64 or off + ln > size or ln > MAX_REGION:
            continue
        if not pool_looks_valid(_read_at(fobj, off, 4096)):
            continue
        mid = off + ln // 2
        if not pool_looks_valid(_read_at(fobj, mid, min(4096, off + ln - mid))):
            continue
        if best is None or ln > best[1]:
            best = (off, ln)
    return {"offset": best[0], "size": best[1]} if best else None


def iter_pool_tokens(fobj: BinaryIO, offset: int, length: int, *, chunk: int = _CHUNK) -> Iterator[bytes]:
    """Yield the NUL-separated tokens of ``[offset, offset+length)`` with bounded memory."""
    pos, end = offset, offset + length
    carry = b""
    while pos < end:
        fobj.seek(pos)
        buf = fobj.read(min(chunk, end - pos))
        if not buf:
            break
        pos += len(buf)
        buf = carry + buf
        parts = buf.split(b"\0")
        carry = parts.pop()
        if len(carry) > _MAX_TOKEN * 4:     # no separator in a very long run: drop it, bound the memory
            carry = b""
        for t in parts:
            if t:
                yield t
    if carry:
        yield carry


def _decode(tok: bytes) -> Optional[str]:
    if len(tok) > _MAX_TOKEN:
        return None
    try:
        return tok.decode("ascii")
    except UnicodeDecodeError:
        return None


def scan_metadata(fobj: BinaryIO, size: int, rules: HotfixRules, *, ref: str,
                  region: Optional[Dict[str, int]] = None, verdict: Optional[str] = None,
                  header_ok: Optional[bool] = None) -> MetadataScan:
    """Match the identifier pool of an (unencrypted) metadata file against ``rules``."""
    res = MetadataScan()
    if verdict in ("yes", "suspected"):
        res.skipped_reason = "metadata verdict is %s: identifier pool not trusted/readable" % verdict
        res.notes.append("metadata_strings skipped (degraded to native symbols and file clues)")
        return res
    chosen: Optional[Dict[str, int]] = None
    if region and isinstance(region.get("offset"), int) and isinstance(region.get("size"), int):
        off, ln = region["offset"], region["size"]
        if 0 <= off and 0 < ln <= MAX_REGION and off + ln <= size:
            if pool_looks_valid(_read_at(fobj, off, 4096)) and pool_looks_valid(
                    _read_at(fobj, off + ln // 2, min(4096, off + ln - (off + ln // 2)))):
                chosen = {"offset": off, "size": ln}
                res.region_source = "stage"
            else:
                res.notes.append("string_region from engine.unity does not look like an identifier pool; re-locating")
    if chosen is None:
        chosen = locate_string_pool(fobj, size)
        if chosen is not None:
            res.region_source = "locator"
    if chosen is None:
        res.skipped_reason = "no readable identifier pool found in metadata"
        return res
    res.region = chosen
    res.ran = True

    hits: Dict[Tuple[str, str, str], Observation] = {}
    pool_counts: Dict[str, int] = {}
    assemblies = set()
    anchors = set()
    hint_seen = set()
    for raw in iter_pool_tokens(fobj, chosen["offset"], chosen["size"]):
        res.tokens += 1
        tok = _decode(raw)
        if tok is None:
            continue
        if raw in _ANCHORS:
            anchors.add(tok)
        if tok.endswith(".dll") and len(assemblies) < _MAX_ASSEMBLIES:
            assemblies.add(tok)
        if len(tok) >= 3:
            for sig, how in rules.match_token(tok):
                key = (sig.framework, how, sig.value)
                if key not in hits:
                    hits[key] = Observation(sig.framework, "metadata", how, sig.value, sig.weight, ref=ref,
                                            detail="identifier %r" % tok, strong=sig.strong,
                                            unverified=sig.unverified, tag=sig.tag)
            for sig in rules.pool_signals:
                if sig.compiled is not None and len(tok) <= 80 and sig.compiled.search(tok):
                    cnt = pool_counts.get(sig.framework, 0)
                    if cnt < (sig.max_matches or 12):
                        pool_counts[sig.framework] = cnt + 1
                        hits[(sig.framework, "pool_regex", tok)] = Observation(
                            sig.framework, "metadata", "pool_regex", tok, sig.weight, ref=ref,
                            detail="identifier %r" % tok, unverified=sig.unverified)
            for h in rules.protection_hints:
                if len(res.protection_hints) < _MAX_HINTS and (h["id"], tok) not in hint_seen and \
                        h["compiled"].search(tok):
                    hint_seen.add((h["id"], tok))
                    res.protection_hints.append({"id": h["id"], "target": h.get("target", ""), "identifier": tok})
    res.observations = list(hits.values())
    res.assemblies = sorted(assemblies)
    if not anchors:
        res.notes.append("pool contains none of the usual anchors (mscorlib/UnityEngine/...): treat results with care")
    return res
