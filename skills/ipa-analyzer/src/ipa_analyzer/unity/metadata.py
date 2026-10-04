"""``global-metadata.dat`` analysis: header layout, self-consistency, entropy, string readability, verdict.

Everything here is heuristic evidence gathering.  Nothing is decrypted or repaired; an XOR key that
makes the header or string table look sane is only recorded as a *hypothesis*.

Header facts and where they were verified (2026-10-04):

* Magic ``0xFAB11BAF`` (bytes ``AF 1B B1 FA``) then ``int32 version`` -- Il2CppDumper ``Metadata.cs`` /
  ``MetadataClass.cs`` (github.com/Perfare/Il2CppDumper, master) and Il2CppInspectorRedux
  ``Il2CppGlobalMetadataHeader.cs``.
* Legacy layout (versions <= 35): a run of ``(int32 offset, int32 size)`` pairs after the version, in the
  order and with the per-version presence rules of Il2CppDumper's ``Il2CppGlobalMetadataHeader`` (the
  ``[Version(Min, Max)]`` attributes; sub-versions such as 24.1 or 27.2 are not stored in the file, so
  the right variant is chosen by comparing the computed header size with the first section offset).
  VERIFIED on a real v31 sample: 31 pairs, header size 256 == first section offset, sections contiguous,
  last section ends exactly at the file end.
* New layout (versions >= 38): a run of ``(int32 offset, int32 size, int32 count)`` triples
  (Il2CppInspectorRedux ``Il2CppSectionMetadata``).  VERIFIED on a real v39 sample: 31 triples, header size
  380 == first section offset.  Section lists for versions >= 104 come from the same source only and were
  not seen in a real file (UNVERIFIED).
* The string table (identifiers: type / method / namespace names, NUL separated) is the third section in
  both layouts.

The accepted version range comes from ``data/il2cpp_backends.json`` (union over all backends): a version
the dumpers cannot handle is *not* evidence of encryption; only a version outside every backend's range is.
"""
from __future__ import annotations

import io
import logging
import struct
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Dict, List, Optional, Tuple

from ..util.entropy import sampled_entropy, shannon

log = logging.getLogger(__name__)

__all__ = [
    "MAGIC", "MAGIC_BYTES", "HIGH_ENTROPY", "MetadataAnalysis", "HeaderCheck", "analyze_metadata",
    "check_header", "header_layout", "backend_support", "version_range", "string_region_info",
    "assess_string_region", "xor_string_hypotheses", "xor_header_hypothesis",
]

MAGIC = 0xFAB11BAF
MAGIC_BYTES = struct.pack("<I", MAGIC)
HIGH_ENTROPY = 7.5            # bits/byte; plain metadata measured 4.7-5.9 on real v31/v39 samples
LOW_ENTROPY = 7.0
MAX_STRING_REGION_READ = 8 * 1024 * 1024
STRING_MARKERS = (b"mscorlib", b"System", b"UnityEngine", b"Assembly-CSharp", b"<Module>")
_PREFIX_SEARCH = 4096

# --- legacy layout: (name, min_version, max_version) as in Il2CppDumper's Il2CppGlobalMetadataHeader ------
_INF = 10 ** 6
_LEGACY: Tuple[Tuple[str, float, float], ...] = (
    ("stringLiteral", 0, _INF), ("stringLiteralData", 0, _INF), ("string", 0, _INF), ("events", 0, _INF),
    ("properties", 0, _INF), ("methods", 0, _INF), ("parameterDefaultValues", 0, _INF),
    ("fieldDefaultValues", 0, _INF), ("fieldAndParameterDefaultValueData", 0, _INF),
    ("fieldMarshaledSizes", 0, _INF), ("parameters", 0, _INF), ("fields", 0, _INF),
    ("genericParameters", 0, _INF), ("genericParameterConstraints", 0, _INF), ("genericContainers", 0, _INF),
    ("nestedTypes", 0, _INF), ("interfaces", 0, _INF), ("vtableMethods", 0, _INF),
    ("interfaceOffsets", 0, _INF), ("typeDefinitions", 0, _INF),
    ("rgctxEntries", 0, 24.1),
    ("images", 0, _INF), ("assemblies", 0, _INF),
    ("metadataUsageLists", 19, 24.5), ("metadataUsagePairs", 19, 24.5),
    ("fieldRefs", 19, _INF), ("referencedAssemblies", 20, _INF),
    ("attributesInfo", 21, 27.2), ("attributeTypes", 21, 27.2),
    ("attributeData", 29, _INF), ("attributeDataRange", 29, _INF),
    ("unresolvedVirtualCallParameterTypes", 22, _INF), ("unresolvedVirtualCallParameterRanges", 22, _INF),
    ("windowsRuntimeTypeNames", 23, _INF), ("windowsRuntimeStrings", 27, _INF),
    ("exportedTypeDefinitions", 24, _INF),
)
LEGACY_MIN, LEGACY_MAX = 16, 35
NEW_MIN = 38
# Stored versions that hide several sub-versions with different header layouts.
_SUBVERSIONS: Dict[int, Tuple[float, ...]] = {
    24: (24.0, 24.1, 24.2, 24.3, 24.4, 24.5),
    27: (27.0, 27.1, 27.2),
}

# --- new layout (>= 38): Il2CppInspectorRedux Il2CppGlobalMetadataHeader section order ----------------------
_NEW_BASE = (
    "stringLiterals", "stringLiteralData", "strings", "events", "properties", "methods", "parameterDefaultValues",
    "fieldDefaultValues", "fieldAndParameterDefaultValueData", "fieldMarshaledSizes", "parameters", "fields",
    "genericParameters", "genericParameterConstraints", "genericContainers", "nestedTypes", "interfaces",
    "vtableMethods", "interfaceOffsets", "typeDefinitions",
)
_NEW_TAIL = (
    "images", "assemblies", "fieldRefs", "referencedAssemblies", "attributeData", "attributeDataRanges",
    "unresolvedIndirectCallParameterTypes", "unresolvedIndirectCallParameterRanges", "windowsRuntimeTypeNames",
    "windowsRuntimeStrings", "exportedTypeDefinitions",
)
_NEW_108 = (
    "methodSpecsOnGenericType", "genericMethodSpecsOnType", "methodSpecs", "genericMethodFunctionsDefinitions",
    "genericMethodFunctionsDefinitionsWithAdjustor", "invokerIndices", "rgctxRanges", "rgctxValues",
    "staticConstructorTypeIndices",
)
_NEW_110 = ("generatedMethodTypeInfos", "generatedMethodTokens")


@dataclass
class HeaderLayout:
    kind: str                      # "legacy" | "new"
    names: Tuple[str, ...]
    entry_size: int                # bytes per section descriptor (8 or 12)
    string_index: int
    verified: bool                 # seen on a real sample / confirmed against two sources

    @property
    def header_size(self) -> int:
        return 8 + self.entry_size * len(self.names)


def header_layouts(version: int) -> List[HeaderLayout]:
    """Candidate layouts for a stored version (several for 24 and 27); empty when the layout is unknown."""
    if LEGACY_MIN <= version <= LEGACY_MAX:
        out: List[HeaderLayout] = []
        seen: set = set()
        for sub in _SUBVERSIONS.get(version, (float(version),)):
            names = tuple(n for n, lo, hi in _LEGACY if lo <= sub <= hi)
            if names in seen:
                continue
            seen.add(names)
            out.append(HeaderLayout("legacy", names, 8, 2, version in (31,)))
        return out
    if version >= NEW_MIN and version <= 110:
        names = list(_NEW_BASE)
        if version >= 104:
            names.append("typeInlineArrays")
        names.extend(_NEW_TAIL)
        if version >= 108:
            names.extend(_NEW_108)
        if version >= 110:
            names.extend(_NEW_110)
        return [HeaderLayout("new", tuple(names), 12, 2, version == 39)]
    return []


def header_layout(version: int, first_offset: Optional[int] = None) -> Optional[HeaderLayout]:
    """Best layout for ``version``; with ``first_offset`` prefers the variant whose header size matches it."""
    cands = header_layouts(version)
    if not cands:
        return None
    if first_offset is not None:
        exact = [c for c in cands if c.header_size == first_offset]
        if exact:
            return exact[-1]
        below = [c for c in cands if c.header_size <= first_offset]
        if below:
            return max(below, key=lambda c: c.header_size)
    return cands[-1]


# --- backend version support (data/il2cpp_backends.json) ----------------------------------------------------
def _catalog() -> Dict[str, Any]:
    try:
        from ..il2cpp.tools import load_catalog
        return load_catalog()
    except Exception:  # noqa: BLE001 - the catalog is optional evidence
        log.debug("backend catalog unavailable", exc_info=True)
        return {}


def backend_support(version: Optional[int], catalog: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Which dump backends accept ``version`` according to the catalog's ``metadata_versions`` ranges."""
    cat = catalog if catalog is not None else _catalog()
    supported: List[str] = []
    needs_unity: List[str] = []
    lo_all: Optional[int] = None
    hi_all: Optional[int] = None
    for name, spec in (cat.get("backends") or {}).items():
        mv = spec.get("metadata_versions") or {}
        if "min" not in mv or "max" not in mv:
            continue
        lo, hi = int(mv["min"]), int(mv["max"])
        lo_all = lo if lo_all is None else min(lo_all, lo)
        hi_all = hi if hi_all is None else max(hi_all, hi)
        if version is not None and lo <= version <= hi:
            supported.append(name)
            if spec.get("requires_unity_version"):
                needs_unity.append(name)
    return {"supported_by": supported, "needs_unity_version": needs_unity,
            "range": [lo_all, hi_all] if lo_all is not None else None,
            "known": bool(supported) if lo_all is not None else None}


def version_range(catalog: Optional[Dict[str, Any]] = None) -> Optional[Tuple[int, int]]:
    r = backend_support(None, catalog)["range"]
    return (r[0], r[1]) if r else None


# --- header check ---------------------------------------------------------------------------------------
@dataclass
class HeaderCheck:
    ok: Optional[bool]                     # None: layout unknown, cannot decide
    layout: str = ""                       # "legacy" | "new" | ""
    header_size: int = 0
    sections: List[Dict[str, Any]] = field(default_factory=list)
    decisive: List[str] = field(default_factory=list)
    soft: List[str] = field(default_factory=list)
    string_region: Optional[Dict[str, int]] = None
    verified_layout: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {"ok": self.ok, "layout": self.layout, "header_size": self.header_size,
                "sections": len(self.sections), "decisive": list(self.decisive), "soft": list(self.soft),
                "verified_layout": self.verified_layout}


def check_header(head: bytes, file_size: int, version: int, *, base: int = 0) -> HeaderCheck:
    """Validate the section table in ``head`` (bytes starting at the metadata start) against ``file_size``.

    ``base`` is the metadata start inside the larger file (offset-prefix hypothesis); ``file_size`` is the
    size of the metadata proper (``len(file) - base``).  Decisive problems make ``ok`` False; soft ones
    (order, alignment, trailing gap) are only reported.
    """
    first = None
    if len(head) >= 12:
        first = struct.unpack_from("<i", head, 8)[0]
    layout = header_layout(version, first)
    if layout is None:
        return HeaderCheck(None)
    hs = layout.header_size
    res = HeaderCheck(None, layout.kind, hs, verified_layout=layout.verified)
    if file_size < hs or len(head) < hs:
        res.ok = False
        res.decisive.append("file_shorter_than_header")
        return res
    es = layout.entry_size
    secs: List[Dict[str, Any]] = []
    for i, name in enumerate(layout.names):
        pos = 8 + i * es
        off, size = struct.unpack_from("<ii", head, pos)
        count = struct.unpack_from("<i", head, pos + 8)[0] if es == 12 else None
        secs.append({"name": name, "offset": off, "size": size, "count": count})
    res.sections = secs
    if secs[0]["offset"] < hs:
        res.decisive.append("first_section_inside_header")
    elif secs[0]["offset"] > hs + 64:
        res.soft.append("gap_after_header")
    nonzero: List[Tuple[int, int, str]] = []
    for s in secs:
        off, size = s["offset"], s["size"]
        if off < 0 or size < 0 or (s["count"] is not None and s["count"] < 0):
            res.decisive.append("negative_field:%s" % s["name"])
            continue
        if off > file_size or off + size > file_size:
            res.decisive.append("out_of_file:%s" % s["name"])
            continue
        if size > 0:
            nonzero.append((off, size, s["name"]))
            if off < hs:
                res.decisive.append("inside_header:%s" % s["name"])
    nonzero.sort()
    for (o1, s1, n1), (o2, _s2, n2) in zip(nonzero, nonzero[1:]):
        if o1 + s1 > o2:
            res.decisive.append("overlap:%s/%s" % (n1, n2))
            break
    offs = [s["offset"] for s in secs if s["size"] > 0]
    if any(b < a for a, b in zip(offs, offs[1:])):
        res.soft.append("sections_not_monotonic")
    if offs and sum(1 for o in offs if o % 4) > max(1, len(offs) // 10):
        res.soft.append("unaligned_offsets")
    if nonzero:
        tail = file_size - max(o + s for o, s, _n in nonzero)
        if tail > 4096:
            res.soft.append("large_tail_gap")
    sr = next((s for s in secs if s["name"] == layout.names[layout.string_index]), None)
    if sr is not None and sr["size"] >= 0:
        res.string_region = {"offset": base + sr["offset"], "size": sr["size"]}
    res.ok = not res.decisive
    return res


# --- string region ----------------------------------------------------------------------------------------
def _token_stats(region: bytes) -> Tuple[int, int]:
    toks = [t for t in region.split(b"\x00") if t]
    good = 0
    for t in toks:
        if all(32 <= c < 127 for c in t):
            good += 1
            continue
        try:
            s = t.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if all(ch.isprintable() for ch in s):
            good += 1
    return good, len(toks)


def assess_string_region(region: bytes) -> Dict[str, Any]:
    """Readability of a string-table sample: share of printable NUL-separated tokens and known markers."""
    if not region:
        return {"readable": False, "token_ratio": 0.0, "tokens": 0, "markers": [], "sample_bytes": 0}
    good, total = _token_stats(region)
    ratio = good / total if total else 0.0
    markers = [m.decode("ascii") for m in STRING_MARKERS if m in region]
    return {"readable": bool(total >= 8 and ratio >= 0.85 and markers), "token_ratio": round(ratio, 4),
            "tokens": total, "markers": markers, "sample_bytes": len(region)}


def string_region_info(fileobj: BinaryIO, region: Dict[str, int]) -> bytes:
    n = max(0, min(region["size"], MAX_STRING_REGION_READ))
    fileobj.seek(region["offset"])
    return fileobj.read(n)


def xor_string_hypotheses(region: bytes, limit: int = 3) -> List[Dict[str, Any]]:
    """Single-byte XOR keys that turn an unreadable string-table sample into readable identifiers (hypothesis)."""
    sample = region[:65536]
    out: List[Dict[str, Any]] = []
    if not sample:
        return out
    for key in range(1, 256):
        dec = bytes(b ^ key for b in sample)
        a = assess_string_region(dec)
        if a["readable"]:
            out.append({"key": key, "token_ratio": a["token_ratio"], "markers": a["markers"]})
            if len(out) >= limit:
                break
    return out


def xor_header_hypothesis(head: bytes, file_size: int, catalog: Optional[Dict[str, Any]] = None
                          ) -> Optional[Dict[str, Any]]:
    """If the first 4 bytes XOR the magic give a key under which the header validates, report it."""
    if len(head) < 12:
        return None
    key4 = bytes(a ^ b for a, b in zip(head[:4], MAGIC_BYTES))
    if not any(key4):
        return None
    period = 4
    for p in (1, 2):
        if all(key4[i] == key4[i % p] for i in range(4)):
            period = p
            break
    key = key4[:period]
    dec = bytes(c ^ key[i % period] for i, c in enumerate(head))
    ver = struct.unpack_from("<i", dec, 4)[0]
    if not (LEGACY_MIN <= ver <= 110):
        return None
    hc = check_header(dec, file_size, ver)
    if hc.ok is not True:
        return None
    return {"key_hex": key.hex(), "period": period, "version": ver}


def identifier_stats(region: bytes, max_tokens: int = 300000) -> Dict[str, Any]:
    """Obfuscation hints from the identifier table: share of 1-2 character names and of non-ASCII names.

    Heuristic only (compiler-generated names such as ``.ctor`` or ``<Module>`` are excluded).  Levels use
    the same idea as the dump-based score but are calibrated on two real samples only (UNVERIFIED).
    """
    toks = [t for t in region.split(b"\x00") if t][:max_tokens]
    toks = [t for t in toks if not t.startswith((b".", b"<", b"get_", b"set_", b"op_"))]
    n = len(toks)
    if n < 50:
        return {"tokens": n, "level": "unknown", "short_ratio": 0.0, "non_ascii_ratio": 0.0}
    short = sum(1 for t in toks if len(t) <= 2)
    non_ascii = sum(1 for t in toks if any(c >= 128 for c in t))
    sr, nr = short / n, non_ascii / n
    worst = max(sr, nr)
    level = "high" if worst >= 0.35 else "medium" if worst >= 0.15 else "low" if worst >= 0.05 else "none"
    return {"tokens": n, "level": level, "short_ratio": round(sr, 4), "non_ascii_ratio": round(nr, 4)}


__all__.append("identifier_stats")


# --- analysis ------------------------------------------------------------------------------------------
@dataclass
class MetadataAnalysis:
    size: int
    magic_ok: bool = False
    version: Optional[int] = None
    version_known: Optional[bool] = None
    supported_by: List[str] = field(default_factory=list)
    needs_unity_version: List[str] = field(default_factory=list)
    header: Optional[HeaderCheck] = None
    entropy: Optional[float] = None
    string_region: Optional[Dict[str, int]] = None
    string_assessment: Optional[Dict[str, Any]] = None
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    verdict: str = "unknown"
    confidence: float = 0.0

    @property
    def header_ok(self) -> Optional[bool]:
        return self.header.ok if self.header is not None else None

    @property
    def string_region_ok(self) -> Optional[bool]:
        return bool(self.string_assessment["readable"]) if self.string_assessment else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "size": self.size, "magic_ok": self.magic_ok, "version": self.version,
            "version_known": self.version_known, "supported_by": list(self.supported_by),
            "needs_unity_version": list(self.needs_unity_version),
            "header": self.header.to_dict() if self.header else None,
            "entropy": self.entropy, "string_region": self.string_region,
            "string_assessment": self.string_assessment, "hypotheses": list(self.hypotheses),
            "reasons": list(self.reasons), "verdict": self.verdict, "confidence": self.confidence,
        }


def _find_prefixed_magic(head: bytes) -> Optional[int]:
    idx = head.find(MAGIC_BYTES, 1, _PREFIX_SEARCH + 4)
    return idx if idx > 0 else None


def analyze_metadata(fileobj: BinaryIO, size: int, *, catalog: Optional[Dict[str, Any]] = None) -> MetadataAnalysis:
    """Analyse an opened ``global-metadata.dat`` (seekable ``fileobj`` of ``size`` bytes)."""
    res = MetadataAnalysis(size=size)
    fileobj.seek(0)
    head = fileobj.read(min(size, _PREFIX_SEARCH + 512))
    if size < 16 or len(head) < 16:
        res.reasons.append("empty_or_short")
        res.verdict, res.confidence = "suspected", 0.5
        return res
    try:
        res.entropy = round(sampled_entropy(fileobj, size), 3)
    except (OSError, ValueError):
        res.entropy = round(shannon(head), 3)
    magic, version = struct.unpack_from("<Ii", head, 0)
    res.magic_ok = magic == MAGIC

    if res.magic_ok:
        _analyze_with_magic(fileobj, size, head, version, res, catalog)
    else:
        _analyze_wrong_magic(fileobj, size, head, res, catalog)
    return res


def _fill_version(res: MetadataAnalysis, version: int, catalog: Optional[Dict[str, Any]]) -> None:
    res.version = version
    sup = backend_support(version, catalog)
    res.supported_by = sup["supported_by"]
    res.needs_unity_version = sup["needs_unity_version"]
    res.version_known = sup["known"]


def _analyze_with_magic(fileobj: BinaryIO, size: int, head: bytes, version: int, res: MetadataAnalysis,
                        catalog: Optional[Dict[str, Any]]) -> None:
    _fill_version(res, version, catalog)
    res.reasons.append("magic_ok")
    if res.version_known is False:
        res.reasons.append("version_out_of_range")
    hc = check_header(head, size, version)
    res.header = hc
    if hc.ok is None:
        res.reasons.append("layout_unknown")
    elif hc.ok is False:
        res.reasons.append("header_inconsistent")
    region = hc.string_region
    if region is not None and region["size"] > 0 and region["offset"] + region["size"] <= size:
        res.string_region = region
        sample = string_region_info(fileobj, region)
        res.string_assessment = assess_string_region(sample)
        if not res.string_assessment["readable"]:
            res.reasons.append("string_region_unreadable")
            res.hypotheses.extend({"type": "xor_string_region", **h} for h in xor_string_hypotheses(sample))
    elif region is not None:
        res.reasons.append("string_region_missing")
    elif hc.ok is None:
        # unknown layout: look for identifier markers in the first chunk after the header instead
        fileobj.seek(0)
        blob = fileobj.read(min(size, MAX_STRING_REGION_READ))
        res.string_assessment = assess_string_region(blob[len(head):] if len(blob) > len(head) else blob)
        if not res.string_assessment["readable"]:
            res.reasons.append("string_region_unreadable")
    if res.entropy is not None and res.entropy >= HIGH_ENTROPY:
        res.reasons.append("high_entropy")

    bad_header = hc.ok is False
    bad_strings = "string_region_unreadable" in res.reasons or "string_region_missing" in res.reasons
    high = "high_entropy" in res.reasons
    if bad_header or bad_strings or high:
        conf = 0.6
        if bad_header:
            conf += 0.15
        if bad_strings:
            conf += 0.1
        if high:
            conf += 0.1
        res.verdict, res.confidence = "suspected", min(conf, 0.9)
    elif res.version_known is False:
        res.verdict, res.confidence = "suspected", 0.45
    else:
        res.verdict = "no"
        res.confidence = 0.9 if (hc.ok is True and hc.verified_layout) else (0.8 if hc.ok is True else 0.65)
        if res.version_known is None:
            res.confidence = min(res.confidence, 0.6)


def _analyze_wrong_magic(fileobj: BinaryIO, size: int, head: bytes, res: MetadataAnalysis,
                         catalog: Optional[Dict[str, Any]]) -> None:
    res.reasons.append("magic_mismatch")
    ent = res.entropy if res.entropy is not None else shannon(head)
    xor = xor_header_hypothesis(head, size, catalog)
    if xor is not None:
        _fill_version(res, xor["version"], catalog)
        res.hypotheses.append({"type": "xor_header", **xor})
        res.reasons.append("xor_header")
        res.verdict, res.confidence = "suspected", 0.85
        return
    idx = _find_prefixed_magic(head)
    if idx is not None:
        ver = struct.unpack_from("<i", head, idx + 4)[0]
        if LEGACY_MIN <= ver <= 110:
            hc = check_header(head[idx:], size - idx, ver, base=idx)
            res.hypotheses.append({"type": "offset_prefix", "offset": idx, "version": ver,
                                   "header_ok": hc.ok})
            _fill_version(res, ver, catalog)
            res.reasons.append("offset_prefix")
            res.verdict, res.confidence = "suspected", 0.8 if hc.ok else 0.6
            return
    ver = struct.unpack_from("<i", head, 4)[0]
    if LEGACY_MIN <= ver <= 110:
        hc = check_header(head, size, ver)
        if hc.ok is True:
            _fill_version(res, ver, catalog)
            res.header = hc
            res.hypotheses.append({"type": "magic_modified", "magic_hex": head[:4].hex(), "version": ver})
            res.reasons.append("magic_modified")
            res.verdict, res.confidence = "suspected", 0.8
            return
    if ent >= HIGH_ENTROPY:
        res.reasons.append("high_entropy")
        res.verdict, res.confidence = "yes", 0.85
        return
    res.reasons.append("wrong_magic_low_entropy")
    res.verdict, res.confidence = "suspected", 0.6


def analyze_metadata_bytes(data: bytes, *, catalog: Optional[Dict[str, Any]] = None) -> MetadataAnalysis:
    """Convenience wrapper for in-memory data (tests, small files)."""
    return analyze_metadata(io.BytesIO(data), len(data), catalog=catalog)


__all__.append("analyze_metadata_bytes")


def evidence_lines(a: MetadataAnalysis) -> List[Tuple[str, str]]:
    """``(kind, detail)`` evidence tuples summarising ``a`` (the stage attaches the file path as ref)."""
    out: List[Tuple[str, str]] = []
    out.append(("heuristic", "magic %s; version %s" % ("0xFAB11BAF" if a.magic_ok else "mismatch", a.version)))
    if a.supported_by:
        out.append(("heuristic", "version %s accepted by backends: %s" % (a.version, ", ".join(a.supported_by))))
    elif a.version is not None and a.version_known is False:
        out.append(("heuristic", "version %s is outside every backend range" % a.version))
    if a.header is not None:
        hc = a.header
        out.append(("heuristic", "header %s layout, %d sections, ok=%s%s" % (
            hc.layout or "unknown", len(hc.sections), hc.ok,
            "; problems: " + ", ".join(hc.decisive[:4]) if hc.decisive else "")))
        if hc.soft:
            out.append(("heuristic", "soft header notes: " + ", ".join(hc.soft)))
    if a.entropy is not None:
        out.append(("heuristic", "sampled entropy %.2f bits/byte" % a.entropy))
    if a.string_assessment is not None:
        sa = a.string_assessment
        out.append(("string", "string table: %d tokens, printable ratio %.2f, markers: %s" % (
            sa["tokens"], sa["token_ratio"], ", ".join(sa["markers"]) or "none")))
    for h in a.hypotheses:
        out.append(("heuristic", "hypothesis: " + ", ".join("%s=%s" % kv for kv in h.items())))
    return out
