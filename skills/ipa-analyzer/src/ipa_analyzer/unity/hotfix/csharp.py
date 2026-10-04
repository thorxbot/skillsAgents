"""C# hot-update assemblies: profile every DLL candidate and tell hot-update from AOT supplemental metadata.

A candidate is a loose ``*.dll`` / ``*.dll.bytes`` file or a PE image found inside an AssetBundle /
SerializedFile.  ``formats.pe_cli`` supplies assembly name, CLR version string, TypeDef count and
AssemblyRef names.  Candidates that are not PE images are split into compressed (magic sniffing),
``encrypted_suspected`` (a 1-4 byte repeating XOR key that makes the head a valid DOS/PE header, or high
entropy without structure) and ``unknown``.

HybridCLR split (name based, heuristic): an assembly whose name is an AOT assembly of the player
(``mscorlib``, ``System*``, ``UnityEngine*``, anything listed in the metadata string pool) is reported as
``aot_meta`` -- a supplemental-metadata image, or a differential-hybrid-execution patch of an AOT assembly;
an assembly referencing the Unity/BCL assemblies under another name is ``hot``.

This module only reports; it never decrypts anything.  The XOR check looks at the PE header only and the
key is recorded as evidence of the hypothesis.
"""
from __future__ import annotations

import struct
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Set

from ...formats import compress_sniff, pe_cli
from ...util.entropy import shannon
from .detect import HotfixRules
from .storage import Blob

__all__ = ["classify_dll", "analyze", "xor_pe_hypothesis", "protection_verdict"]

_HIGH_ENTROPY = 7.2
_MAX_ASSEMBLIES = 200


def xor_pe_hypothesis(head: bytes) -> Optional[Dict[str, Any]]:
    """Find a 1-4 byte repeating key under which ``head`` starts like a PE image (header-level evidence only).

    Plaintext cribs: ``MZ`` at offset 0 and ``PE\\0\\0`` at ``e_lfanew``; for periods 1-2 the key follows
    from ``MZ`` and ``e_lfanew`` must then decode to a ``PE\\0\\0`` signature, for periods 3-4 the usual
    ``e_lfanew = 0x80`` is assumed (compiler convention, UNVERIFIED) to determine the remaining key bytes.
    """
    h = bytes(head[:0x200])
    if len(h) < 0x90 or h[:2] == b"MZ":
        return None
    for period in (1, 2, 3, 4):
        key: Dict[int, int] = {}
        ok = True
        cribs = [(0, b"MZ")]
        if period >= 3:
            cribs.append((0x80, b"PE\x00\x00"))
        for off, plain in cribs:
            for i, p in enumerate(plain):
                idx = (off + i) % period
                k = h[off + i] ^ p
                if key.setdefault(idx, k) != k:
                    ok = False
        if not ok or len(key) != period:
            continue
        kb = bytes(key[i] for i in range(period))
        dec = bytes(c ^ kb[i % period] for i, c in enumerate(h))
        lf = struct.unpack_from("<I", dec, 0x3C)[0]
        if 0x40 <= lf <= len(dec) - 4 and dec[lf:lf + 4] == b"PE\x00\x00":
            return {"key_hex": kb.hex(), "period": period, "confidence": {1: 0.9, 2: 0.8}.get(period, 0.6)}
    return None


def _base_name(name: str) -> str:
    low = name.lower()
    for suf in (".bytes", ".txt"):
        if low.endswith(suf):
            name, low = name[:-len(suf)], low[:-len(suf)]
    return name[:-4] if low.endswith(".dll") else name


def classify_dll(blob: Blob, rules: HotfixRules, aot_names: Set[str], hotfix_runtime: bool) -> Dict[str, Any]:
    data = blob.data if blob.data is not None else blob.head
    entry: Dict[str, Any] = {"name": _base_name(blob.name or "") or "?", "source": blob.source,
                             "size": blob.size if blob.size is not None else len(data), "format": "unknown",
                             "clr": None, "asm_refs": [], "kind": "unknown", "path": blob.container}
    if blob.source != "loose" and blob.name:
        entry["asset"] = blob.name
    info = pe_cli.parse(data) if data[:2] == b"MZ" else None
    if info is not None and info.is_dotnet:
        entry.update(format="pe_cli", clr=info.clr_version, asm_refs=list(info.assembly_refs)[:64],
                     typedef_count=info.typedef_count)
        if info.assembly_name:
            entry["name"] = info.assembly_name
        if blob.data is not None and len(blob.data) < (blob.size or 0):
            entry["warning"] = "image truncated before parsing"
        entry["kind"] = _kind(entry, rules, aot_names, hotfix_runtime, blob)
        return entry
    if info is not None and info.is_pe:
        entry["note"] = "native PE image (no CLI metadata)"
        return entry
    if info is not None:
        entry["note"] = "MZ header but not a valid PE"
    guess = compress_sniff.sniff(blob.head)
    if guess.kind != "none" and guess.confidence >= 0.6:
        entry.update(format="compressed", compression=guess.kind)
        return entry
    xor = xor_pe_hypothesis(blob.head)
    if xor:
        entry.update(format="encrypted_suspected", xor_hypothesis=xor, reason="xor key hypothesis makes the head a valid PE header")
        return entry
    sample = blob.sample or blob.head
    if len(sample) >= 256 and shannon(sample[:16384]) >= _HIGH_ENTROPY:
        entry.update(format="encrypted_suspected", reason="high entropy, no PE/compression magic")
    return entry


def _kind(entry: Dict[str, Any], rules: HotfixRules, aot: Set[str], hotfix_runtime: bool, blob: Blob) -> str:
    name = entry["name"]
    if rules.is_aot_name(name, aot):
        return "aot_meta"
    refs = " ".join(entry["asm_refs"])
    uses_unity = any(r in refs for r in ("UnityEngine", "mscorlib", "netstandard", "Assembly-CSharp", "System"))
    if rules.looks_hot_name(name) or (uses_unity and (hotfix_runtime or blob.name.lower().endswith((".dll.bytes", ".dll.txt")))):
        return "hot"
    return "unknown"


def analyze(blobs: Iterable[Blob], rules: HotfixRules, aot_assemblies: Iterable[str], *, hotfix_runtime: bool,
            named_only: Optional[List[str]] = None, managed_dlls: int = 0) -> Dict[str, Any]:
    aot = {_base_name(a) for a in aot_assemblies}
    entries: List[Dict[str, Any]] = []
    for blob in blobs:
        if len(entries) >= _MAX_ASSEMBLIES:
            break
        entries.append(classify_dll(blob, rules, aot, hotfix_runtime))
    entries.sort(key=lambda e: (e["kind"] != "hot", e["name"], e["source"], e.get("path", "")))
    counts = Counter(e["format"] for e in entries)
    kinds = Counter(e["kind"] for e in entries)
    return {
        "assemblies": entries,
        "counts": {"total": len(entries), "by_format": dict(sorted(counts.items())), "by_kind": dict(sorted(kinds.items()))},
        "named_in_containers": sorted(set(named_only or []))[:40],
        "managed_dlls_in_data_managed": managed_dlls,
        "notes": ["report only: nothing is decrypted, no keys are extracted; being able to read a DLL does not mean it can be run"],
    }


def protection_verdict(cs: Dict[str, Any], *, containers_unreadable: int, csharp_signal: bool,
                       coverage_limited: bool = False) -> Dict[str, Any]:
    entries = cs["assemblies"]
    if not entries:
        if csharp_signal:
            return {"verdict": "unknown", "confidence": 0.3, "reason": "a C# hot-update runtime is present but no assembly could be inspected%s" % (
                " (%d container(s) unreadable)" % containers_unreadable if containers_unreadable else "")}
        if coverage_limited:
            return {"verdict": "unknown", "confidence": 0.3,
                    "reason": "no scripts observed, but coverage is limited (unreadable containers / encrypted binary)"}
        return {"verdict": "n/a", "confidence": 0.5, "reason": "no hot-update assemblies observed"}
    bad = [e for e in entries if e["format"] == "encrypted_suspected"]
    if bad:
        return {"verdict": "suspected", "confidence": 0.8 if any(e.get("xor_hypothesis") for e in bad) else 0.65,
                "reason": "%d assembly candidate(s) are not valid PE/CLI images (XOR-able header or high entropy)" % len(bad)}
    if any(e["format"] == "pe_cli" for e in entries):
        return {"verdict": "no", "confidence": 0.7, "reason": "readable PE/CLI assemblies (plain, not encrypted)"}
    return {"verdict": "unknown", "confidence": 0.3, "reason": "candidates are compressed or of unknown format"}
