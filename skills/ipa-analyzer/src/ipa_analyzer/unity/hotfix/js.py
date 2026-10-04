"""JavaScript hot-update profile (puerts and friends): backend, file formats, protection hints.

Backend evidence: puerts ``Backend*`` type names in the metadata, plus native symbols -- QuickJS API names
(``JS_NewRuntime`` ...), V8 / Node.js C++ mangled namespaces.  puerts' ``DefaultLoader`` reads scripts as
Unity ``TextAsset`` resources (``.mjs`` / ``.cjs``, ``*.txt`` suffix on old Unity versions; fetched from
Tencent/puerts ``Loader.cs`` 2026-10-04), so scripts typically sit in SerializedFiles / bundles rather than as loose files.

File formats: plain text, "binary, not text" (QuickJS / V8 bytecode formats are version specific and are
NOT identified here), compressed, ``encrypted_suspected`` (base64-looking or high entropy).  Nothing is
decrypted or run.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional

from ...formats import compress_sniff
from ...util.entropy import shannon
from .storage import Blob

__all__ = ["classify_blob", "analyze", "protection_verdict"]

_B64 = re.compile(rb"^[A-Za-z0-9+/=\r\n]+$")
_HIGH_ENTROPY = 7.2


def classify_blob(blob: Blob) -> str:
    """plain | binary_non_text | compressed | encrypted_suspected"""
    head = blob.head
    guess = compress_sniff.sniff(head)
    if guess.kind != "none" and guess.confidence >= 0.6:
        return "compressed"
    sample = (blob.sample or head)[:8192]
    if not sample:
        return "binary_non_text"
    text_ok = True
    s = sample[3:] if sample.startswith(b"\xef\xbb\xbf") else sample
    if sum(1 for b in s if b < 9 or (13 < b < 32) or b == 0x7F) / len(s) > 0.01:
        text_ok = False
    else:
        try:
            s.decode("utf-8")
        except UnicodeDecodeError as exc:
            text_ok = exc.start >= len(s) - 4
    if text_ok:
        if len(sample) >= 64 and _B64.match(sample.strip()) and b" " not in sample:
            return "encrypted_suspected"
        return "plain"
    if len(sample) >= 256 and shannon(sample) >= _HIGH_ENTROPY:
        return "encrypted_suspected"
    return "binary_non_text"


def analyze(blobs: Iterable[Blob], backends_from_types: Iterable[Dict[str, Any]],
            native_backends: Iterable[Dict[str, Any]], *, named_in_containers: int = 0,
            extensions: Optional[List[str]] = None) -> Dict[str, Any]:
    counts = Counter()
    formats: List[str] = []
    samples: List[Dict[str, Any]] = []
    total = 0
    for blob in blobs:
        total += 1
        c = classify_blob(blob)
        counts[c] += 1
        if c not in formats:
            formats.append(c)
        if len(samples) < 12:
            samples.append({"path": blob.container, "source": blob.source, "class": c})
    merged: Dict[str, float] = {}
    for b in list(backends_from_types) + list(native_backends):
        bid = b["id"]
        merged[bid] = max(merged.get(bid, 0.0), float(b.get("confidence", 0.0)))
    if "nodejs" in merged:                       # Node.js embeds V8
        merged.setdefault("v8", 0.4)
    backends = [{"id": k, "confidence": round(v, 3)} for k, v in sorted(merged.items(), key=lambda kv: (-kv[1], kv[0]))]
    return {
        "backends": backends,
        "files": {"plain": counts["plain"], "encrypted_suspected": counts["encrypted_suspected"],
                  "binary_non_text": counts["binary_non_text"], "compressed": counts["compressed"], "total": total},
        "formats": formats,
        "extensions": sorted(set(extensions or [])),
        "named_in_containers": named_in_containers,
        "samples": samples,
        "notes": ["JS bytecode formats (QuickJS/V8) are version specific and not identified; non-text binaries are reported as such"],
    }


def protection_verdict(js: Dict[str, Any], *, containers_unreadable: int, js_signal: bool,
                       coverage_limited: bool = False) -> Dict[str, Any]:
    f = js["files"]
    if f["total"] == 0:
        if js_signal:
            return {"verdict": "unknown", "confidence": 0.3,
                    "reason": "a JS runtime is present but no script could be inspected%s" % (
                        " (%d container(s) unreadable)" % containers_unreadable if containers_unreadable else "")}
        if coverage_limited:
            return {"verdict": "unknown", "confidence": 0.3,
                    "reason": "no scripts observed, but coverage is limited (unreadable containers / encrypted binary)"}
        return {"verdict": "n/a", "confidence": 0.5, "reason": "no JS scripts observed"}
    if f["encrypted_suspected"]:
        return {"verdict": "suspected", "confidence": 0.65, "reason": "scripts that are high-entropy or base64-looking"}
    if f["plain"]:
        return {"verdict": "no", "confidence": 0.7, "reason": "plain-text scripts; only a sample was inspected"}
    return {"verdict": "unknown", "confidence": 0.3, "reason": "scripts are binary/compressed of unknown format"}
