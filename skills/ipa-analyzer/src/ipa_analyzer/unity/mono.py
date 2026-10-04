"""Mono backend: are the managed assemblies under ``Data/Managed`` genuine .NET assemblies?

A loose assembly is considered intact when it is a PE image with a CLR header whose metadata root carries the
``BSJB`` signature (``formats.pe_cli``).  Anything else in ``Data/Managed/*.dll`` is evidence of data-level
protection (encrypted / packed assemblies, custom loaders).  Obfuscator markers are plain byte-string hits in
the file; they are low-confidence hints, not proof.

Marker strings: ``ConfusedByAttribute`` (ConfuserEx writes this assembly attribute), ``Beebyte`` (namespace of
the Beebyte Obfuscator attributes), ``SmartAssembly``, ``DotfuscatorAttribute``, ``ObfuscatedByAttribute`` /
``Eazfuscator``.  UNVERIFIED: recalled from the respective projects, not re-checked against their sources.
"""
from __future__ import annotations

import logging
import re
from typing import Any, BinaryIO, Callable, Dict, List, Sequence, Tuple

from ..formats import pe_cli
from ..formats.compress_sniff import sniff as sniff_compression
from ..util.entropy import shannon

log = logging.getLogger(__name__)

__all__ = ["select_assemblies", "analyze_assembly", "analyze_mono", "OBFUSCATOR_MARKERS"]

MAX_ASSEMBLY_READ = 64 * 1024 * 1024
MAX_ASSEMBLIES = 60
ENTROPY_HIGH = 7.5
# UNVERIFIED (see module docstring)
OBFUSCATOR_MARKERS: Tuple[Tuple[str, bytes], ...] = (
    ("confuserex", b"ConfusedByAttribute"),
    ("beebyte", b"Beebyte"),
    ("smartassembly", b"SmartAssembly"),
    ("dotfuscator", b"DotfuscatorAttribute"),
    ("eazfuscator", b"Eazfuscator"),
)
_MANAGED_RE = re.compile(r"(^|/)Data/Managed/[^/]+\.dll$", re.I)


def select_assemblies(paths: Sequence[Tuple[str, str]]) -> List[str]:
    """``paths`` = ``(archive_name, app_relative_name)``; loose managed DLLs, Assembly-CSharp first, capped."""
    dlls = [name for name, rel in paths if _MANAGED_RE.search(rel)]

    def key(name: str) -> Tuple[int, str]:
        leaf = name.rsplit("/", 1)[-1].lower()
        return (0 if leaf.startswith("assembly-csharp") else 1 if leaf.startswith("assembly-") else 2, name)

    dlls.sort(key=key)
    return dlls[:MAX_ASSEMBLIES]


def analyze_assembly(data: bytes) -> Dict[str, Any]:
    """Classify one assembly image already read into memory."""
    info = pe_cli.parse(data)
    rec: Dict[str, Any] = {"size": len(data), "valid_pe_cli": bool(info.is_pe and info.is_dotnet)}
    if rec["valid_pe_cli"]:
        rec.update(format="pe_cli", clr=info.clr_version, assembly_name=info.assembly_name,
                   typedefs=info.typedef_count)
        stats = info.typedef_name_stats or {}
        if stats:
            rec["name_stats"] = stats
        hits = [name for name, pat in OBFUSCATOR_MARKERS if pat in data]
        if hits:
            rec["obfuscator_hints"] = hits
        return rec
    if info.is_pe:
        rec["format"] = "pe_no_cli"
        return rec
    ent = shannon(data[:65536])
    rec["entropy"] = round(ent, 3)
    comp = sniff_compression(data[:32])
    if comp.kind != "none" and comp.confidence >= 0.6:
        rec.update(format="compressed", container=comp.kind)
    elif ent >= ENTROPY_HIGH or (len(data) < 4096 and ent >= 7.0):
        rec["format"] = "encrypted_suspected"
    else:
        rec["format"] = "not_pe"
    return rec


def analyze_mono(names: Sequence[str], open_fn: Callable[[str], BinaryIO], size_of: Callable[[str], int]
                 ) -> Dict[str, Any]:
    """Examine the listed assemblies.  ``open_fn`` returns a readable binary file for an archive name."""
    assemblies: List[Dict[str, Any]] = []
    for name in names:
        size = size_of(name)
        if size > MAX_ASSEMBLY_READ:
            assemblies.append({"path": name, "size": size, "valid_pe_cli": False, "format": "skipped_large"})
            continue
        try:
            with open_fn(name) as fh:
                data = fh.read(MAX_ASSEMBLY_READ)
        except (KeyError, OSError, ValueError) as exc:
            assemblies.append({"path": name, "size": size, "valid_pe_cli": False, "format": "unreadable",
                               "error": str(exc)})
            continue
        rec = analyze_assembly(data)
        rec["path"] = name
        assemblies.append(rec)
    return {"assemblies": assemblies, **_verdict(assemblies)}


def _verdict(assemblies: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not assemblies:
        return {"verdict": "n/a", "confidence": 0.0, "reasons": ["no_managed_assemblies"]}
    checked = [a for a in assemblies if a["format"] not in ("skipped_large", "unreadable")]
    if not checked:
        return {"verdict": "unknown", "confidence": 0.3, "reasons": ["unreadable"]}
    bad = [a for a in checked if not a["valid_pe_cli"]]
    main = [a for a in checked if a["path"].rsplit("/", 1)[-1].lower().startswith("assembly-csharp")]
    main_bad = [a for a in main if not a["valid_pe_cli"]]
    reasons: List[str] = []
    if not bad:
        hints = sorted({h for a in checked for h in a.get("obfuscator_hints", [])})
        if hints:
            reasons.append("obfuscator_hints")
        return {"verdict": "no", "confidence": 0.85, "reasons": reasons or ["all_valid"], "obfuscator_hints": hints}
    enc = [a for a in bad if a["format"] == "encrypted_suspected"]
    if main_bad and any(a["format"] == "encrypted_suspected" for a in main_bad):
        return {"verdict": "yes", "confidence": 0.8, "reasons": ["main_assembly_encrypted"]}
    if len(enc) * 2 >= len(checked):
        return {"verdict": "yes", "confidence": 0.75, "reasons": ["majority_encrypted"]}
    return {"verdict": "suspected", "confidence": 0.7 if main_bad else 0.55,
            "reasons": ["invalid_assembly_main" if main_bad else "invalid_assembly"]}
