"""Locating the ``.app`` bundle inside an ``ArchiveSource`` and naming the input kind."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from ..errors import InvalidInput
from . import ArchiveSource

__all__ = ["AppLocation", "find_app_root", "detect_kind"]


@dataclass
class AppLocation:
    app_root: str                 # "" (source root is the .app) or "Payload/Foo.app/"
    app_name_dir: str             # "Foo.app" ("" if the root has no .app name)
    warnings: List[str] = field(default_factory=list)
    candidates: List[str] = field(default_factory=list)


def _is_app(part: str) -> bool:
    return part.lower().endswith(".app") and len(part) > 4


def _candidates(source: ArchiveSource) -> Dict[str, List[int]]:
    """``{prefix: [total_size, has_info_plist]}`` for every candidate ``.app`` prefix."""
    found: Dict[str, List[int]] = {}
    for e in source.namelist():
        parts = e.name.split("/")
        prefix = None
        # Payload/<X>.app/...  (canonical)
        if len(parts) >= 3 and parts[0] == "Payload" and _is_app(parts[1]):
            prefix = "Payload/%s/" % parts[1]
        # <wrapper>/Payload/<X>.app/...  (IPA zipped inside a folder)
        elif len(parts) >= 4 and parts[1] == "Payload" and _is_app(parts[2]):
            prefix = "%s/Payload/%s/" % (parts[0], parts[2])
        # <X>.app/...  (a zipped .app without Payload)
        elif len(parts) >= 2 and _is_app(parts[0]) and parts[0] != "Payload":
            prefix = parts[0] + "/"
        if prefix is None:
            continue
        slot = found.setdefault(prefix, [0, 0])
        if not e.is_dir:
            slot[0] += e.size
            if e.name == prefix + "Info.plist":
                slot[1] = 1
    return found


def find_app_root(source: ArchiveSource) -> AppLocation:
    """Find the application bundle.

    Preference: ``Payload/<X>.app/`` (unique -> taken; several -> the one with ``Info.plist`` and the
    largest content, with a warning), then wrapper-folder / bare ``<X>.app/`` layouts, then a source that
    *is* the app (``Info.plist`` at its root, or a directory named ``*.app``). Raises ``InvalidInput``
    with a description of what was found otherwise.
    """
    cands = _candidates(source)
    warnings: List[str] = []
    if cands:
        canonical = {p: v for p, v in cands.items() if p.startswith("Payload/")}
        pool = canonical or cands
        with_plist = {p: v for p, v in pool.items() if v[1]}
        pick_from = with_plist or pool
        best = sorted(pick_from.items(), key=lambda kv: (-kv[1][0], kv[0]))[0][0]
        if len(pool) > 1:
            others = sorted(p for p in pool if p != best)
            warnings.append("multiple .app bundles found; analysing %s (largest with Info.plist), ignoring %s"
                            % (best, ", ".join(others)))
        if not canonical:
            warnings.append("no Payload/<name>.app found; using %s" % best)
        if not pick_from[best][1]:
            warnings.append("%s has no Info.plist at its top level" % best)
        return AppLocation(best, best.rstrip("/").rsplit("/", 1)[-1], warnings, sorted(cands))
    names = {e.name for e in source.namelist()}
    src_name = source.path.name
    if "Info.plist" in names:
        return AppLocation("", src_name if _is_app(src_name) else "", warnings, [])
    if source.kind == "dir" and _is_app(src_name):
        warnings.append("%s has no top-level Info.plist" % src_name)
        return AppLocation("", src_name, warnings, [])
    top = sorted({n.split("/", 1)[0] for n in names})[:8]
    if not names:
        raise InvalidInput("the input contains no files (empty archive or directory): %s" % source.path)
    raise InvalidInput("no iOS application bundle found in %s: expected Payload/<name>.app/ (top-level entries: %s)"
                       % (source.path, ", ".join(top) or "none"))


def detect_kind(source: ArchiveSource, loc: AppLocation) -> str:
    """Input kind for the report: ``ipa | zip | app_dir | payload_dir | dir``."""
    if source.kind == "zip":
        return "ipa" if source.path.suffix.lower() == ".ipa" else "zip"
    if loc.app_root == "":
        return "app_dir"
    if loc.app_root.startswith("Payload/"):
        return "payload_dir"
    return "dir"
