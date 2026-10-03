"""Stage ``ingest`` (WP1): open the input, locate the .app, hash the input, bind the output directory.

Produces ``ctx.results["ingest"]`` (see CONTRACT-FREEZE section 4.1), sets ``ctx.source`` /
``ctx.app_root``, calls ``ctx.bind_input`` and installs the safe extractor behind ``ctx.extract``.
Raises ``errors.InvalidInput`` when the input cannot be analysed at all.
"""
from __future__ import annotations

import hashlib
import logging
from typing import List, Optional

from ..context import AnalysisContext
from ..ingest import ArchiveSource, open_source
from ..ingest.layout import detect_kind, find_app_root
from ..ingest.safe_extract import check_archive_limits, install_ctx_extractor, unsafe_reason
from ..models import StageResult
from ..registry import register
from ..util.hashing import sha256_stream

log = logging.getLogger(__name__)

NAME = 'ingest'


def tree_digest(source: ArchiveSource) -> str:
    """Deterministic SHA-256 over a directory source: sorted names, sizes and (streamed) contents."""
    h = hashlib.sha256()
    for e in sorted((x for x in source.namelist() if not x.is_dir), key=lambda x: x.name):
        h.update(e.name.encode("utf-8", "replace") + b"\0" + str(e.size).encode("ascii") + b"\0")
        with source.open(e.name) as fh:
            for block in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(block)
    return h.hexdigest()


def _name_warnings(source: ArchiveSource) -> List[str]:
    unsafe = 0
    seen = {}
    collisions = 0
    for e in source.namelist():
        if unsafe_reason(e.name):
            unsafe += 1
        key = e.name.casefold()
        if key in seen and seen[key] != e.name:
            collisions += 1
        seen.setdefault(key, e.name)
    out = []
    if unsafe:
        out.append("%d entry name(s) are unsafe (absolute / '..' / drive letter) and will never be extracted" % unsafe)
    if collisions:
        out.append("%d entry name(s) differ only by case; extraction renames them with a ~N suffix" % collisions)
    return out


@register(name='ingest')
class IngestStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        src: Optional[ArchiveSource] = ctx.source
        if src is None:
            src = open_source(ctx.input_path, limits=ctx.cfg.limits)
            ctx.source = src
        warnings: List[str] = list(getattr(src, "warnings", []) or [])

        entries = src.namelist()
        if src.kind == "zip":
            archive_size = ctx.input_path.stat().st_size
        else:
            archive_size = sum(e.size for e in entries if not e.is_dir)
        warnings += check_archive_limits(entries, archive_size, ctx.cfg.limits)
        warnings += _name_warnings(src)

        loc = find_app_root(src)
        warnings += loc.warnings
        ctx.app_root = loc.app_root

        digest = sha256_stream(ctx.input_path) if src.kind == "zip" else tree_digest(src)
        ctx.bind_input(digest)
        if hasattr(src, "set_spill_dir"):
            src.set_spill_dir(ctx.workdir / "spill")
        install_ctx_extractor(ctx, src)

        data = {
            "kind": detect_kind(src, loc),
            "path": str(ctx.input_path),
            "size": archive_size,
            "sha256": digest,
            "app_root": loc.app_root,
            "app_name_dir": loc.app_name_dir,
            "entries": len(entries),
            "warnings": warnings,
        }
        log.info("ingest: %s (%s), app root %r, %d entries", ctx.input_path, data["kind"], loc.app_root, len(entries))
        return StageResult.ok(NAME, data, warnings=warnings)
