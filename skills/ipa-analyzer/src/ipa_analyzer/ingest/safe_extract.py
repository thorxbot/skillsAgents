"""Selective, hostile-input-safe extraction from an ``ArchiveSource``.

Guarantees for everything written by ``SafeExtractor``:

* entry names with ``..`` components, absolute paths, drive letters or UNC prefixes are refused
  (``UnsafePath``); components are sanitised for Windows (reserved device names, illegal characters,
  trailing dots / spaces) and case-insensitive collisions get a ``~N`` suffix;
* total bytes, single-file size, file count and compression ratio are limited (``LimitExceeded``);
* files are written to a temporary name next to the destination and renamed atomically;
* the final path is always verified to be inside the destination root;
* symlink entries are only recorded (in the manifest); optionally created on POSIX when the target
  stays inside the root. They are never followed.

``install_ctx_extractor`` wires this into ``AnalysisContext.extract``.
"""
from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePath, PurePosixPath
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from ..config import LimitsConfig
from ..errors import InvalidInput, LimitExceeded, UnsafePath
from ..util.paths import is_within, sanitize_component, to_long_path
from . import ArchiveSource, EntryInfo

log = logging.getLogger(__name__)

__all__ = ["RATIO_FLOOR", "ExtractBudget", "PathAllocator", "SafeExtractor", "unsafe_reason", "map_components",
           "join_within", "check_archive_limits", "install_ctx_extractor"]

MiB = 1024 * 1024
# Entries smaller than this are never rejected for their compression ratio alone (a 1 MB zero-filled file
# compresses ~1000:1 but is harmless). Ratio is checked for larger entries.
RATIO_FLOOR = 64 * MiB
_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_SPLIT_RE = re.compile(r"[\\/]")
MANIFEST_NAME = "extract.manifest.json"


# --- pure path helpers (testable with PureWindowsPath) ---------------------------------------------
def unsafe_reason(name: str) -> Optional[str]:
    """Why ``name`` (an archive entry name) must not be extracted, or ``None`` if it is acceptable.

    Backslashes are treated as separators for the ``..`` check so that Windows-style traversal inside
    a zip is caught on every platform.
    """
    if not name:
        return "empty name"
    if "\x00" in name:
        return "NUL byte in name"
    if name[0] in "/\\":
        return "absolute path or UNC prefix"
    if _DRIVE_RE.match(name):
        return "drive letter"
    comps = _SPLIT_RE.split(name)
    if ".." in comps:
        return "parent directory reference (zip-slip)"
    if not [c for c in name.split("/") if c not in ("", ".")]:
        return "empty path"
    return None


def map_components(name: str) -> List[str]:
    """Sanitised path components of an entry name. Raises ``UnsafePath`` for unsafe names."""
    reason = unsafe_reason(name)
    if reason:
        raise UnsafePath("unsafe entry name %r: %s" % (name, reason))
    return [sanitize_component(c) for c in name.split("/") if c not in ("", ".")]


def join_within(root: PurePath, comps: Sequence[str]) -> PurePath:
    """``root`` joined with ``comps``; raises ``UnsafePath`` if the result is not lexically inside ``root``."""
    p = root.joinpath(*comps)
    if not is_within(root, p, resolve=False):
        raise UnsafePath("path escapes the destination: %s" % "/".join(comps))
    return p


def _fold(s: str) -> str:
    return unicodedata.normalize("NFC", s).casefold()


def _suffixed(comp: str, n: int, is_file: bool, max_len: int = 255) -> str:
    stem, ext = os.path.splitext(comp) if is_file else (comp, "")
    tag = "~%d" % n
    if len(stem) + len(tag) + len(ext) > max_len:
        stem = stem[: max_len - len(tag) - len(ext)]
    return stem + tag + ext


class PathAllocator:
    """Assigns collision-free destination paths on case-insensitive file systems.

    Two entries whose paths differ only in case (or Unicode normalisation) get distinct names
    (``a.txt`` / ``A~1.txt``); directories that differ only in case are merged; a file/directory clash
    renames the later one.
    """

    def __init__(self) -> None:
        self._nodes: Dict[Tuple[str, ...], Tuple[str, str]] = {}

    def claim(self, comps: Sequence[str]) -> None:
        """Register an already assigned path (e.g. restored from a manifest)."""
        parent: Tuple[str, ...] = ()
        for i, c in enumerate(comps):
            key = parent + (_fold(c),)
            self._nodes.setdefault(key, (c, "file" if i == len(comps) - 1 else "dir"))
            parent = key

    def allocate(self, comps: Sequence[str]) -> Tuple[List[str], bool]:
        """Return ``(actual_components, changed)``."""
        out: List[str] = []
        parent: Tuple[str, ...] = ()
        changed = False
        for i, c in enumerate(comps):
            is_file = i == len(comps) - 1
            kind = "file" if is_file else "dir"
            cand, n = c, 0
            while True:
                key = parent + (_fold(cand),)
                ex = self._nodes.get(key)
                if ex is None:
                    self._nodes[key] = (cand, kind)
                    break
                if ex[1] == "dir" and kind == "dir":
                    cand = ex[0]
                    break
                n += 1
                cand = _suffixed(c, n, is_file)
            changed = changed or cand != c
            out.append(cand)
            parent = key
        return out, changed


# --- limits -----------------------------------------------------------------------------------------
@dataclass
class ExtractBudget:
    total_bytes: int = 0
    files: int = 0


def _ratio(info: EntryInfo) -> float:
    if info.size <= 0:
        return 0.0
    return float("inf") if info.compressed_size <= 0 else info.size / info.compressed_size


def check_archive_limits(entries: Iterable[EntryInfo], archive_size: int, limits: LimitsConfig,
                         *, ratio_floor: int = RATIO_FLOOR) -> List[str]:
    """Reject decompression bombs before any analysis; returns non-fatal warnings.

    Fatal (``LimitExceeded``): more than ``max_files`` entries; an entry larger than ``max_file_size``
    that also exceeds ``max_ratio``; declared total larger than ``max_total_extract`` *and* an overall
    ratio above ``max_ratio``. Merely large or highly compressible entries only warn, because nothing is
    unpacked unless it is needed and each later extraction re-checks the limits.
    """
    warnings: List[str] = []
    total = comp_total = count = 0
    big_ratio = 0
    for e in entries:
        if e.is_dir:
            continue
        count += 1
        if count > limits.max_files:
            raise LimitExceeded("archive has more than %d files (limit max_files)" % limits.max_files)
        total += e.size
        comp_total += e.compressed_size
        r = _ratio(e)
        if e.size > limits.max_file_size and r > limits.max_ratio:
            raise LimitExceeded("entry %r declares %d bytes (limit %d) at compression ratio %s:1 (limit %g:1): "
                                "decompression bomb" % (e.name, e.size, limits.max_file_size,
                                                        "inf" if r == float("inf") else "%d" % r, limits.max_ratio))
        if e.size >= ratio_floor and r > limits.max_ratio:
            big_ratio += 1
    denom = max(archive_size, comp_total, 1)
    if total > limits.max_total_extract and total / denom > limits.max_ratio:
        raise LimitExceeded("archive declares %d bytes of content (limit %d) at an overall compression ratio of "
                            "%d:1 (limit %g:1): decompression bomb"
                            % (total, limits.max_total_extract, total // denom, limits.max_ratio))
    if total > limits.max_total_extract:
        warnings.append("archive declares %d bytes of content, above the extraction limit %d; only needed files "
                        "will be unpacked" % (total, limits.max_total_extract))
    if big_ratio:
        warnings.append("%d large entr%s exceed the compression ratio limit %g:1 and will not be extracted"
                        % (big_ratio, "y" if big_ratio == 1 else "ies", limits.max_ratio))
    return warnings


# --- extractor --------------------------------------------------------------------------------------
class SafeExtractor:
    """Extract entries below ``root`` with the guarantees listed in the module docstring.

    ``path_fn`` maps an archive name to the name used below ``root`` (default: unchanged), e.g. to
    strip the ``Payload/X.app/`` prefix.
    """

    def __init__(self, source: ArchiveSource, root: Path, limits: LimitsConfig, *,
                 path_fn: Optional[Callable[[str], str]] = None, create_symlinks: bool = False,
                 ratio_floor: int = RATIO_FLOOR, manifest_path: Optional[Path] = None,
                 budget: Optional[ExtractBudget] = None) -> None:
        self.source = source
        self.root = Path(root)
        self.limits = limits
        self.path_fn = path_fn
        self.create_symlinks = create_symlinks
        self.ratio_floor = ratio_floor
        self.manifest_path = Path(manifest_path) if manifest_path else None
        self.budget = budget or ExtractBudget()
        self.manifest: Dict[str, Dict[str, Any]] = {}
        self._alloc = PathAllocator()
        self._dirty = False
        self._load_manifest()

    # -- manifest -------------------------------------------------------------------------------------
    def _load_manifest(self) -> None:
        if not self.manifest_path or not self.manifest_path.is_file():
            return
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
            entries = doc.get("entries", {})
            for name, rec in entries.items():
                self.manifest[name] = rec
                if rec.get("path"):
                    self._alloc.claim(rec["path"].split("/"))
        except (OSError, ValueError, AttributeError):
            log.debug("ignoring unreadable manifest %s", self.manifest_path, exc_info=True)
            self.manifest.clear()
            self._alloc = PathAllocator()

    def save_manifest(self) -> None:
        """Persist ``archive name -> path`` (and sanitising / collision / symlink notes) as JSON."""
        if not self.manifest_path or not self._dirty:
            return
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.manifest_path.with_name(self.manifest_path.name + ".tmp")
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"version": 1, "entries": self.manifest}, fh, indent=1, sort_keys=True, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, self.manifest_path)
        self._dirty = False

    # -- extraction -------------------------------------------------------------------------------------
    def _check_limits(self, info: EntryInfo) -> None:
        lim = self.limits
        if info.size > lim.max_file_size:
            raise LimitExceeded("entry %r is %d bytes, above the per-file limit %d" % (info.name, info.size, lim.max_file_size))
        if self.budget.total_bytes + info.size > lim.max_total_extract:
            raise LimitExceeded("extracting %r would exceed the total extraction limit %d (already %d)"
                                % (info.name, lim.max_total_extract, self.budget.total_bytes))
        if self.budget.files + 1 > lim.max_files:
            raise LimitExceeded("file count limit %d reached" % lim.max_files)
        r = _ratio(info)
        if info.size >= self.ratio_floor and r > lim.max_ratio:
            raise LimitExceeded("entry %r has compression ratio %s:1 above the limit %g:1 (decompression bomb?)"
                                % (info.name, "inf" if r == float("inf") else "%d" % r, lim.max_ratio))

    def extract(self, name: str) -> Optional[Path]:
        """Extract one entry; returns its path, or ``None`` for directories and symlinks.

        Raises ``UnsafePath``, ``LimitExceeded``, ``InvalidInput`` (corrupt entry), ``KeyError`` (no such
        entry) or ``OSError``.
        """
        reason = unsafe_reason(name)
        if reason:
            raise UnsafePath("unsafe entry name %r: %s" % (name, reason))
        info = self.source.stat(name)
        if info.is_dir:
            return None
        rec = self.manifest.get(name)
        known: Optional[List[str]] = None
        if rec is not None and rec.get("path") and not rec.get("symlink_target"):
            known = rec["path"].split("/")
            cached = self.root.joinpath(*known)
            if cached.is_file() and cached.stat().st_size == info.size and is_within(self.root, cached):
                return cached
        mapped = self.path_fn(name) if self.path_fn else name
        comps = map_components(mapped)
        sanitized = comps != [c for c in mapped.split("/") if c not in ("", ".")]
        if info.is_symlink:
            return self._record_symlink(name, info, comps, sanitized)
        self._check_limits(info)
        if known is not None:        # path assigned in an earlier run whose file is gone: keep the mapping
            actual, renamed = known, bool(rec.get("renamed_for_collision")) if rec else False
        else:
            actual, renamed = self._alloc.allocate(comps)
        dest = self.root.joinpath(*actual)
        if not is_within(self.root, dest, resolve=False) or not is_within(self.root, dest):
            raise UnsafePath("destination escapes the extraction root: %s" % name)
        os.makedirs(to_long_path(dest.parent), exist_ok=True)
        if not is_within(self.root, dest.parent):       # a pre-existing symlinked directory
            raise UnsafePath("destination directory resolves outside the extraction root: %s" % name)
        if dest.is_dir():
            raise InvalidInput("cannot extract %r: a directory exists at %s" % (name, dest))
        fd, tmp = tempfile.mkstemp(prefix=".ipa-part-", dir=str(dest.parent))
        os.close(fd)
        try:
            self.source.extract_to(name, Path(tmp))
            os.replace(to_long_path(tmp), to_long_path(dest))
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        self.budget.total_bytes += info.size
        self.budget.files += 1
        self.manifest[name] = {"path": "/".join(actual), "size": info.size, "sanitized": sanitized,
                               "renamed_for_collision": renamed}
        self._dirty = True
        return dest

    def _record_symlink(self, name: str, info: EntryInfo, comps: List[str], sanitized: bool) -> None:
        target = ""
        getter = getattr(self.source, "symlink_target", None)
        if getter is not None:
            try:
                target = str(getter(name))
            except (InvalidInput, OSError, KeyError):
                target = ""
        rec: Dict[str, Any] = {"path": "", "symlink_target": target, "symlink_created": False, "sanitized": sanitized}
        if self.create_symlinks and os.name != "nt" and target:
            actual, _ = self._alloc.allocate(comps)
            link = self.root.joinpath(*actual)
            resolved = PurePosixPath(os.path.normpath(os.path.join(str(link.parent), target)))
            if not target.startswith("/") and is_within(self.root, link.parent) and \
                    is_within(self.root.resolve(), Path(str(resolved)), resolve=False) and not link.exists():
                os.makedirs(link.parent, exist_ok=True)
                os.symlink(target, link)
                rec.update({"path": "/".join(actual), "symlink_created": True})
        self.manifest[name] = rec
        self._dirty = True
        return None

    def extract_many(self, names: Iterable[str]) -> Tuple[Dict[str, Path], Dict[str, str]]:
        """Extract several entries; returns ``(extracted, errors)`` where errors map name -> message."""
        done: Dict[str, Path] = {}
        errors: Dict[str, str] = {}
        for name in dict.fromkeys(names):
            try:
                p = self.extract(name)
            except KeyError:
                errors[name] = "no such entry"
            except (UnsafePath, LimitExceeded, InvalidInput) as exc:
                errors[name] = str(exc)
            except OSError as exc:
                errors[name] = "I/O error: %s" % exc
            except (ValueError, OverflowError) as exc:      # malformed entry metadata: skip this entry only
                errors[name] = "malformed entry: %s" % exc
            else:
                if p is not None:
                    done[name] = p
        return done, errors


def install_ctx_extractor(ctx: Any, source: ArchiveSource) -> SafeExtractor:
    """Make ``ctx.extract`` use a ``SafeExtractor`` rooted at ``ctx.workdir / "x"``."""
    ex = SafeExtractor(source, ctx.workdir / "x", ctx.cfg.limits, manifest_path=ctx.workdir / MANIFEST_NAME)

    def _extract(c: Any, names: List[str]) -> Dict[str, Path]:
        got, errors = ex.extract_many(names)
        for n, msg in errors.items():
            c.add_warning("extract: skipping %r: %s" % (n, msg))
        ex.save_manifest()
        return got

    ctx.set_extractor(_extract)
    return ex
