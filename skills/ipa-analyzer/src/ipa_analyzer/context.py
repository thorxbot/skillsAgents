"""AnalysisContext: the single object shared by all stages (frozen public API)."""
from __future__ import annotations

import logging
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, Iterable, List, Optional

from .config import Config
from .ingest import ArchiveSource
from .models import Finding, StageResult, Status
from .util.paths import is_within, sanitize_component

Extractor = Callable[["AnalysisContext", List[str]], Dict[str, Path]]

# Legacy / short result keys accepted for reading (canonical key is the stage name).
RESULT_ALIASES: Dict[str, str] = {"unity": "engine.unity"}


class Results(dict):
    """``ctx.results``: ``{stage_name: data}``; lookups also accept ``RESULT_ALIASES``.

    Only stages that finished ``ok``/``partial`` have an entry. Iteration yields canonical keys only.
    """

    def _canon(self, key: Any) -> Any:
        return RESULT_ALIASES.get(key, key) if isinstance(key, str) else key

    def __getitem__(self, key: Any) -> Dict[str, Any]:
        return super().__getitem__(self._canon(key))

    def get(self, key: Any, default: Any = None) -> Any:
        return super().get(self._canon(key), default)

    def __contains__(self, key: object) -> bool:
        return super().__contains__(self._canon(key))


class AnalysisContext:
    def __init__(self, cfg: Config, input_path: Path, *, out_dir: Optional[Path] = None,
                 workdir: Optional[Path] = None, source: Optional[ArchiveSource] = None,
                 app_root: str = "") -> None:
        self.cfg = cfg
        self.input_path = Path(input_path)
        self.source: Optional[ArchiveSource] = source
        # "" (source root is the .app itself) or a POSIX prefix ending with "/", e.g. "Payload/Foo.app/".
        self.app_root: str = app_root
        self.results: Results = Results()
        self.stage_results: Dict[str, StageResult] = {}
        self.findings: List[Finding] = []
        self.warnings: List[str] = []
        self.artifacts: Dict[str, str] = {}   # logical name -> path relative to out_dir
        self.log = logging.getLogger("ipa_analyzer")
        self.input_name: str = self.input_path.stem or "input"
        self.input_sha256: Optional[str] = None
        self._out_dir = Path(out_dir) if out_dir is not None else None
        self._workdir = Path(workdir) if workdir is not None else None
        self._extractor: Optional[Extractor] = None
        self._extracted_total = 0

    # --- binding / directories ---------------------------------------------------------------
    @property
    def is_bound(self) -> bool:
        return self._out_dir is not None

    def bind_input(self, sha256: str, name: Optional[str] = None) -> None:
        """Fix the output directory ``<output_dir>/<name>-<sha12>/`` and workdir ``.../work`` (idempotent).

        Called by the ingest stage once the input hash is known.
        """
        self.input_sha256 = sha256
        if name:
            self.input_name = name
        if self._out_dir is None:
            self._out_dir = Path(self.cfg.output_dir) / ("%s-%s" % (sanitize_component(self.input_name), sha256[:12]))
        self._out_dir.mkdir(parents=True, exist_ok=True)
        if self._workdir is None:
            self._workdir = self._out_dir / "work"

    @property
    def out_dir(self) -> Path:
        """Directory for final deliverables (report files, dumps, split extractions)."""
        if self._out_dir is None:
            raise RuntimeError("AnalysisContext is not bound to an input yet (call bind_input)")
        return self._out_dir

    @property
    def workdir(self) -> Path:
        """Scratch directory (lazily extracted files); removed after the run unless --keep-workdir."""
        if self._workdir is None:
            if self._out_dir is not None:
                self._workdir = self._out_dir / "work"
            else:
                self._workdir = Path(tempfile.mkdtemp(prefix="ipa-analyzer-"))
        self._workdir.mkdir(parents=True, exist_ok=True)
        return self._workdir

    def artifact_path(self, rel: str) -> Path:
        """Path of a deliverable inside ``out_dir`` (parents created; refuses to leave ``out_dir``)."""
        p = self.out_dir / rel
        if not is_within(self.out_dir, p):
            raise ValueError("artifact path escapes the output directory: %r" % rel)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def register_artifact(self, name: str, rel: str) -> None:
        """Record that deliverable ``rel`` (relative to ``out_dir``) exists, e.g. ``("report.json", "report.json")``."""
        self.artifacts[name] = rel

    # --- app paths ---------------------------------------------------------------------------
    def app_path(self, rel: str) -> str:
        """Archive name of ``rel`` (relative to the .app root), e.g. ``app_path("Info.plist")``."""
        return self.app_root + rel.lstrip("/")

    def rel(self, name: str) -> Optional[str]:
        """Path of archive entry ``name`` relative to the .app root; ``None`` if outside the app."""
        if not self.app_root:
            return name
        return name[len(self.app_root):] if name.startswith(self.app_root) else None

    # --- extraction --------------------------------------------------------------------------
    def set_extractor(self, fn: Optional[Extractor]) -> None:
        """WP1 installs the safe, limit-aware extractor here."""
        self._extractor = fn

    def extract(self, paths: Iterable[str]) -> Dict[str, Path]:
        """Lazily extract archive entries to ``workdir``; returns ``{archive_name: local_path}``.

        Names that could not be extracted (missing, unsafe, over limits) are absent from the result
        and a warning is recorded. Already-extracted files are reused.
        """
        names = list(dict.fromkeys(paths))
        if self._extractor is not None:
            return self._extractor(self, names)
        return self._default_extract(names)

    def _default_extract(self, names: List[str]) -> Dict[str, Path]:
        out: Dict[str, Path] = {}
        if self.source is None:
            self.add_warning("extract: no input source is open")
            return out
        lim = self.cfg.limits
        base = self.workdir / "x"
        for name in names:
            parts = PurePosixPath(name).parts
            if not parts or any(p in ("..", "/") or ":" in p for p in parts):
                self.add_warning("extract: refusing unsafe entry name %r" % name)
                continue
            try:
                info = self.source.stat(name)
            except KeyError:
                self.add_warning("extract: no such entry %r" % name)
                continue
            if info.is_dir or info.is_symlink:
                continue
            dest = base.joinpath(*[sanitize_component(p) for p in parts])
            if not is_within(base, dest):
                self.add_warning("extract: refusing entry that escapes the workdir %r" % name)
                continue
            if dest.is_file() and dest.stat().st_size == info.size:
                out[name] = dest
                continue
            if info.size > lim.max_file_size or self._extracted_total + info.size > lim.max_total_extract:
                self.add_warning("extract: skipping %r (size limit)" % name)
                continue
            try:
                self.source.extract_to(name, dest)
            except Exception as exc:  # noqa: BLE001 - report and continue
                self.add_warning("extract: failed for %r: %s" % (name, exc))
                continue
            self._extracted_total += info.size
            out[name] = dest
        return out

    # --- results / findings ------------------------------------------------------------------
    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)
        self.log.warning(msg)

    def stage_status(self, name: str) -> Optional[Status]:
        r = self.stage_results.get(name)
        return r.status if r else None

    def findings_by_id(self, finding_id: str) -> List[Finding]:
        return [f for f in self.findings if f.id == finding_id]

    def close(self) -> None:
        if self.source is not None:
            try:
                self.source.close()
            except Exception:  # noqa: BLE001
                self.log.debug("closing source failed", exc_info=True)
