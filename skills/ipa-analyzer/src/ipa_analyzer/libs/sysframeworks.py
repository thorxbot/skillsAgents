"""System framework / ``/usr/lib`` dylib table (``data/sysframeworks.json``)."""
from __future__ import annotations

import fnmatch
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..util import paths as _paths

log = logging.getLogger(__name__)

_VER_SUFFIX = re.compile(r"(\.[0-9]+)+$")
_LETTER_SUFFIX = re.compile(r"\.[A-Z]$")
_FW_RE = re.compile(r"/([^/]+)\.framework/")


@dataclass(frozen=True)
class SysRecord:
    name: str
    purpose_zh: str
    purpose_en: str
    sensitive: bool = False
    capability: str = ""


def normalize_dylib_name(path_or_leaf: str) -> str:
    """``/usr/lib/libc++.1.dylib`` -> ``libc++``; ``libz.1.2.11.dylib`` -> ``libz``; ``libSystem.B.dylib`` -> ``libSystem``."""
    leaf = path_or_leaf.rsplit("/", 1)[-1]
    if leaf.endswith(".dylib"):
        leaf = leaf[:-6]
    prev = None
    while prev != leaf:
        prev = leaf
        leaf = _VER_SUFFIX.sub("", leaf)
        leaf = _LETTER_SUFFIX.sub("", leaf)
    return leaf


def framework_name_of(path: str) -> Optional[str]:
    """``X`` of ``.../X.framework/X`` (the last framework component), else None."""
    m = list(_FW_RE.finditer(path))
    return m[-1].group(1) if m else None


class SysFrameworks:
    def __init__(self, doc: Optional[Dict[str, Any]] = None) -> None:
        doc = doc or {}
        self.frameworks: Dict[str, SysRecord] = {k: self._rec(k, v) for k, v in (doc.get("frameworks") or {}).items()}
        self.usr_lib: Dict[str, SysRecord] = {k: self._rec(k, v) for k, v in (doc.get("usr_lib") or {}).items()}
        self.patterns: List[Tuple[str, SysRecord]] = [(p["glob"], self._rec(p["glob"], p))
                                                      for p in doc.get("usr_lib_patterns") or [] if "glob" in p]

    @staticmethod
    def _rec(name: str, d: Dict[str, Any]) -> SysRecord:
        return SysRecord(name, str(d.get("purpose_zh", "")), str(d.get("purpose_en", "")), bool(d.get("sensitive")),
                         str(d.get("capability", "")))

    def lookup(self, install_path: str) -> Optional[SysRecord]:
        """Record for a system install path (``/System/Library/Frameworks/X.framework/X`` or ``/usr/lib/...``)."""
        fw = framework_name_of(install_path) if "/System/Library/Frameworks/" in install_path else None
        if fw:
            rec = self.frameworks.get(fw)
            if rec is not None:
                return rec
            nested = install_path.rsplit("/", 1)[-1]
            return self.frameworks.get(nested)
        stem = normalize_dylib_name(install_path)
        rec = self.usr_lib.get(stem)
        if rec is not None:
            return rec
        leaf = install_path.rsplit("/", 1)[-1]
        for glob, prec in self.patterns:
            if fnmatch.fnmatchcase(leaf, glob + "*" if not glob.endswith("*") else glob):
                return SysRecord(stem, prec.purpose_zh, prec.purpose_en, prec.sensitive, prec.capability)
        return None


def load_sysframeworks(data_dir: Optional[Path] = None) -> SysFrameworks:
    path = (Path(data_dir) if data_dir else _paths.resource_dir("data")) / "sysframeworks.json"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return SysFrameworks(json.load(fh))
    except (OSError, ValueError) as exc:
        log.warning("system framework table unreadable (%s): %s", path, exc)
        return SysFrameworks()
