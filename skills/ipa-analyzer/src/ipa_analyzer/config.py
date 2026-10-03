"""Run configuration (frozen public contract; see docs/CONTRACT-FREEZE.md)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .errors import UsageError

KiB = 1024
MiB = 1024 * KiB
GiB = 1024 * MiB

LANGS: Tuple[str, ...] = ("zh", "en")
FORMATS: Tuple[str, ...] = ("md", "json", "html")
# Categories accepted by --extract (physical "split" extraction, implemented by WP1).
EXTRACT_CATEGORIES: Tuple[str, ...] = ("binary", "frameworks", "metadata", "bundles", "plists", "all")

_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?)(?:i?b)?\s*$", re.IGNORECASE)
_SIZE_MULT = {"": 1, "k": KiB, "m": MiB, "g": GiB, "t": 1024 * GiB}


def parse_size(text: str) -> int:
    """Parse ``"512"``, ``"64M"``, ``"2GiB"`` into bytes. Raises ``UsageError`` on bad input."""
    m = _SIZE_RE.match(str(text))
    if not m:
        raise UsageError("invalid size: %r (examples: 1048576, 512M, 2G)" % (text,))
    return int(float(m.group(1)) * _SIZE_MULT[m.group(2).lower()])


@dataclass
class Il2cppConfig:
    enabled: bool = True
    force_dump: bool = False
    timeout_s: int = 900
    tool_path: Optional[str] = None
    dotnet_path: Optional[str] = None
    backend_order: List[str] = field(default_factory=list)


@dataclass
class UnityConfig:
    bundle_deep_sample: int = 200
    hotfix_scan_bundles: int = 100
    hotfix_scan_bytes_per_bundle: int = 64 * MiB


@dataclass
class LimitsConfig:
    # Defaults: docs/02-ARCHITECTURE.md section 6 (8 GB / 2 GB / 200k / 200:1).
    max_total_extract: int = 8 * GiB
    max_file_size: int = 2 * GiB
    max_files: int = 200_000
    max_ratio: float = 200.0


@dataclass
class Config:
    output_dir: Path = field(default_factory=lambda: Path("out"))
    lang: str = "zh"
    formats: Tuple[str, ...] = ("md", "json")
    stages: Optional[Tuple[str, ...]] = None  # None = all stages; otherwise only these + hard deps
    skip: Tuple[str, ...] = ()
    il2cpp: Il2cppConfig = field(default_factory=Il2cppConfig)
    unity: UnityConfig = field(default_factory=UnityConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    libs_user_path: Optional[Path] = None
    engines_user_dir: Optional[Path] = None
    signature_integrity: bool = True
    offline: bool = False
    redact: bool = True
    assume_yes: bool = False
    extract: Tuple[str, ...] = ()
    keep_workdir: bool = False
    verbose: int = 0

    def validate(self) -> "Config":
        """Raise ``UsageError`` for invalid values; returns self for chaining."""
        if self.lang not in LANGS:
            raise UsageError("--lang must be one of %s" % ", ".join(LANGS))
        bad = [f for f in self.formats if f not in FORMATS]
        if bad:
            raise UsageError("unknown --format value(s): %s (allowed: %s)" % (",".join(bad), ",".join(FORMATS)))
        badx = [c for c in self.extract if c not in EXTRACT_CATEGORIES]
        if badx:
            raise UsageError(
                "unknown --extract category(ies): %s (allowed: %s)" % (",".join(badx), ",".join(EXTRACT_CATEGORIES))
            )
        if self.il2cpp.timeout_s <= 0:
            raise UsageError("il2cpp timeout must be positive")
        if self.limits.max_total_extract <= 0 or self.limits.max_file_size <= 0 or self.limits.max_files <= 0:
            raise UsageError("limits must be positive")
        return self

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serialisable view (paths as strings, tuples as lists). Key order is fixed."""
        out: Dict[str, Any] = {}
        for f in fields(self):
            v = getattr(self, f.name)
            if f.name in ("il2cpp", "unity", "limits"):
                v = {sf.name: getattr(v, sf.name) for sf in fields(v)}
                if f.name == "il2cpp":
                    v["backend_order"] = list(v["backend_order"])
            elif isinstance(v, Path):
                v = str(v)
            elif isinstance(v, tuple):
                v = list(v)
            out[f.name] = v
        return out

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Config":
        cfg = cls()
        for f in fields(cls):
            if f.name not in d:
                continue
            v = d[f.name]
            if f.name == "il2cpp":
                cfg.il2cpp = Il2cppConfig(**{k: v[k] for k in v if k in Il2cppConfig.__dataclass_fields__})
            elif f.name == "unity":
                cfg.unity = UnityConfig(**{k: v[k] for k in v if k in UnityConfig.__dataclass_fields__})
            elif f.name == "limits":
                cfg.limits = LimitsConfig(**{k: v[k] for k in v if k in LimitsConfig.__dataclass_fields__})
            elif f.name in ("output_dir", "libs_user_path", "engines_user_dir"):
                setattr(cfg, f.name, Path(v) if v is not None else None)
            elif f.name in ("formats", "skip", "extract"):
                setattr(cfg, f.name, tuple(v))
            elif f.name == "stages":
                setattr(cfg, f.name, tuple(v) if v is not None else None)
            else:
                setattr(cfg, f.name, v)
        return cfg
