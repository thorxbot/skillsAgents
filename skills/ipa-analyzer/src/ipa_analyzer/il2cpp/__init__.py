"""IL2CPP dump contract: request/result types, error codes, backend Protocol (frozen).

WP6 implements ``tools.py``, ``dotnet.py``, ``runner.py``, ``backends.py`` and ``summarize.py`` and
replaces ``run_il2cpp_dump`` by re-exporting the real implementation from ``runner.py`` while
keeping this signature.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from ..config import Config

__all__ = ["Il2CppErrorCode", "Il2CppRunRequest", "Il2CppRunResult", "ProvisionResult", "Il2CppBackend",
           "run_il2cpp_dump"]


class Il2CppErrorCode(str, Enum):
    E_BINARY_FAIRPLAY = "E_BINARY_FAIRPLAY"
    E_METADATA_ENCRYPTED = "E_METADATA_ENCRYPTED"
    E_METADATA_VERSION_UNSUPPORTED = "E_METADATA_VERSION_UNSUPPORTED"
    E_REGISTRATION_NOT_FOUND = "E_REGISTRATION_NOT_FOUND"
    E_DOTNET_MISSING = "E_DOTNET_MISSING"
    E_TOOL_DOWNLOAD_FAILED = "E_TOOL_DOWNLOAD_FAILED"
    E_TIMEOUT = "E_TIMEOUT"
    E_UNKNOWN = "E_UNKNOWN"


@dataclass
class Il2CppRunRequest:
    binary_path: Path                      # thin (single-arch) Mach-O, already extracted to disk
    metadata_path: Path                    # global-metadata.dat
    out_dir: Path                          # where dump artifacts are collected
    unity_version: Optional[str] = None    # cross-checked Unity version, if known
    metadata_version: Optional[int] = None
    force_dump: bool = False
    timeout_s: int = 900
    work_dir: Optional[Path] = None        # scratch dir for working copies
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Il2CppRunResult:
    ok: bool
    error_code: Optional[Il2CppErrorCode] = None
    message: str = ""
    remediation: str = ""                  # English fallback; i18n keyed by error code
    backend: str = ""
    backend_version: str = ""
    out_dir: Optional[Path] = None
    artifacts: Dict[str, str] = field(default_factory=dict)   # logical name -> path relative to out_dir
    stdout_tail: List[str] = field(default_factory=list)
    stderr_tail: List[str] = field(default_factory=list)
    duration_s: float = 0.0
    cached: bool = False
    attempts: List[Dict[str, Any]] = field(default_factory=list)   # [{backend, ok, error_code}]


@dataclass
class ProvisionResult:
    ok: bool
    command: List[str] = field(default_factory=list)   # argv prefix that launches the backend
    version: str = ""
    error_code: Optional[Il2CppErrorCode] = None
    message: str = ""


@runtime_checkable
class Il2CppBackend(Protocol):
    name: str

    def supports(self, meta_version: Optional[int], unity_version: Optional[str]) -> bool: ...

    def provision(self, tools: Any, cfg: Config) -> ProvisionResult: ...

    def run(self, req: Il2CppRunRequest, provisioned: ProvisionResult, cfg: Config) -> Il2CppRunResult: ...


def run_il2cpp_dump(req: Il2CppRunRequest, tools: Any, cfg: Config) -> Il2CppRunResult:
    """Run the backend chain for ``req`` (implemented by WP6 in ``runner.py``)."""
    raise NotImplementedError("run_il2cpp_dump is provided by WP6 (il2cpp/runner.py)")
