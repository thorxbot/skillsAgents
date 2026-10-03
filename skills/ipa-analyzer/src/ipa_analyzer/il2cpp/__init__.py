"""IL2CPP dump: frozen contract (request/result types, error codes, backend Protocol) plus the WP6 toolchain.

Submodules: ``tools`` (tool supply + ``tools`` CLI), ``dotnet`` (runtime discovery/installation),
``backends`` (Il2CppDumper / Cpp2IL / Il2CppInspectorRedux adapters), ``runner`` (non-interactive
supervised runs, ``run_il2cpp_dump``), ``summarize`` (streaming ``dump.cs`` summary), ``errors``.
The contract classes below are defined first so the submodules can import them from the package.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from ..config import Config

__all__ = ["Il2CppErrorCode", "Il2CppRunRequest", "Il2CppRunResult", "ProvisionResult", "Il2CppBackend",
           "run_il2cpp_dump", "ToolManager", "ResolvedTool", "summarize_dump", "DumpSummary", "select_backends"]


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
    # --- additive optional fields (WP6) ---
    env: Dict[str, str] = field(default_factory=dict)      # environment to launch the backend with
    tool_dir: Optional[Path] = None                        # tool-owned directory (copied per run when it holds config.json)
    kind: str = ""                                         # dotnet_dll | dotnet_apphost | native | python
    source: str = ""                                       # explicit | env | path | cache | download
    warnings: List[str] = field(default_factory=list)


@runtime_checkable
class Il2CppBackend(Protocol):
    name: str

    def supports(self, meta_version: Optional[int], unity_version: Optional[str]) -> bool: ...

    def provision(self, tools: Any, cfg: Config) -> ProvisionResult: ...

    def run(self, req: Il2CppRunRequest, provisioned: ProvisionResult, cfg: Config) -> Il2CppRunResult: ...


# The real implementation lives in runner.py (imported last: the submodules import the names above).
from .runner import run_il2cpp_dump  # noqa: E402
from .tools import ToolManager, ResolvedTool  # noqa: E402
from .summarize import summarize_dump, DumpSummary  # noqa: E402
from .backends import select_backends  # noqa: E402
