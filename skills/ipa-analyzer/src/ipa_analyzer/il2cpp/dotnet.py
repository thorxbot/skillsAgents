"""Locate / install a .NET runtime and build the environment for launching .NET based dumpers.

* Discovery order: explicit path, ``DOTNET_ROOT``, the user-level install in the cache directory, ``PATH``,
  well-known install locations. A candidate is accepted when ``dotnet --list-runtimes`` shows a
  ``Microsoft.NETCore.App`` whose major version is at least ``min_major``.
* Installation uses Microsoft's official ``dotnet-install`` script into the cache directory (user level,
  no admin rights) and only after consent (``Config.assume_yes`` or an interactive confirmation).
* ``DOTNET_ROLL_FORWARD=Major`` lets tools built for an older runtime (net6/net7) run on a newer one.
  Verified 2026-10-03: Il2CppDumper v6.7.46 net6/net7 builds exit 150 on a machine with only
  Microsoft.NETCore.App 8.0.25 unless DOTNET_ROLL_FORWARD=Major (or LatestMajor) is set.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Mapping, Optional, Sequence

from ..util import paths as _paths
from ..util import procs as _procs
from . import Il2CppErrorCode
from .errors import ToolDownloadError, remediation_for

log = logging.getLogger(__name__)

RUNTIME_NAME = "Microsoft.NETCore.App"
DEFAULT_ROLL_FORWARD = "Major"
DEFAULT_CHANNEL = "8.0"
# Source: https://learn.microsoft.com/dotnet/core/tools/dotnet-environment-variables (DOTNET_ROLL_FORWARD:
# Disable | LatestPatch | Minor | LatestMinor | Major | LatestMajor). Verified for Major/LatestMajor, see module docstring.
ROLL_FORWARD_VALUES = ("Disable", "LatestPatch", "Minor", "LatestMinor", "Major", "LatestMajor")

_RUNTIME_LINE = re.compile(r"^\s*(?P<name>[A-Za-z0-9_.]+)\s+(?P<version>\S+)\s+\[(?P<path>.*)\]\s*$")


@dataclass(frozen=True)
class RuntimeInfo:
    name: str
    version: str
    path: str = ""

    @property
    def major(self) -> int:
        m = re.match(r"(\d+)", self.version)
        return int(m.group(1)) if m else 0

    @property
    def version_tuple(self) -> tuple:
        return tuple(int(x) for x in re.findall(r"\d+", self.version.split("-", 1)[0])[:3])


def parse_runtimes(text: str) -> List[RuntimeInfo]:
    """Parse ``dotnet --list-runtimes`` output (``Microsoft.NETCore.App 8.0.25 [/path]`` per line)."""
    out: List[RuntimeInfo] = []
    for line in text.splitlines():
        m = _RUNTIME_LINE.match(line)
        if m:
            out.append(RuntimeInfo(m.group("name"), m.group("version"), m.group("path")))
    return out


def best_runtime_major(runtimes: Sequence[RuntimeInfo]) -> Optional[int]:
    majors = [r.major for r in runtimes if r.name == RUNTIME_NAME]
    return max(majors) if majors else None


# --- discovery ---------------------------------------------------------------------------------------------
def dotnet_exe_name(system: Optional[str] = None) -> str:
    return "dotnet.exe" if (system or sys_platform_name()) == "Windows" else "dotnet"


def sys_platform_name() -> str:
    import platform
    return platform.system()


def cached_dotnet_dir(cache_root: Optional[Path] = None) -> Path:
    return (Path(cache_root) if cache_root is not None else _paths.cache_dir()) / "dotnet"


def _well_known(system: str, env: Mapping[str, str]) -> List[Path]:
    if system == "Windows":
        out = []
        for key in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"):
            if env.get(key):
                out.append(Path(env[key]) / "dotnet" / "dotnet.exe")
        out.append(Path(r"C:\Program Files\dotnet\dotnet.exe"))
        return out
    if system == "Darwin":
        return [Path("/usr/local/share/dotnet/dotnet"), Path("/opt/homebrew/bin/dotnet"),
                Path("/opt/homebrew/opt/dotnet/libexec/dotnet"), Path.home() / ".dotnet" / "dotnet"]
    return [Path("/usr/share/dotnet/dotnet"), Path("/usr/lib/dotnet/dotnet"), Path("/usr/lib64/dotnet/dotnet"),
            Path("/usr/local/share/dotnet/dotnet"), Path("/snap/bin/dotnet"), Path.home() / ".dotnet" / "dotnet"]


def iter_dotnet_candidates(explicit: Optional[str] = None, *, cache_root: Optional[Path] = None,
                           env: Optional[Mapping[str, str]] = None, system: Optional[str] = None) -> Iterator[Path]:
    """Yield existing ``dotnet`` executables in discovery order (no duplicates)."""
    env = os.environ if env is None else env
    system = system or sys_platform_name()
    seen: set = set()

    def emit(p: Optional[Path]) -> Iterator[Path]:
        if p is None:
            return
        try:
            ok = p.is_file()
            key = str(p.resolve())
        except OSError:
            return
        if ok and key not in seen:
            seen.add(key)
            yield p

    if explicit:
        p = Path(explicit)
        if p.is_dir():
            p = p / dotnet_exe_name(system)
        yield from emit(p)
        return
    root = env.get("DOTNET_ROOT")
    if root:
        yield from emit(Path(root) / dotnet_exe_name(system))
    yield from emit(cached_dotnet_dir(cache_root) / dotnet_exe_name(system))
    which = shutil.which(dotnet_exe_name(system), path=env.get("PATH"))
    if which:
        yield from emit(Path(which))
    for p in _well_known(system, env):
        yield from emit(p)


def find_dotnet(explicit: Optional[str] = None, *, cache_root: Optional[Path] = None,
                env: Optional[Mapping[str, str]] = None, system: Optional[str] = None) -> Optional[Path]:
    """First existing ``dotnet`` executable (does not check runtime versions)."""
    for p in iter_dotnet_candidates(explicit, cache_root=cache_root, env=env, system=system):
        return p
    return None


def list_runtimes(dotnet: Path, *, timeout: float = 30.0, env: Optional[Mapping[str, str]] = None
                  ) -> List[RuntimeInfo]:
    """Runtimes reported by ``dotnet --list-runtimes`` (empty list when the command fails)."""
    run_env = _procs.minimal_env({"DOTNET_ROOT": str(Path(dotnet).resolve().parent), **dict(env or {}),
                                  "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_NOLOGO": "1"})
    res = _procs.run([str(dotnet), "--list-runtimes"], timeout=timeout, env=run_env)
    if not res.ok:
        log.debug("dotnet --list-runtimes failed: %s %s", res.returncode, res.error or res.stderr[-200:])
        return []
    return parse_runtimes(res.stdout)


# --- results / instructions ----------------------------------------------------------------------------------
@dataclass
class DotnetResult:
    ok: bool
    dotnet: Optional[Path] = None
    root: Optional[Path] = None
    version: str = ""
    major: int = 0
    installed: bool = False                 # installed by us during this call
    error_code: Optional[Il2CppErrorCode] = None
    message: str = ""
    remediation: str = ""
    runtimes: List[RuntimeInfo] = field(default_factory=list)


def install_instructions(system: Optional[str] = None, min_major: int = 8) -> str:
    system = system or sys_platform_name()
    major = max(min_major, 8)
    if system == "Darwin":
        return ("macOS: 'brew install --cask dotnet-sdk' / 'brew install dotnet' or the pkg from "
                "https://dotnet.microsoft.com/download (runtime %d.0 or newer)" % major)
    if system == "Windows":
        return "Windows: 'winget install Microsoft.DotNet.Runtime.%d' (or the installer from https://dotnet.microsoft.com/download)" % major
    return ("Linux: use your package manager (e.g. 'sudo apt install dotnet-runtime-%d.0', 'sudo dnf install "
            "dotnet-runtime-%d.0') or Microsoft's dotnet-install.sh into a user directory" % (major, major))


def build_install_command(system: str, script: Path, *, install_dir: Path, channel: str,
                          runtime: str = "dotnet", shell_exe: Optional[str] = None) -> List[str]:
    """Argument list that runs Microsoft's install script for a shared runtime (pure function, no I/O).

    POSIX: ``bash dotnet-install.sh --runtime dotnet --channel X --install-dir D --no-path``.
    Windows: ``powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File dotnet-install.ps1
    -Runtime dotnet -Channel X -InstallDir D -NoPath``. Options are from ``dotnet-install.sh --help`` (2026-10-03).
    """
    if system == "Windows":
        return [shell_exe or "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-File", str(script), "-Runtime", runtime, "-Channel", channel, "-InstallDir", str(install_dir),
                "-NoPath"]
    return [shell_exe or "bash", str(script), "--runtime", runtime, "--channel", channel, "--install-dir",
            str(install_dir), "--no-path"]


def build_env(dotnet: Optional[Path], *, roll_forward: str = DEFAULT_ROLL_FORWARD,
              extra: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    """Whitelisted environment for launching a .NET tool (``DOTNET_ROOT`` points at the chosen install)."""
    env: Dict[str, str] = {"DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_NOLOGO": "1",
                           "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1", "NO_COLOR": "true"}
    if roll_forward:
        env["DOTNET_ROLL_FORWARD"] = roll_forward
    if dotnet is not None:
        try:
            env["DOTNET_ROOT"] = str(Path(dotnet).resolve().parent)
        except OSError:
            env["DOTNET_ROOT"] = str(Path(dotnet).parent)
    if extra:
        env.update(extra)
    return _procs.minimal_env(env)


# --- installation --------------------------------------------------------------------------------------------
Downloader = Callable[..., Path]


def _download_script(url: str, dest_dir: Path, downloader: Optional[Downloader]) -> Path:
    from . import tools as _tools
    fn = downloader or _tools.download_file
    return fn(url, dest_dir, sha256=None, allow_unpinned=True, filename=Path(url).name)


def install_runtime(channel: str, *, cache_root: Optional[Path] = None, system: Optional[str] = None,
                    downloader: Optional[Downloader] = None, timeout_s: float = 1200.0,
                    runner: Optional[Callable[[List[str], float, Mapping[str, str]], "_procs.ProcResult"]] = None
                    ) -> Path:
    """Install the shared ``Microsoft.NETCore.App`` runtime of ``channel`` into the cache; returns the dotnet exe."""
    from . import tools as _tools
    system = system or sys_platform_name()
    catalog = _tools.load_catalog()
    script_cfg = catalog.get("dotnet", {}).get("install_script", {})
    url = script_cfg.get("ps1_url" if system == "Windows" else "sh_url") or \
        ("https://dot.net/v1/dotnet-install.ps1" if system == "Windows" else "https://dot.net/v1/dotnet-install.sh")
    install_dir = cached_dotnet_dir(cache_root)
    install_dir.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="dotnet-install-", dir=str(install_dir.parent)))
    try:
        script = _download_script(url, work, downloader)
        shell = None
        if system == "Windows":
            shell = shutil.which("powershell") or shutil.which("pwsh")
            if not shell:
                raise ToolDownloadError("PowerShell was not found; cannot run dotnet-install.ps1", "policy")
        elif not shutil.which("bash"):
            raise ToolDownloadError("bash was not found; cannot run dotnet-install.sh", "policy")
        cmd = build_install_command(system, script, install_dir=install_dir, channel=channel, shell_exe=shell)
        env = _procs.minimal_env({"DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_NOLOGO": "1"})
        log.info("installing .NET runtime %s into %s", channel, install_dir)
        res = (runner or (lambda c, t, e: _procs.run(c, t, env=e, cwd=str(work))))(cmd, timeout_s, env)
        if not res.ok:
            tail = (res.stderr or res.stdout or res.error or "").strip().splitlines()[-5:]
            raise ToolDownloadError("dotnet-install failed (exit %s): %s" % (res.returncode, " | ".join(tail)),
                                    "network")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    exe = install_dir / dotnet_exe_name(system)
    if not exe.is_file():
        raise ToolDownloadError("dotnet-install finished but %s is missing" % exe, "network")
    return exe


def ensure_runtime(min_major: int, *, explicit: Optional[str] = None, allow_install: bool = False,
                   consent_cb: Optional[Callable[[str], bool]] = None, offline: bool = False,
                   cache_root: Optional[Path] = None, channel: Optional[str] = None,
                   downloader: Optional[Downloader] = None, system: Optional[str] = None,
                   env: Optional[Mapping[str, str]] = None,
                   runtimes_fn: Optional[Callable[[Path], List[RuntimeInfo]]] = None,
                   install_fn: Optional[Callable[..., Path]] = None) -> DotnetResult:
    """Find a runtime with major >= ``min_major`` or (with consent) install one into the cache.

    ``min_major <= 0`` means the tool is self-contained: returns ok without a dotnet executable.
    Failure returns ``E_DOTNET_MISSING`` (with per-OS install guidance) or ``E_TOOL_DOWNLOAD_FAILED``
    when an authorised installation could not be completed.
    """
    system = system or sys_platform_name()
    if min_major <= 0:
        return DotnetResult(True, message="self-contained tool, no .NET needed")
    lister = runtimes_fn or (lambda d: list_runtimes(d))
    seen: List[RuntimeInfo] = []
    for cand in iter_dotnet_candidates(explicit, cache_root=cache_root, env=env, system=system):
        rts = lister(cand)
        seen.extend(rts)
        ok = [r for r in rts if r.name == RUNTIME_NAME and r.major >= min_major]
        if ok:
            best = max(ok, key=lambda r: r.version_tuple)
            return DotnetResult(True, dotnet=cand, root=Path(cand).resolve().parent, version=best.version,
                                major=best.major, runtimes=rts)
    have = best_runtime_major(seen)
    why = ("Found .NET runtime(s) up to major %d but major >= %d is required" % (have, min_major)
           if have else "No .NET runtime was found")
    guide = install_instructions(system, min_major)
    if explicit:
        return DotnetResult(False, error_code=Il2CppErrorCode.E_DOTNET_MISSING, runtimes=seen,
                            message="%s at the explicit dotnet path %s" % (why, explicit),
                            remediation="Fix --dotnet PATH or omit it. " + guide)
    consent_msg = ("Install the .NET %s runtime (user level, into %s, no admin rights) from dot.net?"
                   % (channel or DEFAULT_CHANNEL, cached_dotnet_dir(cache_root)))
    if offline:
        return DotnetResult(False, error_code=Il2CppErrorCode.E_DOTNET_MISSING, runtimes=seen,
                            message=why + " (offline mode: not installing)", remediation=guide)
    allowed = bool(allow_install) or bool(consent_cb and consent_cb(consent_msg))
    if not allowed:
        return DotnetResult(False, error_code=Il2CppErrorCode.E_DOTNET_MISSING, runtimes=seen,
                            message=why + "; installation was not authorised",
                            remediation="%s Or re-run with --yes to allow a user-level install into the cache." % guide)
    chan = channel or DEFAULT_CHANNEL
    try:
        exe = (install_fn or install_runtime)(chan, cache_root=cache_root, system=system, downloader=downloader)
    except ToolDownloadError as exc:
        return DotnetResult(False, error_code=Il2CppErrorCode.E_TOOL_DOWNLOAD_FAILED, runtimes=seen,
                            message="Installing .NET %s failed: %s" % (chan, exc.message),
                            remediation=remediation_for(Il2CppErrorCode.E_TOOL_DOWNLOAD_FAILED) + " " + guide)
    rts = lister(exe)
    ok = [r for r in rts if r.name == RUNTIME_NAME and r.major >= min_major]
    if not ok:
        return DotnetResult(False, error_code=Il2CppErrorCode.E_DOTNET_MISSING, runtimes=rts,
                            message="Installed .NET %s but it does not provide major >= %d" % (chan, min_major),
                            remediation=guide)
    best = max(ok, key=lambda r: r.version_tuple)
    return DotnetResult(True, dotnet=exe, root=Path(exe).resolve().parent, version=best.version, major=best.major,
                        installed=True, runtimes=rts)


def default_consent(assume_yes: bool) -> Callable[[str], bool]:
    """Consent callback: ``assume_yes`` -> always yes; interactive TTY -> ask; otherwise no."""
    if assume_yes:
        return lambda _msg: True

    def ask(msg: str) -> bool:
        try:
            if not (sys.stdin and sys.stdin.isatty() and sys.stdout and sys.stdout.isatty()):
                return False
            answer = input("%s [y/N] " % msg)
        except (EOFError, OSError):
            return False
        return answer.strip().lower() in ("y", "yes")

    return ask
