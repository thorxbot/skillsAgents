"""Subprocess helpers: ``shell=False``, timeouts, process-tree termination (POSIX + Windows)."""
from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import IO, List, Mapping, Optional, Sequence

log = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "win32"

# Environment variables that are safe/necessary to pass to external tools.
_ENV_WHITELIST = ("PATH", "HOME", "USERPROFILE", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "SystemRoot",
                  "COMSPEC", "PATHEXT", "LANG", "LC_ALL", "LOCALAPPDATA", "APPDATA", "XDG_CACHE_HOME",
                  "XDG_CONFIG_HOME", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy",
                  "no_proxy")
# DOTNET_* variables passed through: locating the runtime and quieting the CLI. Anything else
# (DOTNET_STARTUP_HOOKS, DOTNET_gcServer, ...) can change what code the host loads and is dropped.
_DOTNET_ENV_WHITELIST = frozenset({
    "DOTNET_ROOT", "DOTNET_ROOT_X64", "DOTNET_ROOT_ARM64", "DOTNET_ROOT(x86)", "DOTNET_ROLL_FORWARD", "DOTNET_NOLOGO",
    "DOTNET_SKIP_FIRST_TIME_EXPERIENCE", "DOTNET_CLI_TELEMETRY_OPTOUT", "DOTNET_CLI_HOME", "DOTNET_MULTILEVEL_LOOKUP",
    "DOTNET_SYSTEM_GLOBALIZATION_INVARIANT",
})


@dataclass
class ProcResult:
    cmd: List[str]
    returncode: Optional[int]
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    duration_s: float = 0.0
    error: Optional[str] = None     # e.g. executable not found

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and self.error is None


def minimal_env(extra: Optional[Mapping[str, str]] = None) -> dict:
    """Whitelisted copy of ``os.environ`` plus ``extra`` (for launching external tools)."""
    env = {k: v for k, v in os.environ.items() if k in _ENV_WHITELIST or k in _DOTNET_ENV_WHITELIST}
    if extra:
        env.update(extra)
    return env


def which_safe(cmd: str, path: Optional[str] = None, *, cwd: Optional[str] = None,
               pathext: Optional[str] = None, windows: Optional[bool] = None) -> Optional[str]:
    """Locate an executable on ``path`` (default ``$PATH``) without ever picking one from the working directory.

    ``shutil.which`` searches the current directory first on Windows (and treats empty ``PATH`` entries as the
    current directory on POSIX), so a file dropped next to the user would run instead of the real tool. Here
    empty entries, ``.`` and any entry that resolves to ``cwd`` are skipped. A ``cmd`` that already contains a
    directory component is returned as is when it is an executable file.
    """
    win = IS_WINDOWS if windows is None else windows
    cwd_real = os.path.normcase(os.path.realpath(cwd if cwd is not None else os.getcwd()))

    def usable(p: str) -> bool:
        return os.path.isfile(p) and os.access(p, os.X_OK)

    exts = [""]
    if win:
        raw = pathext if pathext is not None else os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD")
        listed = [e for e in raw.split(";") if e]
        have_ext = os.path.splitext(cmd)[1].lower() in [e.lower() for e in listed]
        exts = [""] if have_ext else [""] + listed
    if os.path.dirname(cmd) or (win and "/" in cmd):
        return next((cmd + e for e in exts if usable(cmd + e)), None)
    search = path if path is not None else os.environ.get("PATH", "")
    seen = set()
    for d in search.split(os.pathsep):
        d = d.strip('"')
        if not d or d == os.curdir:
            continue
        real = os.path.normcase(os.path.realpath(d))
        if real == cwd_real or real in seen:
            continue
        seen.add(real)
        for e in exts:
            cand = os.path.join(d, cmd + e)
            if usable(cand):
                return cand
    return None


def taskkill_command(pid: int) -> List[str]:
    """Windows command that kills ``pid`` and its whole process tree."""
    return ["taskkill", "/PID", str(int(pid)), "/T", "/F"]


def popen(cmd: Sequence[str], *, cwd: Optional[str] = None, env: Optional[Mapping[str, str]] = None,
          stdin: object = subprocess.DEVNULL, stdout: object = subprocess.PIPE,
          stderr: object = subprocess.PIPE) -> "subprocess.Popen[bytes]":
    """``Popen`` with ``shell=False`` in its own process group / session so ``kill_tree`` works."""
    kwargs: dict = {}
    if IS_WINDOWS:
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(  # noqa: S603 - argument list, no shell
        list(cmd), cwd=cwd, env=dict(env) if env is not None else None, stdin=stdin,  # type: ignore[arg-type]
        stdout=stdout, stderr=stderr, shell=False, **kwargs)  # type: ignore[arg-type]


def kill_tree(proc: "subprocess.Popen[bytes]", *, grace_s: float = 0.0) -> None:
    """Terminate ``proc`` and all its descendants.

    POSIX: signals the process group (only when ``proc`` leads its own group, i.e. it was started
    through :func:`popen`; otherwise just ``proc``). Windows: ``taskkill /T /F``. Never raises.
    """
    if proc.poll() is not None and not _has_group_members(proc):
        return
    try:
        if IS_WINDOWS:
            try:
                subprocess.run(taskkill_command(proc.pid), stdout=subprocess.DEVNULL,  # noqa: S603
                               stderr=subprocess.DEVNULL, timeout=15, check=False)
            except (OSError, subprocess.SubprocessError):
                pass
            try:
                proc.kill()
            except OSError:
                pass
        else:
            pgid = None
            try:
                pgid = os.getpgid(proc.pid)
            except OSError:
                pass
            own_group = pgid is not None and pgid == proc.pid
            if own_group:
                if grace_s > 0:
                    _signal_group(proc.pid, signal.SIGTERM)
                    deadline = time.monotonic() + grace_s
                    while time.monotonic() < deadline and proc.poll() is None:
                        time.sleep(0.02)
                _signal_group(proc.pid, signal.SIGKILL)
            else:
                try:
                    proc.kill()
                except OSError:
                    pass
        try:
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            pass
    except Exception:  # noqa: BLE001
        log.debug("kill_tree failed", exc_info=True)


def _has_group_members(proc: "subprocess.Popen[bytes]") -> bool:
    if IS_WINDOWS:
        return False
    try:
        os.killpg(proc.pid, 0)
        return True
    except OSError:
        return False


def _signal_group(pgid: int, sig: int) -> None:
    try:
        os.killpg(pgid, sig)
    except OSError:
        pass


def run(cmd: Sequence[str], timeout: float, env: Optional[Mapping[str, str]] = None, cwd: Optional[str] = None,
        input: Optional[bytes] = None, stdin: Optional[IO[bytes]] = None) -> ProcResult:
    """Run ``cmd`` (argument list) with a hard timeout; the process tree is killed on timeout.

    stdin is closed (``/dev/null``) unless ``input``/``stdin`` is given. Output is decoded as UTF-8
    with replacement. A missing executable yields ``ProcResult(error=...)`` instead of raising.
    """
    cmd = [str(c) for c in cmd]
    started = time.monotonic()
    try:
        proc = popen(cmd, cwd=cwd, env=env,
                     stdin=subprocess.PIPE if input is not None else (stdin or subprocess.DEVNULL))
    except OSError as exc:
        return ProcResult(cmd, None, error="%s: %s" % (type(exc).__name__, exc),
                          duration_s=time.monotonic() - started)
    timed_out = False
    try:
        out, err = proc.communicate(input=input, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        kill_tree(proc)
        try:
            out, err = proc.communicate(timeout=5)
        except Exception:  # noqa: BLE001
            out, err = b"", b""
    except BaseException:
        kill_tree(proc)
        raise
    else:
        # Reap stragglers that outlived the main process but share its group.
        if not IS_WINDOWS and _has_group_members(proc):
            _signal_group(proc.pid, signal.SIGKILL)
    return ProcResult(
        cmd=cmd, returncode=proc.returncode,
        stdout=(out or b"").decode("utf-8", errors="replace"),
        stderr=(err or b"").decode("utf-8", errors="replace"),
        timed_out=timed_out, duration_s=time.monotonic() - started)
