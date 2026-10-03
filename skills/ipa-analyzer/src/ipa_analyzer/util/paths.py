"""Cross-platform path helpers: cache / user-data directories, containment checks, name sanitising."""
from __future__ import annotations

import os
import platform
import re
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from typing import Mapping, Optional, Union

APP_DIR_NAME = "ipa-analyzer"
ENV_HOME = "IPA_ANALYZER_HOME"


def _system(system: Optional[str]) -> str:
    return system or platform.system()


def _pure_dirs(system: str, env: Mapping[str, str], home: PurePath, kind: str) -> PurePath:
    """Pure (no I/O) directory resolution so Windows rules are testable on any host."""
    override = env.get(ENV_HOME)
    if override:
        return (PureWindowsPath if system == "Windows" else PurePosixPath)(override)
    if system == "Darwin":
        base = PurePosixPath(home.as_posix())
        return base / "Library" / ("Caches" if kind == "cache" else "Application Support") / APP_DIR_NAME
    if system == "Windows":
        wh = PureWindowsPath(str(home))
        if kind == "cache":
            root = PureWindowsPath(env["LOCALAPPDATA"]) if env.get("LOCALAPPDATA") else wh / "AppData" / "Local"
            return root / APP_DIR_NAME / "cache"
        root = PureWindowsPath(env["APPDATA"]) if env.get("APPDATA") else wh / "AppData" / "Roaming"
        return root / APP_DIR_NAME
    base = PurePosixPath(home.as_posix())
    if kind == "cache":
        xdg = env.get("XDG_CACHE_HOME")
        return (PurePosixPath(xdg) if xdg else base / ".cache") / APP_DIR_NAME
    xdg = env.get("XDG_CONFIG_HOME")
    return (PurePosixPath(xdg) if xdg else base / ".config") / APP_DIR_NAME


def cache_dir(*, env: Optional[Mapping[str, str]] = None, system: Optional[str] = None,
              home: Optional[Path] = None) -> Path:
    """Cache directory (tools, .NET runtime, downloads).

    ``IPA_ANALYZER_HOME`` (if set) is used as-is; otherwise macOS ``~/Library/Caches/ipa-analyzer``,
    Linux ``${XDG_CACHE_HOME:-~/.cache}/ipa-analyzer``, Windows ``%LOCALAPPDATA%\\ipa-analyzer\\cache``.
    Pure resolution: the directory is not created.
    """
    return Path(str(_pure_dirs(_system(system), os.environ if env is None else env,
                               home or Path.home(), "cache")))


def user_data_dir(*, env: Optional[Mapping[str, str]] = None, system: Optional[str] = None,
                  home: Optional[Path] = None) -> Path:
    """Directory for user-editable data (``libs.user.json``, ``engines.user.d/``).

    ``IPA_ANALYZER_HOME`` if set, else macOS ``~/Library/Application Support/ipa-analyzer``,
    Linux ``${XDG_CONFIG_HOME:-~/.config}/ipa-analyzer``, Windows ``%APPDATA%\\ipa-analyzer``.
    """
    return Path(str(_pure_dirs(_system(system), os.environ if env is None else env,
                               home or Path.home(), "data")))


def tools_dir() -> Path:
    return cache_dir() / "tools"


def resource_dir(name: str) -> Path:
    """Locate a bundled resource directory (``data`` / ``schemas`` / ``references``).

    Search order: ``IPA_ANALYZER_<NAME>_DIR`` env, the skill root (source tree / editable install /
    skill copy), then ``ipa_analyzer/_<name>`` inside the installed package (wheel layout).
    """
    env = os.environ.get("IPA_ANALYZER_%s_DIR" % name.upper())
    if env:
        return Path(env)
    skill_root = Path(__file__).resolve().parents[3]
    cand = skill_root / name
    if cand.is_dir():
        return cand
    pkg = Path(__file__).resolve().parents[1] / ("_" + name)
    return pkg


# --- containment ------------------------------------------------------------------------------
def _norm(p: PurePath) -> tuple:
    """(anchor, parts) after lexical ``.``/``..`` folding; Windows paths are case-folded."""
    win = isinstance(p, PureWindowsPath)
    anchor = p.anchor
    raw = p.parts[1:] if anchor else p.parts
    parts: list = []
    for part in raw:
        if part in (".", ""):
            continue
        if part == "..":
            if parts and parts[-1] != "..":
                parts.pop()
            elif not anchor:
                parts.append(part)
            continue
        parts.append(part)
    if win:
        return anchor.casefold(), tuple(x.casefold() for x in parts)
    return anchor, tuple(parts)


def is_within(base: Union[str, PurePath], p: Union[str, PurePath], *, resolve: bool = True) -> bool:
    """True if ``p`` is ``base`` or lies below it.

    With ``resolve=True`` (default) real ``Path`` objects are resolved first (symlinks, ``..``).
    With ``resolve=False`` the comparison is purely lexical (use for ``PureWindowsPath`` tests).
    Windows paths compare case-insensitively; mixing Windows and POSIX flavours is never "within".
    """
    b = base if isinstance(base, PurePath) else Path(base)
    q = p if isinstance(p, PurePath) else Path(p)
    if resolve and isinstance(b, Path) and isinstance(q, Path):
        try:
            b = b.resolve()
            q = q.resolve()
        except (OSError, RuntimeError):
            return False
    if isinstance(b, PureWindowsPath) != isinstance(q, PureWindowsPath):
        return False
    ba, bp = _norm(b)
    qa, qp = _norm(q)
    return ba == qa and len(qp) >= len(bp) and qp[:len(bp)] == bp


# --- file name sanitising ---------------------------------------------------------------------
# Source: Microsoft Learn "Naming Files, Paths, and Namespaces" (reserved names CON, PRN, AUX, NUL,
# COM1-9, LPT1-9 and the superscript-digit variants; also followed by an extension). COM0/LPT0 and
# CONIN$/CONOUT$ are NOT in that list; they are included here as a conservative extra.
_RESERVED_BASES = (
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {"COM%s" % d for d in "0123456789\u00b9\u00b2\u00b3"}
    | {"LPT%s" % d for d in "0123456789\u00b9\u00b2\u00b3"}
)
# Source: same page: < > : " / \ | ? * and control characters 0-31 are not allowed.
_ILLEGAL_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def is_windows_reserved(name: str) -> bool:
    """True for names Windows treats as devices, with or without extension (``CON``, ``nul.txt``)."""
    base = name.split(".", 1)[0].rstrip(" ").upper()
    return base in _RESERVED_BASES


def sanitize_component(name: str, *, max_len: int = 255, replacement: str = "_") -> str:
    """Make one path component safe on every platform.

    Replaces illegal characters, prefixes Windows reserved device names, strips trailing dots and
    spaces, neutralises ``.`` / ``..`` / empty names and truncates (keeping the extension).
    Never returns an empty string or a path separator.
    """
    s = _ILLEGAL_RE.sub(replacement, name)
    s = s.rstrip(" .")
    if not s:   # also covers ".", ".." and names made only of dots/spaces
        s = replacement
    if is_windows_reserved(s):
        s = replacement + s
    if len(s) > max_len:
        stem, dot, ext = s.rpartition(".")
        if dot and 0 < len(ext) <= 16 and len(ext) + 1 < max_len:
            s = stem[: max_len - len(ext) - 1] + "." + ext
        else:
            s = s[:max_len]
        s = s.rstrip(" .") or replacement
    return s


def to_long_path(path: Union[str, Path], *, system: Optional[str] = None) -> str:
    """Windows extended-length form (``\\\\?\\C:\\...`` / ``\\\\?\\UNC\\...``); identity elsewhere."""
    s = str(path)
    if _system(system) != "Windows":
        return s
    if s.startswith("\\\\?\\"):
        return s
    s = s.replace("/", "\\")
    if s.startswith("\\\\"):
        return "\\\\?\\UNC\\" + s[2:]
    if len(s) >= 2 and s[1] == ":":
        return "\\\\?\\" + s
    return s
