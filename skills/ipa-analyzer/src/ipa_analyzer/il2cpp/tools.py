"""Tool supply for the IL2CPP backends: catalog, resolution, verified download, install, ``tools`` CLI.

Resolution order for a backend: explicit path -> environment variable (``IL2CPPDUMPER_PATH`` ...) ->
``PATH`` -> cache -> download (HTTPS only, host allow-list, pinned SHA256, atomic install). With
``offline`` (``--offline`` / ``Config.offline``) nothing ever touches the network.

The catalog (versions, URLs, SHA256, platform assets) is ``data/il2cpp_backends.json``.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import logging
import os
import platform
import shutil
import socket
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from ..config import Config
from ..util import paths as _paths
from ..util import procs as _procs
from . import Il2CppErrorCode
from .errors import Il2CppToolError, ToolDownloadError, remediation_for

log = logging.getLogger(__name__)

CATALOG_FILE = "il2cpp_backends.json"
INSTALL_MARKER = ".install.json"
TOOL_ALIASES = {"dumper": "il2cppdumper", "il2cpp-dumper": "il2cppdumper", "il2cppdumper": "il2cppdumper",
                "perfare": "il2cppdumper", "cpp2il": "cpp2il", "il2cppinspector": "redux",
                "il2cppinspectorredux": "redux", "inspector": "redux", "redux": "redux"}


# --- catalog ------------------------------------------------------------------------------------------------
_CATALOG_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}


def catalog_path() -> Path:
    return _paths.resource_dir("data") / CATALOG_FILE


def load_catalog(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load (and cache by mtime) ``il2cpp_backends.json``. A missing/corrupt file yields an empty catalog."""
    p = Path(path) if path is not None else catalog_path()
    try:
        mtime = p.stat().st_mtime
    except OSError:
        log.warning("IL2CPP backend catalog not found: %s", p)
        return {"backends": {}, "default_order": [], "download": {}, "dotnet": {}}
    hit = _CATALOG_CACHE.get(str(p))
    if hit and hit[0] == mtime:
        return hit[1]
    try:
        with open(p, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        log.warning("IL2CPP backend catalog unreadable (%s): %s", p, exc)
        data = {"backends": {}, "default_order": [], "download": {}, "dotnet": {}}
    _CATALOG_CACHE[str(p)] = (mtime, data)
    return data


def canonical_name(name: str) -> str:
    key = name.strip().lower().replace("_", "").replace(" ", "")
    return TOOL_ALIASES.get(key, key)


@dataclass
class ToolSpec:
    name: str
    raw: Dict[str, Any]

    @property
    def version(self) -> str:
        return str(self.raw.get("version", ""))

    @property
    def display_name(self) -> str:
        return str(self.raw.get("display_name", self.name))

    @property
    def env_var(self) -> str:
        return str(self.raw.get("env_var", ""))

    @property
    def executable_names(self) -> List[str]:
        return [str(x) for x in self.raw.get("executable_names", [])]

    @property
    def assets(self) -> List[Dict[str, Any]]:
        return [a for a in self.raw.get("assets", []) if isinstance(a, dict)]

    @property
    def min_dotnet(self) -> int:
        return int(self.raw.get("dotnet", {}).get("min_major", 0) or 0)

    @property
    def roll_forward(self) -> str:
        return str(self.raw.get("dotnet", {}).get("roll_forward", "") or "")

    @property
    def install_channel(self) -> str:
        return str(self.raw.get("dotnet", {}).get("install_channel", "") or "")

    def asset_by_id(self, asset_id: str) -> Optional[Dict[str, Any]]:
        for a in self.assets:
            if a.get("id") == asset_id:
                return a
        return None


# --- platform ----------------------------------------------------------------------------------------------
def norm_arch(machine: str) -> str:
    m = machine.lower()
    if m in ("arm64", "aarch64", "armv8", "armv8l"):
        return "arm64"
    if m in ("x86_64", "amd64", "x64"):
        return "x86_64"
    return m


def norm_system(system: str) -> str:
    s = system.lower()
    return {"darwin": "darwin", "windows": "windows", "linux": "linux"}.get(s, s)


def platform_matches(platforms: Sequence[str], system: str, machine: str) -> bool:
    """``platforms`` entries: ``any``, ``windows``, ``linux``, ``darwin-arm64``, ``linux-aarch64`` ..."""
    sysn, arch = norm_system(system), norm_arch(machine)
    for entry in platforms:
        e = entry.lower()
        if e == "any":
            return True
        head, _, tail = e.partition("-")
        if norm_system(head) != sysn:
            continue
        if not tail or norm_arch(tail) == arch:
            return True
    return False


def preferred_asset_ids(spec: ToolSpec, *, system: str, machine: str, dotnet_available: bool = True) -> List[str]:
    """Asset ids usable on this platform, best first (pure function)."""
    usable = [str(a["id"]) for a in spec.assets
              if platform_matches(a.get("platforms", []), system, machine) and "id" in a]
    sel = spec.raw.get("asset_selection") or {}
    order: List[str] = []
    if norm_system(system) == "windows" and not dotnet_available and sel.get("windows_without_dotnet") in usable:
        order.append(str(sel["windows_without_dotnet"]))
    if sel.get("default") in usable:
        order.append(str(sel["default"]))
    order.extend(i for i in usable if i not in order)
    return order


# --- download -----------------------------------------------------------------------------------------------
@dataclass
class DownloadPolicy:
    allowed_hosts: Tuple[str, ...] = ("github.com", "release-assets.githubusercontent.com",
                                      "objects.githubusercontent.com", "dot.net", "builds.dotnet.microsoft.com",
                                      "aka.ms")
    require_https: bool = True
    max_bytes: int = 200 * 1024 * 1024
    timeout_s: float = 60.0
    retries: int = 3
    backoff_s: float = 0.5
    max_redirects: int = 8
    user_agent: str = "ipa-analyzer/0.1 (+tool-provisioning)"

    @classmethod
    def from_catalog(cls, catalog: Mapping[str, Any]) -> "DownloadPolicy":
        d = catalog.get("download", {}) if isinstance(catalog, Mapping) else {}
        base = cls()
        return cls(allowed_hosts=tuple(d.get("allowed_hosts", base.allowed_hosts)),
                   max_bytes=int(d.get("max_bytes", base.max_bytes)),
                   timeout_s=float(d.get("timeout_s", base.timeout_s)),
                   retries=int(d.get("retries", base.retries)))


def check_url(url: str, policy: DownloadPolicy) -> None:
    """Raise ``ToolDownloadError(reason='policy')`` unless ``url`` is HTTPS (if required) on an allowed host."""
    parts = urllib.parse.urlsplit(url)
    if policy.require_https and parts.scheme != "https":
        raise ToolDownloadError("refusing non-HTTPS URL: %s" % _safe_url(url), "policy")
    if parts.scheme not in ("https", "http"):
        raise ToolDownloadError("unsupported URL scheme: %s" % parts.scheme, "policy")
    host = (parts.hostname or "").lower()
    if not host or host not in {h.lower() for h in policy.allowed_hosts}:
        raise ToolDownloadError("host %r is not in the download allow-list" % host, "policy")


def _safe_url(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, "", ""))


class _PolicyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validates every redirect target against the policy (HTTPS + host allow-list)."""

    def __init__(self, policy: DownloadPolicy) -> None:
        self.policy = policy
        self.hops = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        check_url(newurl, self.policy)
        self.hops += 1
        if self.hops > self.policy.max_redirects:
            raise ToolDownloadError("too many redirects", "policy")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_file(url: str, dest_dir: Path, *, sha256: Optional[str], policy: Optional[DownloadPolicy] = None,
                  filename: Optional[str] = None, expected_size: Optional[int] = None, allow_unpinned: bool = False,
                  sleep: Callable[[float], None] = time.sleep) -> Path:
    """Download ``url`` into ``dest_dir`` and verify SHA256; returns the final path.

    Only HTTPS and allow-listed hosts (also for every redirect hop). The payload is streamed into a
    ``.part`` file while hashing and renamed on success; any failure removes the partial file. A missing
    ``sha256`` is refused unless ``allow_unpinned`` (used for Microsoft's install script only).
    Proxy settings come from the standard ``HTTPS_PROXY``/``NO_PROXY`` environment variables.
    """
    policy = policy or DownloadPolicy()
    if not sha256 and not allow_unpinned:
        raise ToolDownloadError("no pinned SHA256 for %s; refusing automatic download" % _safe_url(url), "unpinned")
    check_url(url, policy)
    dest_dir.mkdir(parents=True, exist_ok=True)
    name = filename or PurePosixPath(urllib.parse.urlsplit(url).path).name or "download.bin"
    name = _paths.sanitize_component(name)
    final = dest_dir / name
    last_exc: Optional[Exception] = None
    attempts = max(1, policy.retries)
    for attempt in range(attempts):
        part = dest_dir / (".%s.%s.part" % (name, uuid.uuid4().hex[:8]))
        try:
            return _download_once(url, part, final, sha256, policy, expected_size)
        except ToolDownloadError as exc:
            _rm(part)
            if exc.reason in ("policy", "sha256", "size", "unpinned", "http"):
                raise
            last_exc = exc
        except (urllib.error.URLError, socket.timeout, ConnectionError, http.client.HTTPException, OSError) as exc:
            _rm(part)
            last_exc = exc
        if attempt + 1 < attempts:
            sleep(policy.backoff_s * (2 ** attempt))
    raise ToolDownloadError("download of %s failed after %d attempt(s): %s" % (_safe_url(url), attempts, last_exc),
                            "network")


def _rm(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def _download_once(url: str, part: Path, final: Path, sha256: Optional[str], policy: DownloadPolicy,
                   expected_size: Optional[int]) -> Path:
    handler = _PolicyRedirectHandler(policy)
    opener = urllib.request.build_opener(handler)
    req = urllib.request.Request(url, headers={"User-Agent": policy.user_agent, "Accept": "*/*"})
    h = hashlib.sha256()
    total = 0
    try:
        with opener.open(req, timeout=policy.timeout_s) as resp:
            final_url = getattr(resp, "url", url) or url
            check_url(final_url, policy)
            clen = resp.headers.get("Content-Length")
            if clen and clen.isdigit() and int(clen) > policy.max_bytes:
                raise ToolDownloadError("Content-Length %s exceeds the %d byte limit" % (clen, policy.max_bytes), "size")
            with open(part, "wb") as out:
                while True:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > policy.max_bytes:
                        raise ToolDownloadError("download exceeds the %d byte limit" % policy.max_bytes, "size")
                    h.update(chunk)
                    out.write(chunk)
            if clen and clen.isdigit() and int(clen) != total:
                raise http.client.IncompleteRead(b"", int(clen) - total)
    except urllib.error.HTTPError as exc:
        if 400 <= exc.code < 500 and exc.code != 429:
            raise ToolDownloadError("HTTP %d for %s" % (exc.code, _safe_url(url)), "http")
        raise
    if expected_size is not None and total != expected_size:
        raise ToolDownloadError("size mismatch: got %d bytes, catalog says %d" % (total, expected_size), "size")
    digest = h.hexdigest()
    if sha256 and digest.lower() != sha256.lower():
        raise ToolDownloadError("SHA256 mismatch for %s: expected %s, got %s" % (final.name, sha256, digest), "sha256")
    os.replace(str(part), str(final))
    return final


# --- safe archive extraction ---------------------------------------------------------------------------------
def _unsafe_member(name: str) -> bool:
    n = name.replace("\\", "/")
    if not n or n.startswith("/") or n.startswith("//"):
        return True
    if len(n) >= 2 and n[1] == ":":
        return True
    parts = [p for p in n.split("/") if p not in ("", ".")]
    return any(p == ".." for p in parts) or "\x00" in n or PureWindowsPath(name).drive != ""


def safe_extract_zip(zip_path: Path, dest: Path, *, max_total: int = 1024 * 1024 * 1024, max_files: int = 5000,
                     max_ratio: float = 1000.0) -> List[Path]:
    """Extract ``zip_path`` into ``dest`` refusing path traversal, symlinks, zip bombs and Windows-illegal names."""
    dest.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    total = 0
    try:
        zf = zipfile.ZipFile(str(zip_path))
    except (zipfile.BadZipFile, OSError) as exc:
        raise ToolDownloadError("archive is not a valid zip: %s" % exc, "sha256")
    with zf:
        infos = zf.infolist()
        if len(infos) > max_files:
            raise ToolDownloadError("archive has too many entries (%d)" % len(infos), "policy")
        for info in infos:
            name = info.filename
            if _unsafe_member(name):
                raise ToolDownloadError("unsafe path in archive: %r" % name, "policy")
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                log.debug("skipping symlink entry %s", name)
                continue
            parts = [_paths.sanitize_component(p) for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
            if info.is_dir():
                (dest.joinpath(*parts)).mkdir(parents=True, exist_ok=True)
                continue
            if not parts:
                continue
            if info.compress_size and info.file_size / max(1, info.compress_size) > max_ratio and info.file_size > 1 << 20:
                raise ToolDownloadError("suspicious compression ratio for %r" % name, "policy")
            target = dest.joinpath(*parts)
            if not _paths.is_within(dest, target):
                raise ToolDownloadError("unsafe path in archive: %r" % name, "policy")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                while True:
                    chunk = src.read(1 << 20)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_total:
                        raise ToolDownloadError("archive expands beyond %d bytes" % max_total, "policy")
                    out.write(chunk)
            if mode & 0o111 and os.name != "nt":
                try:
                    target.chmod(target.stat().st_mode | 0o111)
                except OSError:
                    pass
            written.append(target)
    return written


def make_executable(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError as exc:
        log.debug("chmod +x failed for %s: %s", path, exc)


def adhoc_codesign(path: Path, *, system: Optional[str] = None) -> Optional[str]:
    """macOS arm64 kills unsigned downloaded Mach-O executables (exit 137); ad-hoc signing fixes that.

    Verified 2026-10-03: ``codesign -s - --force <file>`` made Cpp2IL's OSX-ARM64 build start. Returns a
    warning string on failure, ``None`` on success or when not applicable.
    """
    if (system or platform.system()) != "Darwin":
        return None
    exe = shutil.which("codesign")
    if not exe:
        return "codesign not found; the downloaded executable may be killed by macOS (run: codesign -s - --force %s)" % path
    res = _procs.run([exe, "-s", "-", "--force", str(path)], timeout=60)
    if not res.ok:
        return "ad-hoc codesign failed for %s: %s" % (path.name, (res.stderr or res.error or "").strip()[:200])
    return None


# --- resolution ----------------------------------------------------------------------------------------------
@dataclass
class ResolvedTool:
    ok: bool
    name: str
    version: str = ""
    source: str = ""                      # explicit | env | path | cache | download
    kind: str = ""                        # dotnet_dll | dotnet_apphost | native | python
    entry: Optional[Path] = None
    command: List[str] = field(default_factory=list)   # launch prefix WITHOUT the dotnet host
    tool_dir: Optional[Path] = None
    min_dotnet: int = 0
    uses_dotnet_env: bool = False         # a self-contained-or-not .exe: pass DOTNET_* env when dotnet is known
    asset_id: str = ""
    error_code: Optional[Il2CppErrorCode] = None
    message: str = ""
    remediation: str = ""
    warnings: List[str] = field(default_factory=list)


def _read_runtimeconfig_major(dll: Path) -> int:
    cfg = dll.with_name(dll.stem + ".runtimeconfig.json")
    try:
        data = json.loads(cfg.read_text(encoding="utf-8"))
        ver = data["runtimeOptions"]["framework"]["version"]
        return int(str(ver).split(".")[0])
    except (OSError, ValueError, KeyError, TypeError):
        return 0


def _find_entry(root: Path, names: Sequence[str], max_depth: int = 3) -> Optional[Path]:
    """Shallowest file under ``root`` whose name equals one of ``names`` (earlier names win on ties)."""
    wanted = [n.lower() for n in names]
    best: Optional[Tuple[int, int, Path]] = None
    base_depth = len(root.parts)
    try:
        for dirpath, dirnames, filenames in os.walk(str(root)):
            depth = len(Path(dirpath).parts) - base_depth
            if depth >= max_depth:
                dirnames[:] = []
            for fn in filenames:
                low = fn.lower()
                if low in wanted:
                    cand = (depth, wanted.index(low), Path(dirpath) / fn)
                    if best is None or cand[:2] < best[:2]:
                        best = cand
    except OSError:
        return None
    return best[2] if best else None


class ToolManager:
    """Resolve / install the external IL2CPP tools (and know the consent policy for .NET installs)."""

    def __init__(self, cfg: Optional[Config] = None, *, cache_root: Optional[Path] = None,
                 offline: Optional[bool] = None, consent: Optional[Callable[[str], bool]] = None,
                 downloader: Optional[Callable[..., Path]] = None, catalog: Optional[Dict[str, Any]] = None,
                 policy: Optional[DownloadPolicy] = None, system: Optional[str] = None,
                 machine: Optional[str] = None, env: Optional[Mapping[str, str]] = None) -> None:
        self.cfg = cfg or Config()
        self.cache_root = Path(cache_root) if cache_root is not None else None
        self.offline = bool(self.cfg.offline if offline is None else offline)
        from .dotnet import default_consent
        self.consent = consent or default_consent(self.cfg.assume_yes)
        self.catalog = catalog if catalog is not None else load_catalog()
        self.policy = policy or DownloadPolicy.from_catalog(self.catalog)
        self._downloader = downloader or download_file
        self.system = system or platform.system()
        self.machine = machine or platform.machine()
        self.env = os.environ if env is None else env

    # -- layout
    @property
    def cache(self) -> Path:
        return self.cache_root if self.cache_root is not None else _paths.cache_dir()

    @property
    def tools_root(self) -> Path:
        return self.cache / "tools"

    def names(self) -> List[str]:
        order = [n for n in self.catalog.get("default_order", []) if n in self.catalog.get("backends", {})]
        rest = [n for n in self.catalog.get("backends", {}) if n not in order]
        return order + rest

    def spec(self, name: str) -> ToolSpec:
        cname = canonical_name(name)
        raw = self.catalog.get("backends", {}).get(cname)
        if raw is None:
            raise KeyError("unknown IL2CPP tool %r (known: %s)" % (name, ", ".join(self.names())))
        return ToolSpec(cname, raw)

    # -- resolution
    def _explicit_for(self, spec: ToolSpec, explicit: Optional[str]) -> Optional[str]:
        if explicit:
            return explicit
        if spec.name == "il2cppdumper" and self.cfg.il2cpp.tool_path:
            return str(self.cfg.il2cpp.tool_path)
        return None

    def resolve(self, name: str, *, install: bool = False, explicit: Optional[str] = None,
                dotnet_available: bool = True) -> ResolvedTool:
        """Find ``name`` (explicit -> env -> PATH -> cache -> download when ``install``)."""
        try:
            spec = self.spec(name)
        except KeyError as exc:
            return ResolvedTool(False, name, error_code=Il2CppErrorCode.E_TOOL_DOWNLOAD_FAILED, message=str(exc.args[0] if exc.args else exc))
        exp = self._explicit_for(spec, explicit)
        if exp:
            res = self.from_path(spec, Path(exp).expanduser(), "explicit")
            if not res.ok:
                res.remediation = ("Fix the path given with --il2cpp-tool, or remove it to use the automatic "
                                   "download. " + remediation_for(Il2CppErrorCode.E_TOOL_DOWNLOAD_FAILED))
            return res
        env_val = self.env.get(spec.env_var) if spec.env_var else None
        if env_val:
            res = self.from_path(spec, Path(env_val).expanduser(), "env")
            if res.ok:
                return res
            log.warning("%s=%s is not usable: %s", spec.env_var, env_val, res.message)
        for exe in spec.executable_names + [e.lower() for e in spec.executable_names]:
            if exe.lower().endswith(".dll"):
                continue
            found = _procs.which_safe(exe, self.env.get("PATH"))
            if found:
                res = self.from_path(spec, Path(found), "path")
                if res.ok:
                    return res
        cached = self._from_cache(spec, dotnet_available)
        if cached is not None:
            return cached
        if not install:
            return ResolvedTool(False, spec.name, error_code=Il2CppErrorCode.E_TOOL_DOWNLOAD_FAILED,
                                message="%s is not installed (cache: %s)" % (spec.display_name, self.tools_root),
                                remediation="Run 'ipa-analyze tools install %s' (needs network) or pass "
                                            "--il2cpp-tool PATH." % spec.name)
        return self.install(spec.name, dotnet_available=dotnet_available)

    def from_path(self, spec: ToolSpec, p: Path, source: str) -> ResolvedTool:
        """Interpret a user supplied path (file or directory) as a launchable tool."""
        err = ResolvedTool(False, spec.name, source=source, error_code=Il2CppErrorCode.E_TOOL_DOWNLOAD_FAILED)
        p = Path(os.path.abspath(os.path.expanduser(str(p))))   # the dumper runs in another cwd: a relative path would break
        if not p.exists():
            err.message = "tool path does not exist: %s" % p
            return err
        entry: Optional[Path] = p
        if p.is_dir():
            names = spec.executable_names + [str(a.get("entry")) for a in spec.assets if a.get("entry")]
            entry = _find_entry(p, names)
            if entry is None:
                err.message = "no %s executable found inside %s" % (spec.display_name, p)
                return err
        assert entry is not None
        suffix = entry.suffix.lower()
        if suffix == ".exe" and norm_system(self.system) != "windows":
            sibling = entry.with_suffix(".dll")
            if sibling.is_file():
                entry, suffix = sibling, ".dll"
        kind = "native"
        min_dotnet = 0
        uses_env = False
        command = [str(entry)]
        if suffix == ".py":
            kind, command = "python", [sys.executable, str(entry)]
        elif suffix == ".dll":
            kind = "dotnet_dll"
            min_dotnet = _read_runtimeconfig_major(entry) or spec.min_dotnet or 6
        else:
            if norm_system(self.system) != "windows" and not os.access(str(entry), os.X_OK):
                err.message = "%s is not executable (chmod +x)" % entry
                return err
            asset = next((a for a in spec.assets if str(a.get("entry", "")).lower() == entry.name.lower()), None)
            if asset is not None and asset.get("kind") == "dotnet_apphost":
                kind, min_dotnet = "dotnet_apphost", int(asset.get("min_dotnet", spec.min_dotnet) or 0)
            elif spec.min_dotnet and spec.name != "il2cppdumper":
                kind, min_dotnet = "dotnet_apphost", spec.min_dotnet
            else:
                uses_env = bool(spec.roll_forward)
        tool_dir = entry.parent if (entry.parent / "config.json").is_file() and spec.name == "il2cppdumper" else None
        version, asset_id = self._installed_version_info(entry)
        return ResolvedTool(True, spec.name, version=version, source=source, kind=kind, entry=entry,
                            command=command, tool_dir=tool_dir, min_dotnet=min_dotnet, uses_dotnet_env=uses_env,
                            asset_id=asset_id)

    def _installed_version_info(self, entry: Path) -> Tuple[str, str]:
        for parent in list(entry.parents)[:5]:
            marker = parent / INSTALL_MARKER
            if marker.is_file():
                try:
                    d = json.loads(marker.read_text(encoding="utf-8"))
                    return str(d.get("version", "")), str(d.get("asset_id", ""))
                except (OSError, ValueError):
                    break
        return "", ""

    def _asset_dir(self, spec: ToolSpec, asset_id: str) -> Path:
        return self.tools_root / spec.name / spec.version / asset_id

    def _from_cache(self, spec: ToolSpec, dotnet_available: bool) -> Optional[ResolvedTool]:
        for aid in preferred_asset_ids(spec, system=self.system, machine=self.machine,
                                       dotnet_available=dotnet_available):
            d = self._asset_dir(spec, aid)
            if not (d / INSTALL_MARKER).is_file():
                continue
            asset = spec.asset_by_id(aid) or {}
            entry = _find_entry(d, [str(asset.get("entry", ""))] + spec.executable_names)
            if entry is None:
                continue
            res = self.from_path(spec, entry, "cache")
            if res.ok:
                res.version, res.asset_id = spec.version, aid
                if asset.get("kind") in ("dotnet_dll", "dotnet_apphost"):
                    res.min_dotnet = int(asset.get("min_dotnet", res.min_dotnet) or res.min_dotnet)
                return res
        return None

    # -- installation
    def install(self, name: str, *, force: bool = False, dotnet_available: bool = True,
                asset_id: Optional[str] = None) -> ResolvedTool:
        """Download, verify and install ``name`` into the cache. Never raises; check ``.ok``."""
        try:
            spec = self.spec(name)
        except KeyError as exc:
            return ResolvedTool(False, name, error_code=Il2CppErrorCode.E_TOOL_DOWNLOAD_FAILED, message=str(exc.args[0] if exc.args else exc))
        try:
            return self._install(spec, force=force, dotnet_available=dotnet_available, asset_id=asset_id)
        except ToolDownloadError as exc:
            log.warning("installing %s failed: %s", spec.name, exc.message)
            return ResolvedTool(False, spec.name, error_code=exc.code, message=exc.message,
                                remediation=_download_remediation(exc))
        except Il2CppToolError as exc:
            return ResolvedTool(False, spec.name, error_code=exc.code, message=exc.message,
                                remediation=exc.remediation)
        except OSError as exc:
            return ResolvedTool(False, spec.name, error_code=Il2CppErrorCode.E_TOOL_DOWNLOAD_FAILED,
                                message="installing %s failed: %s" % (spec.name, exc),
                                remediation=remediation_for(Il2CppErrorCode.E_TOOL_DOWNLOAD_FAILED))

    def _install(self, spec: ToolSpec, *, force: bool, dotnet_available: bool, asset_id: Optional[str]) -> ResolvedTool:
        order = [asset_id] if asset_id else preferred_asset_ids(spec, system=self.system, machine=self.machine,
                                                                dotnet_available=dotnet_available)
        if not order:
            raise ToolDownloadError("no %s build is published for %s/%s" % (spec.display_name, self.system, self.machine),
                                    "policy")
        asset = spec.asset_by_id(order[0])
        if asset is None:
            raise ToolDownloadError("unknown asset id %r for %s" % (order[0], spec.name), "policy")
        aid = str(asset["id"])
        target = self._asset_dir(spec, aid)
        if not force and (target / INSTALL_MARKER).is_file():
            cached = self._from_cache(spec, dotnet_available)
            if cached is not None:
                return cached
        if self.offline:
            raise ToolDownloadError("offline mode: %s is not cached and cannot be downloaded" % spec.display_name,
                                    "offline")
        sha = asset.get("sha256")
        if not sha:
            raise ToolDownloadError(
                "the catalog has no SHA256 for %s (%s); automatic download is refused" % (spec.display_name, aid),
                "unpinned")
        dl_dir = self.tools_root / ".downloads"
        staging = self.tools_root / (".staging-%s-%s" % (spec.name, uuid.uuid4().hex[:8]))
        warnings: List[str] = []
        archive: Optional[Path] = None
        try:
            archive = self._downloader(str(asset["url"]), dl_dir, sha256=str(sha), policy=self.policy,
                                       filename=str(asset.get("filename") or ""),
                                       expected_size=asset.get("size"))
            staging.mkdir(parents=True, exist_ok=True)
            entry_name = str(asset.get("entry") or spec.executable_names[0])
            if asset.get("archive", "zip") == "zip":
                safe_extract_zip(archive, staging)
            else:
                shutil.copyfile(str(archive), str(staging / entry_name))
            entry = _find_entry(staging, [entry_name] + spec.executable_names)
            if entry is None:
                raise ToolDownloadError("archive does not contain %s" % entry_name, "policy")
            if asset.get("kind") in ("native", "dotnet_apphost"):
                make_executable(entry)
                warn = adhoc_codesign(entry, system=self.system)
                if warn:
                    warnings.append(warn)
            marker = {"name": spec.name, "version": spec.version, "asset_id": aid, "filename": asset.get("filename"),
                      "url": asset.get("url"), "sha256": sha, "installed_at": int(time.time()),
                      "warnings": warnings}
            with open(str(staging / INSTALL_MARKER), "w", encoding="utf-8", newline="\n") as fh:   # no write_text(newline=) before 3.10
                fh.write(json.dumps(marker, indent=1))
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)
            os.replace(str(staging), str(target))
        finally:
            shutil.rmtree(staging, ignore_errors=True)
            if archive is not None:
                _rm(Path(archive))
        res = self._from_cache(spec, dotnet_available)
        if res is None:
            raise ToolDownloadError("installed %s but could not locate its entry point" % spec.display_name, "policy")
        res.source = "download"
        res.warnings.extend(warnings)
        return res

    # -- status
    def status(self) -> List[Dict[str, Any]]:
        rows = []
        for n in self.names():
            spec = self.spec(n)
            res = self.resolve(n, install=False)
            rows.append({"name": spec.name, "display_name": spec.display_name, "version": spec.version,
                         "role": spec.raw.get("role", ""), "maturity": spec.raw.get("maturity", ""),
                         "installed": res.ok, "source": res.source, "path": str(res.entry) if res.entry else "",
                         "kind": res.kind, "min_dotnet": res.min_dotnet or spec.min_dotnet,
                         "downloadable": any(a.get("sha256") for a in spec.assets)})
        return rows


def _download_remediation(exc: ToolDownloadError) -> str:
    if exc.reason == "offline":
        return "Run 'ipa-analyze tools install <name>' once while online, or pass --il2cpp-tool PATH."
    if exc.reason == "unpinned":
        return "Download the release manually, verify it yourself and pass --il2cpp-tool PATH."
    if exc.reason == "sha256":
        return ("The downloaded file did not match the pinned SHA256 and was discarded. Do not use it; retry "
                "later or download from the official release page and pass --il2cpp-tool PATH.")
    return remediation_for(Il2CppErrorCode.E_TOOL_DOWNLOAD_FAILED)


# --- CLI entry points (wired by cli.py) -----------------------------------------------------------------------
EXIT_OK = 0
EXIT_USAGE = 1
EXIT_FAIL = 4


def _manager_from_args(args: Any) -> ToolManager:
    cfg = Config()
    cfg.offline = bool(getattr(args, "offline", False))
    cfg.assume_yes = bool(getattr(args, "yes", False))
    dn = getattr(args, "dotnet", None)
    if dn:
        cfg.il2cpp.dotnet_path = str(dn)
    return ToolManager(cfg)


def cmd_tools_list(args: Any) -> int:
    from . import dotnet as _dn
    mgr = _manager_from_args(args)
    print("cache directory: %s" % mgr.cache)
    for row in mgr.status():
        state = ("%s (%s)" % (row["path"], row["source"])) if row["installed"] else "not installed"
        need = (" needs .NET >= %d" % row["min_dotnet"]) if row["min_dotnet"] else " no .NET needed"
        print("%-12s %-10s %-12s %s;%s" % (row["name"], row["version"], row["maturity"], state, need))
    dn = _dn.find_dotnet(getattr(args, "dotnet", None), cache_root=mgr.cache_root)
    if dn is None:
        print("dotnet       -          -            not found")
    else:
        rts = [r for r in _dn.list_runtimes(dn) if r.name == _dn.RUNTIME_NAME]
        print("dotnet       %-10s -            %s (runtimes: %s)" % (
            rts[-1].version if rts else "?", dn, ", ".join(r.version for r in rts) or "none"))
    return EXIT_OK


def cmd_tools_install(args: Any) -> int:
    from . import dotnet as _dn
    name = str(getattr(args, "name", "") or "")
    mgr = _manager_from_args(args)
    if canonical_name(name) == "dotnet":
        res = _dn.ensure_runtime(int(str(mgr.catalog.get("dotnet", {}).get("default_install_channel", "8.0")).split(".")[0]),
                                 explicit=getattr(args, "dotnet", None), allow_install=True,
                                 offline=mgr.offline, cache_root=mgr.cache_root)
        if res.ok:
            print("dotnet: %s (runtime %s)" % (res.dotnet, res.version))
            return EXIT_OK
        print("error: %s\n%s" % (res.message, res.remediation), file=sys.stderr)
        return EXIT_FAIL
    try:
        spec = mgr.spec(name)
    except KeyError as exc:
        print("error: %s" % (exc.args[0] if exc.args else exc), file=sys.stderr)
        return EXIT_USAGE
    res = mgr.install(spec.name)
    if not res.ok:
        print("error: %s\n%s" % (res.message, res.remediation), file=sys.stderr)
        return EXIT_FAIL
    print("%s %s: %s" % (spec.display_name, res.version or spec.version, res.entry))
    for w in res.warnings:
        print("warning: %s" % w, file=sys.stderr)
    if res.min_dotnet:
        d = _dn.ensure_runtime(res.min_dotnet, explicit=getattr(args, "dotnet", None), allow_install=False,
                               offline=True, cache_root=mgr.cache_root)
        if not d.ok:
            print("note: a .NET runtime >= %d is required to run it; run 'ipa-analyze tools install dotnet' "
                  "(user-level, no admin rights) or install one yourself." % res.min_dotnet, file=sys.stderr)
    return EXIT_OK


def cmd_tools_path(args: Any) -> int:
    from . import dotnet as _dn
    name = str(getattr(args, "name", "") or "")
    mgr = _manager_from_args(args)
    if canonical_name(name) == "dotnet":
        p = _dn.find_dotnet(getattr(args, "dotnet", None), cache_root=mgr.cache_root)
        if p is None:
            print("error: dotnet not found", file=sys.stderr)
            return EXIT_FAIL
        print(p)
        return EXIT_OK
    try:
        mgr.spec(name)
    except KeyError as exc:
        print("error: %s" % (exc.args[0] if exc.args else exc), file=sys.stderr)
        return EXIT_USAGE
    res = mgr.resolve(name, install=False)
    if not res.ok or res.entry is None:
        print("error: %s\n%s" % (res.message, res.remediation), file=sys.stderr)
        return EXIT_FAIL
    print(res.entry)
    return EXIT_OK
