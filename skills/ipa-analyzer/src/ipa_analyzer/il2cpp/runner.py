"""Non-interactive execution of IL2CPP dumpers: supervised subprocess, Mach-O pre-flight, backend chain, cache.

``run_il2cpp_dump`` is the public entry point (re-exported by the package). The heavy lifting for one
backend lives in ``backends.py``; this module provides the process supervisor they share
(``run_supervised``), request validation, thin-slice extraction, FairPlay detection and the
attempt/fallback loop with a per-input result cache.
"""
from __future__ import annotations

import codecs
import dataclasses
import hashlib
import json
import logging
import os
import queue
import re
import shutil
import struct
import subprocess
import tempfile
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Pattern, Sequence, Tuple

from ..config import Config
from ..util import paths as _paths
from ..util import procs as _procs
from . import Il2CppErrorCode, Il2CppRunRequest, Il2CppRunResult
from .errors import (classify_output, redact_lines, redact_text, remediation_for, tail_lines)

log = logging.getLogger(__name__)

CACHE_MARKER = ".il2cpp-cache.json"
RUN_LOG_NAME = "il2cpp-run.log"
LOG_CAP_BYTES = 5 * 1024 * 1024
HEAD_LINES_KEPT = 500
METADATA_MAGIC = 0xFAB11BAF   # Source: Il2CppDumper Program.cs / Metadata.cs ("0xFAB11BAF"), il2cpp-metadata.h


# =============================================================================================================
# Process supervision
# =============================================================================================================
@dataclass
class PromptRule:
    """A console prompt that means "the tool is waiting for input" (``answer`` None = cannot be answered)."""
    pattern: Pattern[str]
    answer: Optional[str] = None
    label: str = ""

    @classmethod
    def from_catalog(cls, items: Sequence[Dict[str, Any]]) -> List["PromptRule"]:
        rules = []
        for it in items:
            try:
                rx = re.compile(str(it["pattern"]), re.IGNORECASE)
            except (re.error, KeyError):
                continue
            ans = it.get("answer") if it.get("answerable") else None
            rules.append(cls(rx, ans, str(it.get("pattern"))))
        return rules


@dataclass
class SupervisedResult:
    returncode: Optional[int] = None
    head: List[str] = field(default_factory=list)          # first lines (both streams, arrival order)
    tail: List[str] = field(default_factory=list)          # last lines
    lines_total: int = 0
    timed_out: bool = False
    idle_timeout: bool = False
    prompt: Optional[str] = None                           # text of an unanswerable prompt that was detected
    answered: int = 0
    duration_s: float = 0.0
    start_error: Optional[str] = None

    def all_lines(self) -> List[str]:
        return _merge(self.head, self.tail, self.lines_total)


def _merge(head: List[str], tail: List[str], total: int) -> List[str]:
    """``head`` and ``tail`` overlap when fewer than head+tail lines exist; rebuild the exact sequence."""
    if total <= len(head):
        return head[:total]
    overlap = len(head) + len(tail) - total
    return head + (tail[overlap:] if overlap > 0 else tail)


def run_supervised(cmd: Sequence[str], *, cwd: Optional[str], env: Optional[Dict[str, str]], timeout_s: float,
                   idle_timeout_s: Optional[float] = None, prompts: Sequence[PromptRule] = (),
                   log_path: Optional[Path] = None, tail_n: int = 200, poll_s: float = 0.05) -> SupervisedResult:
    """Run ``cmd`` (argument list, no shell) and watch it.

    * stdout and stderr are read incrementally; *partial* lines are also checked, so prompts without a
      trailing newline (``Input CodeRegistration: ``) are detected.
    * stdin is a pipe that stays open and silent: a tool that waits for input blocks, which we detect either
      via ``prompts`` (answerable prompts get their ``answer`` written) or via ``idle_timeout_s`` (no output).
    * Global ``timeout_s`` and idle timeout kill the whole process tree (``util.procs.kill_tree``).
    Returns the exit code (``None`` if killed before exiting normally) and the first/last lines.
    """
    started = time.monotonic()
    res = SupervisedResult()
    try:
        proc = _procs.popen([str(c) for c in cmd], cwd=cwd, env=env, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        res.start_error = "%s: %s" % (type(exc).__name__, exc)
        res.duration_s = time.monotonic() - started
        return res

    events: "queue.Queue[Tuple[str, bytes]]" = queue.Queue()

    def pump(stream: Any, tag: str) -> None:
        try:
            while True:
                chunk = stream.read1(4096)
                if not chunk:
                    break
                events.put((tag, chunk))
        except (OSError, ValueError):
            pass
        finally:
            events.put((tag + ":eof", b""))

    threads = [threading.Thread(target=pump, args=(proc.stdout, "out"), daemon=True),
               threading.Thread(target=pump, args=(proc.stderr, "err"), daemon=True)]
    for t in threads:
        t.start()

    decoders = {"out": codecs.getincrementaldecoder("utf-8")(errors="replace"),
                "err": codecs.getincrementaldecoder("utf-8")(errors="replace")}
    pending = {"out": "", "err": ""}
    tail: Deque[str] = deque(maxlen=max(1, tail_n))
    log_fh = None
    log_bytes = 0
    if log_path is not None:
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_fh = open(log_path, "w", encoding="utf-8", newline="\n")
        except OSError:
            log_fh = None
    eof = set()
    last_output = time.monotonic()
    deadline = started + float(timeout_s)
    answered_at: Dict[str, int] = {}

    def emit(tag: str, line: str) -> None:
        nonlocal log_bytes
        line = redact_text(line)
        res.lines_total += 1
        if len(res.head) < HEAD_LINES_KEPT:
            res.head.append(line)
        tail.append(line)
        if log_fh is not None and log_bytes < LOG_CAP_BYTES:
            data = "[%s] %s\n" % (tag, line)
            log_bytes += len(data)
            try:
                log_fh.write(data)
            except OSError:
                pass

    def check_prompt(tag: str, text: str) -> bool:
        """Return True if the tool must be stopped because of an unanswerable prompt."""
        if not prompts or not text.strip():
            return False
        for rule in prompts:
            if rule.pattern.search(text):
                if rule.answer is not None and proc.stdin is not None:
                    key = rule.label + "|" + text
                    if answered_at.get(key, 0) >= 3:
                        return False
                    answered_at[key] = answered_at.get(key, 0) + 1
                    try:
                        proc.stdin.write(rule.answer.encode("utf-8"))
                        proc.stdin.flush()
                        res.answered += 1
                    except (OSError, ValueError):
                        pass
                    pending[tag] = ""
                    return False
                res.prompt = text.strip()
                return True
        return False

    def handle(tag: str, data: bytes, check: bool) -> bool:
        """Feed one chunk; returns True when an unanswerable prompt requires stopping the tool."""
        text = pending[tag] + decoders[tag].decode(data)
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        *lines, rest = text.split("\n")
        pending[tag] = rest
        for ln in lines:
            emit(tag, ln)
            if check and check_prompt(tag, ln):
                return True
        if check and rest and check_prompt(tag, rest):
            emit(tag, rest)
            pending[tag] = ""
            return True
        return False

    exit_seen: Optional[float] = None
    try:
        while True:
            now = time.monotonic()
            if now >= deadline:
                res.timed_out = True
                break
            if idle_timeout_s and now - last_output > idle_timeout_s and proc.poll() is None:
                res.idle_timeout = True
                break
            try:
                tag, data = events.get(timeout=poll_s)
            except queue.Empty:
                if proc.poll() is not None:
                    exit_seen = exit_seen or now
                    if len(eof) >= 2 or now - exit_seen > 2.0:   # 2s grace: a descendant may hold a pipe open
                        break
                continue
            if tag.endswith(":eof"):
                eof.add(tag[:-4])
                if len(eof) >= 2 and proc.poll() is not None:
                    break
                continue
            last_output = time.monotonic()
            if handle(tag, data, True):
                break
    finally:
        _procs.kill_tree(proc)    # also reaps stragglers of the process group
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except (OSError, ValueError):
                pass
        for t in threads:
            t.join(timeout=2.0)
        while True:   # output that arrived while we were stopping the tool
            try:
                tag, data = events.get_nowait()
            except queue.Empty:
                break
            if not tag.endswith(":eof"):
                handle(tag, data, False)
        for tag in ("out", "err"):
            if pending[tag]:
                emit(tag, pending[tag])
                pending[tag] = ""
        if log_fh is not None:
            try:
                log_fh.close()
            except OSError:
                pass
    killed = res.timed_out or res.idle_timeout or res.prompt is not None
    res.returncode = None if killed else proc.returncode
    res.tail = list(tail)
    res.duration_s = time.monotonic() - started
    return res


# =============================================================================================================
# Mach-O pre-flight (pure Python; Source: Apple <mach-o/loader.h>, <mach-o/fat.h>)
# =============================================================================================================
_FAT_MAGIC, _FAT_MAGIC_64 = 0xCAFEBABE, 0xCAFEBABF           # big-endian fat headers
_MH_MAGIC, _MH_MAGIC_64 = 0xFEEDFACE, 0xFEEDFACF             # little-endian thin (iOS is little-endian)
_CPU_TYPE_ARM64 = 0x0100000C
_LC_ENCRYPTION_INFO, _LC_ENCRYPTION_INFO_64 = 0x21, 0x2C
_MAX_CMDS_BYTES = 8 * 1024 * 1024


@dataclass
class MachOSlice:
    cputype: int
    offset: int
    size: int
    is64: bool
    encrypted: Optional[bool] = None   # None = could not determine


@dataclass
class MachOInfo:
    is_macho: bool = False
    is_fat: bool = False
    slices: List[MachOSlice] = field(default_factory=list)

    def preferred(self) -> Optional[MachOSlice]:
        for s in self.slices:
            if s.cputype == _CPU_TYPE_ARM64:
                return s
        for s in self.slices:
            if s.is64:
                return s
        return self.slices[0] if self.slices else None


def inspect_macho(path: Path) -> MachOInfo:
    """Parse Mach-O/fat headers and the ``LC_ENCRYPTION_INFO(_64)`` of every slice; never raises."""
    info = MachOInfo()
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            head = fh.read(8)
            if len(head) < 8:
                return info
            magic_be = struct.unpack(">I", head[:4])[0]
            if magic_be in (_FAT_MAGIC, _FAT_MAGIC_64):
                n = struct.unpack(">I", head[4:8])[0]
                if not 0 < n < 30:   # Java class files also start with CAFEBABE; real fat files have few archs
                    return info
                info.is_fat = True
                esz = 32 if magic_be == _FAT_MAGIC_64 else 20
                raw = fh.read(esz * n)
                for i in range(min(n, len(raw) // esz)):
                    ent = raw[i * esz:(i + 1) * esz]
                    if magic_be == _FAT_MAGIC_64:
                        cpu, _sub, off, sz = struct.unpack(">iiQQ", ent[:24])
                    else:
                        cpu, _sub, off, sz = struct.unpack(">iiII", ent[:16])
                    cpu &= 0xFFFFFFFF
                    if off + sz > size or sz < 28:
                        continue
                    info.slices.append(MachOSlice(cpu, off, sz, bool(cpu & 0x01000000)))
            else:
                magic_le = struct.unpack("<I", head[:4])[0]
                if magic_le not in (_MH_MAGIC, _MH_MAGIC_64):
                    return info
                cpu = struct.unpack("<I", fh.read(4))[0]
                info.slices.append(MachOSlice(cpu, 0, size, magic_le == _MH_MAGIC_64))
            for sl in info.slices:
                sl.encrypted = _slice_encrypted(fh, sl)
        info.is_macho = bool(info.slices)
    except (OSError, struct.error):
        pass
    return info


def _slice_encrypted(fh: Any, sl: MachOSlice) -> Optional[bool]:
    try:
        fh.seek(sl.offset)
        hdr = fh.read(32 if sl.is64 else 28)
        if len(hdr) < (32 if sl.is64 else 28):
            return None
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic not in (_MH_MAGIC, _MH_MAGIC_64):
            return None
        ncmds, sizeofcmds = struct.unpack("<II", hdr[16:24])
        if sizeofcmds > _MAX_CMDS_BYTES or sizeofcmds < 8:
            return None
        cmds = fh.read(sizeofcmds)
        pos = 0
        for _ in range(min(ncmds, 4096)):
            if pos + 8 > len(cmds):
                break
            cmd, cmdsize = struct.unpack_from("<II", cmds, pos)
            if cmdsize < 8 or pos + cmdsize > len(cmds):
                break
            if cmd in (_LC_ENCRYPTION_INFO, _LC_ENCRYPTION_INFO_64) and cmdsize >= 20:
                _off, cryptsize, cryptid = struct.unpack_from("<III", cmds, pos + 8)
                return cryptid != 0 and cryptsize > 0
            pos += cmdsize
        return False
    except (OSError, struct.error):
        return None


def extract_slice(src: Path, sl: MachOSlice, dest: Path) -> Path:
    """Write one fat slice as a thin Mach-O (no ``lipo``)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(src, "rb") as fin, open(dest, "wb") as fout:
        fin.seek(sl.offset)
        remaining = sl.size
        while remaining > 0:
            chunk = fin.read(min(1 << 20, remaining))
            if not chunk:
                break
            fout.write(chunk)
            remaining -= len(chunk)
    return dest


def read_metadata_header(path: Path) -> Tuple[bool, Optional[int]]:
    """``(magic_ok, version)`` of a ``global-metadata.dat`` (version is the int32 at offset 4)."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        return False, None
    if len(head) < 8:
        return False, None
    magic, version = struct.unpack("<Ii", head)
    return magic == METADATA_MAGIC, (version if magic == METADATA_MAGIC else None)


# =============================================================================================================
# Request handling
# =============================================================================================================
def _fail(code: Il2CppErrorCode, message: str, *, remediation: str = "", backend: str = "",
          attempts: Optional[List[Dict[str, Any]]] = None, stdout_tail: Optional[List[str]] = None,
          stderr_tail: Optional[List[str]] = None) -> Il2CppRunResult:
    return Il2CppRunResult(ok=False, error_code=code, message=message, remediation=remediation or remediation_for(code),
                           backend=backend, attempts=attempts or [], stdout_tail=stdout_tail or [],
                           stderr_tail=stderr_tail or [])


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _stage_file(src: Path, dst: Path) -> Path:
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(str(src), str(dst))
    except (OSError, NotImplementedError, AttributeError):
        shutil.copyfile(str(src), str(dst))
    return dst


def _validate_out_dir(out_dir: Path, allowed_root: Optional[str]) -> Optional[str]:
    try:
        resolved = out_dir.resolve()
    except (OSError, RuntimeError) as exc:
        return "cannot resolve the output directory: %s" % exc
    if out_dir.exists() and not out_dir.is_dir():
        return "output path exists and is not a directory: %s" % out_dir
    if resolved == Path(resolved.anchor) or resolved == Path.home().resolve():
        return "refusing to write dump artifacts into %s" % resolved
    if allowed_root and not _paths.is_within(Path(allowed_root), resolved):
        return "output directory %s is outside the allowed root %s" % (resolved, allowed_root)
    return None


def _cache_key(bin_sha: str, meta_sha: str, backend: str, version: str) -> str:
    return hashlib.sha256(("%s|%s|%s|%s" % (bin_sha, meta_sha, backend, version)).encode("utf-8")).hexdigest()


def _read_marker(out_dir: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads((out_dir / CACHE_MARKER).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _artifacts_present(out_dir: Path, artifacts: Dict[str, str]) -> bool:
    if not artifacts:
        return False
    for rel in artifacts.values():
        if not (out_dir / rel).exists():
            return False
    return True


def run_il2cpp_dump(req: Il2CppRunRequest, tools: Any, cfg: Config) -> Il2CppRunResult:
    """Validate ``req``, pick backends for its metadata/Unity version and run them until one succeeds.

    Order of work: input validation (files, sizes, output dir) -> metadata magic/version -> Mach-O
    pre-flight (fat -> arm64 slice, FairPlay => ``E_BINARY_FAIRPLAY``) -> result cache -> per backend:
    provision (download / .NET) and run, falling back to the next backend for the codes listed in
    ``fallback_on`` of the catalog. Never raises for expected failures; inspect ``ok`` / ``error_code``.
    """
    from . import backends as _backends
    from .tools import ToolManager

    t0 = time.monotonic()
    mgr = tools if tools is not None else ToolManager(cfg)
    bin_p, meta_p, out_dir = Path(req.binary_path), Path(req.metadata_path), Path(req.out_dir)

    for p, label in ((bin_p, "binary"), (meta_p, "metadata")):
        if not p.is_file():
            return _fail(Il2CppErrorCode.E_UNKNOWN, "%s file not found: %s" % (label, p))
    try:
        bin_size, meta_size = bin_p.stat().st_size, meta_p.stat().st_size
    except OSError as exc:
        return _fail(Il2CppErrorCode.E_UNKNOWN, "cannot stat inputs: %s" % exc)
    if bin_size == 0:
        return _fail(Il2CppErrorCode.E_UNKNOWN, "the binary is empty: %s" % bin_p)
    if meta_size == 0:
        return _fail(Il2CppErrorCode.E_METADATA_ENCRYPTED, "global-metadata.dat is empty")
    limit = cfg.limits.max_file_size
    if bin_size > limit or meta_size > limit:
        return _fail(Il2CppErrorCode.E_UNKNOWN, "input exceeds the configured max file size (%d bytes)" % limit)
    bad_out = _validate_out_dir(out_dir, req.extra.get("allowed_root") if isinstance(req.extra, dict) else None)
    if bad_out:
        return _fail(Il2CppErrorCode.E_UNKNOWN, bad_out)

    magic_ok, hdr_version = read_metadata_header(meta_p)
    if not magic_ok and not req.force_dump:
        return _fail(Il2CppErrorCode.E_METADATA_ENCRYPTED,
                     "global-metadata.dat does not start with the IL2CPP magic 0xFAB11BAF")
    meta_version = req.metadata_version if req.metadata_version is not None else hdr_version

    base = Path(req.work_dir) if req.work_dir else None
    if base is not None:
        base.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="il2cpp-", dir=str(base) if base else None))
    try:
        info = inspect_macho(bin_p)
        staged_bin = run_dir / "il2cpp_binary"
        if info.is_macho:
            pick = info.preferred()
            if pick is not None and pick.encrypted:
                return _fail(Il2CppErrorCode.E_BINARY_FAIRPLAY,
                             "the selected Mach-O slice has LC_ENCRYPTION_INFO cryptid != 0 (FairPlay)")
            if info.is_fat and pick is not None:
                extract_slice(bin_p, pick, staged_bin)
            else:
                _stage_file(bin_p, staged_bin)
        else:
            _stage_file(bin_p, staged_bin)
        staged_meta = _stage_file(meta_p, run_dir / "global-metadata.dat")

        chain = _backends.select_backends(meta_version, req.unity_version, cfg)
        if not chain:
            return _fail(Il2CppErrorCode.E_METADATA_VERSION_UNSUPPORTED,
                         "no backend supports metadata version %s (unity %s)" % (meta_version, req.unity_version or "unknown"))
        catalog_fallback = set(mgr.catalog.get("fallback_on", [])) if hasattr(mgr, "catalog") else set()

        bin_sha: Optional[str] = None
        meta_sha: Optional[str] = None
        attempts: List[Dict[str, Any]] = []
        first_failure: Optional[Il2CppRunResult] = None
        deadline = t0 + max(1, int(req.timeout_s))
        sreq = dataclasses.replace(req, binary_path=staged_bin, metadata_path=staged_meta, work_dir=run_dir,
                                   metadata_version=meta_version)

        for backend in chain:
            # cache first: a previous successful run of this backend on identical inputs
            marker = _read_marker(out_dir) if out_dir.is_dir() else None
            if marker and marker.get("backend") == backend.name:
                bin_sha = bin_sha or _sha256_file(bin_p)
                meta_sha = meta_sha or _sha256_file(meta_p)
                want = _cache_key(bin_sha, meta_sha, backend.name, _backends.catalog_version(backend, cfg, mgr))
                arts = marker.get("artifacts") or {}
                if marker.get("key") == want and _artifacts_present(out_dir, arts):
                    attempts.append({"backend": backend.name, "ok": True, "error_code": None, "cached": True})
                    return Il2CppRunResult(ok=True, backend=backend.name, backend_version=str(marker.get("backend_version", "")),
                                           out_dir=out_dir, artifacts=dict(arts), cached=True,
                                           duration_s=time.monotonic() - t0, attempts=attempts,
                                           message="reused cached dump")
            remaining = deadline - time.monotonic()
            if remaining < 5:
                res = _fail(Il2CppErrorCode.E_TIMEOUT, "overall time budget (%ds) exhausted before running %s"
                            % (req.timeout_s, backend.name), backend=backend.name)
                attempts.append({"backend": backend.name, "ok": False, "error_code": res.error_code.value})
                first_failure = first_failure or res
                break
            try:
                prov = backend.provision(mgr, cfg)
            except Exception as exc:  # noqa: BLE001 - provisioning must not crash the pipeline
                log.exception("provisioning %s crashed", backend.name)
                res = _fail(Il2CppErrorCode.E_UNKNOWN, "provisioning %s crashed: %s: %s" % (backend.name, type(exc).__name__, exc),
                            backend=backend.name)
                attempts.append({"backend": backend.name, "ok": False, "error_code": res.error_code.value})
                first_failure = first_failure or res
                continue
            if not prov.ok:
                code = prov.error_code or Il2CppErrorCode.E_UNKNOWN
                res = _fail(code, prov.message, backend=backend.name)
                attempts.append({"backend": backend.name, "ok": False, "error_code": code.value, "stage": "provision"})
                first_failure = first_failure or res
                if code.value in catalog_fallback or not catalog_fallback:
                    continue
                break
            try:
                step_req = dataclasses.replace(sreq, timeout_s=int(remaining))
                res = backend.run(step_req, prov, cfg)
            except Exception as exc:  # noqa: BLE001
                log.exception("backend %s crashed", backend.name)
                res = _fail(Il2CppErrorCode.E_UNKNOWN, "backend %s crashed: %s: %s" % (backend.name, type(exc).__name__, exc),
                            backend=backend.name)
            res.backend = res.backend or backend.name
            res.backend_version = res.backend_version or prov.version
            attempts.append({"backend": res.backend, "ok": res.ok,
                             "error_code": res.error_code.value if res.error_code else None,
                             "version": res.backend_version, "duration_s": round(res.duration_s, 2)})
            if res.ok:
                bin_sha = bin_sha or _sha256_file(bin_p)
                meta_sha = meta_sha or _sha256_file(meta_p)
                _write_marker(out_dir, _cache_key(bin_sha, meta_sha, backend.name,
                                                  _backends.catalog_version(backend, cfg, mgr)), res)
                res.attempts = attempts
                res.duration_s = time.monotonic() - t0
                return res
            first_failure = first_failure or res
            code = res.error_code or Il2CppErrorCode.E_UNKNOWN
            if catalog_fallback and code.value not in catalog_fallback:
                break
        final = first_failure or _fail(Il2CppErrorCode.E_UNKNOWN, "no backend produced a result")
        final.attempts = attempts
        final.duration_s = time.monotonic() - t0
        return final
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)


def _write_marker(out_dir: Path, key: str, res: Il2CppRunResult) -> None:
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / CACHE_MARKER).write_text(json.dumps({
            "key": key, "backend": res.backend, "backend_version": res.backend_version,
            "artifacts": res.artifacts, "created": int(time.time())}, indent=1), encoding="utf-8", newline="\n")
    except OSError as exc:
        log.warning("could not write the IL2CPP cache marker: %s", exc)


def finish_log(log_src: Path, out_dir: Path) -> Optional[str]:
    """Copy the (already redacted) run log into ``out_dir``; returns its relative name."""
    try:
        if not log_src.is_file():
            return None
        out_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(str(log_src), str(out_dir / RUN_LOG_NAME))
        return RUN_LOG_NAME
    except OSError:
        return None


def new_stage_dir(work_dir: Path, prefix: str) -> Path:
    d = work_dir / ("%s-%s" % (prefix, uuid.uuid4().hex[:8]))
    d.mkdir(parents=True, exist_ok=True)
    return d


__all__ = ["run_il2cpp_dump", "run_supervised", "SupervisedResult", "PromptRule", "inspect_macho", "extract_slice",
           "read_metadata_header", "MachOInfo", "MachOSlice", "tail_lines", "redact_lines"]
