"""Backend adapters: Il2CppDumper (primary), Cpp2IL and Il2CppInspectorRedux (fallbacks).

Facts about each tool (CLI, config, prompts, version ranges, hashes) live in ``data/il2cpp_backends.json``
with sources; this module turns them into non-interactive runs. Maturity:

* ``Il2CppDumperBackend`` - complete: private tool copy + generated ``config.json`` (``RequireAnyKey=false``),
  prompt detection, output classification, artifact collection. Verified up to ``--help``/error paths; a
  real successful dump needs a real IPA and was NOT exercised.
* ``Cpp2ILBackend`` / ``InspectorReduxBackend`` - minimal: provision + one or two runs + collecting the
  generated C# tree. Output names of Redux are UNVERIFIED (it needs a .NET 10 runtime that was not available).
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..config import Config
from ..util import procs as _procs
from . import (Il2CppBackend, Il2CppErrorCode, Il2CppRunRequest, Il2CppRunResult, ProvisionResult)
from . import dotnet as _dotnet
from .errors import classify_output, remediation_for, redact_text, tail_lines
from .runner import PromptRule, SupervisedResult, finish_log, new_stage_dir, run_supervised
from .tools import ToolManager, load_catalog

log = logging.getLogger(__name__)

DUMPER_ARTIFACTS = ("dump.cs", "script.json", "il2cpp.h", "stringliteral.json", "DummyDll")
_MAX_TOOL_COPY_BYTES = 256 * 1024 * 1024
_DEFAULT_IDLE_S = 300


def _dir_size(path: Path, cap: int) -> int:
    total = 0
    for dirpath, _dirs, files in os.walk(str(path)):
        for fn in files:
            try:
                total += os.path.getsize(os.path.join(dirpath, fn))
            except OSError:
                pass
            if total > cap:
                return total
    return total


def _move_into(src: Path, dst: Path) -> None:
    if dst.exists():
        if dst.is_dir() and not dst.is_symlink():
            shutil.rmtree(dst, ignore_errors=True)
        else:
            dst.unlink()
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))


def _nonempty_file(p: Path) -> bool:
    try:
        return p.is_file() and p.stat().st_size > 0
    except OSError:
        return False


def _rel(out_dir: Path, p: Path) -> str:
    return p.relative_to(out_dir).as_posix()


class _ExternalBackend:
    """Shared plumbing: catalog access, support matrix, provisioning."""

    name = ""

    def __init__(self, catalog: Optional[Dict[str, Any]] = None) -> None:
        self._catalog = catalog

    # -- catalog
    @property
    def catalog(self) -> Dict[str, Any]:
        return self._catalog if self._catalog is not None else load_catalog()

    @property
    def raw(self) -> Dict[str, Any]:
        return self.catalog.get("backends", {}).get(self.name, {})

    # -- Il2CppBackend
    def supports(self, meta_version: Optional[float], unity_version: Optional[str]) -> bool:
        mv = self.raw.get("metadata_versions") or {}
        if meta_version is not None and mv:
            try:
                if not (float(mv.get("min", 0)) <= float(meta_version) <= float(mv.get("max", 10 ** 6))):
                    return False
            except (TypeError, ValueError):
                return False
        if self.raw.get("requires_unity_version") and not unity_version:
            return False
        return bool(self.raw)

    def provision(self, tools: Any, cfg: Config) -> ProvisionResult:
        mgr: ToolManager = tools if isinstance(tools, ToolManager) else ToolManager(cfg)
        spec = mgr.spec(self.name)
        explicit_dotnet = cfg.il2cpp.dotnet_path
        probe = None
        if spec.min_dotnet:
            probe = _dotnet.ensure_runtime(spec.min_dotnet, explicit=explicit_dotnet, allow_install=False,
                                           consent_cb=lambda _m: False, offline=True, cache_root=mgr.cache_root)
        probe_ok = bool(probe is None or probe.ok)
        res = mgr.resolve(self.name, install=False, dotnet_available=probe_ok)
        if not res.ok and not res.source and not mgr.offline:
            # about to download: make sure the runtime it needs is obtainable first (no pointless downloads)
            sel = spec.raw.get("asset_selection") or {}
            self_contained = bool(sel.get("windows_without_dotnet")) and mgr.system == "Windows" and not probe_ok
            if spec.min_dotnet and not probe_ok and not self_contained:
                dres = _dotnet.ensure_runtime(spec.min_dotnet, explicit=explicit_dotnet, allow_install=False,
                                              consent_cb=mgr.consent, offline=False, cache_root=mgr.cache_root,
                                              channel=spec.install_channel or None, downloader=mgr._downloader)
                if not dres.ok:
                    return ProvisionResult(False, error_code=dres.error_code or Il2CppErrorCode.E_DOTNET_MISSING,
                                           message=dres.message + (" " + dres.remediation if dres.remediation else ""))
                probe, probe_ok = dres, True
            res = mgr.install(self.name, dotnet_available=probe_ok)
        if not res.ok:
            return ProvisionResult(False, error_code=res.error_code or Il2CppErrorCode.E_TOOL_DOWNLOAD_FAILED,
                                   message=res.message + (" " + res.remediation if res.remediation else ""))
        env: Dict[str, str] = {}
        command = list(res.command)
        warnings = list(res.warnings)
        need = res.min_dotnet
        if need:
            dres = probe if (probe is not None and probe.ok and probe.major >= need) else _dotnet.ensure_runtime(
                need, explicit=explicit_dotnet, allow_install=False, consent_cb=mgr.consent, offline=mgr.offline,
                cache_root=mgr.cache_root, channel=spec.install_channel or None, downloader=mgr._downloader)
            if not dres.ok:
                return ProvisionResult(False, error_code=dres.error_code or Il2CppErrorCode.E_DOTNET_MISSING,
                                       message=dres.message + (" " + dres.remediation if dres.remediation else ""))
            env = _dotnet.build_env(dres.dotnet, roll_forward=spec.roll_forward or _dotnet.DEFAULT_ROLL_FORWARD)
            if res.kind == "dotnet_dll":
                command = [str(dres.dotnet)] + command
        else:
            dn = _dotnet.find_dotnet(explicit_dotnet, cache_root=mgr.cache_root) if res.uses_dotnet_env else None
            env = _dotnet.build_env(dn, roll_forward=spec.roll_forward if dn else "")
        if res.version:
            version = res.version
        elif res.source in ("cache", "download"):
            version = spec.version
        else:
            version = "custom"
        return ProvisionResult(True, command=command, version=version, env=env, tool_dir=res.tool_dir,
                               kind=res.kind, source=res.source, warnings=warnings)

    def run(self, req: Il2CppRunRequest, provisioned: ProvisionResult, cfg: Config) -> Il2CppRunResult:
        raise NotImplementedError

    # -- helpers shared by implementations
    def _prompts(self) -> List[PromptRule]:
        return PromptRule.from_catalog(self.raw.get("interactive_prompts", []))

    @staticmethod
    def _env(req: Il2CppRunRequest, prov: ProvisionResult) -> Dict[str, str]:
        """Whitelisted environment of the provisioned tool plus ``req.extra['env']`` (explicit caller overrides)."""
        env = dict(prov.env) if prov.env else _procs.minimal_env()
        extra = req.extra.get("env") if isinstance(req.extra, dict) else None
        if isinstance(extra, dict):
            env.update({str(k): str(v) for k, v in extra.items()})
        return env

    def _idle(self, req: Il2CppRunRequest) -> float:
        v = req.extra.get("idle_timeout_s") if isinstance(req.extra, dict) else None
        base = float(v) if v else float(_DEFAULT_IDLE_S)
        return max(5.0, min(base, float(req.timeout_s)))

    def _classify(self, sup: SupervisedResult, *, extra_patterns: Sequence[Dict[str, Any]] = ()
                  ) -> Tuple[Optional[Il2CppErrorCode], str]:
        dn = self.catalog.get("dotnet", {})
        c = classify_output(sup.all_lines(), list(self.raw.get("error_patterns", [])) + list(extra_patterns),
                            returncode=sup.returncode, prompt=sup.prompt,
                            missing_framework_markers=dn.get("missing_framework_markers", []),
                            missing_framework_rc=dn.get("missing_framework_exit_code"))
        if c is None:
            return None, ""
        return c.code, c.message

    def _failure(self, sup: SupervisedResult, prov: ProvisionResult, message: str, code: Il2CppErrorCode,
                 log_path: Optional[Path], req: Il2CppRunRequest) -> Il2CppRunResult:
        rel = finish_log(log_path, Path(req.out_dir)) if log_path else None
        res = Il2CppRunResult(ok=False, error_code=code, message=redact_text(message),
                              remediation=remediation_for(code), backend=self.name, backend_version=prov.version,
                              stdout_tail=tail_lines(sup.tail, 200), stderr_tail=[], duration_s=sup.duration_s)
        if rel:
            res.artifacts = {"run.log": rel}
        return res


# =============================================================================================================
class Il2CppDumperBackend(_ExternalBackend):
    """Perfare/Il2CppDumper. See ``data/il2cpp_backends.json`` -> ``backends.il2cppdumper`` for the sources."""

    name = "il2cppdumper"

    def run(self, req: Il2CppRunRequest, provisioned: ProvisionResult, cfg: Config) -> Il2CppRunResult:
        t0 = time.monotonic()
        work = Path(req.work_dir) if req.work_dir else Path(os.environ.get("TMPDIR", "."))
        stage = new_stage_dir(work, "dumper")
        out_stage = stage / "out"
        out_stage.mkdir()
        log_path = stage / "tool.log"
        try:
            command = list(provisioned.command)
            warnings: List[str] = list(provisioned.warnings)
            # config.json is read from the tool's own directory (AppDomain.BaseDirectory): use a private copy.
            td = provisioned.tool_dir
            if td is not None and (td / "config.json").is_file() and _dir_size(td, _MAX_TOOL_COPY_BYTES) <= _MAX_TOOL_COPY_BYTES:
                copy = stage / "tool"
                shutil.copytree(str(td), str(copy))
                command = [self._rebase(c, td, copy) for c in command]
                self._write_config(copy / "config.json", req)
            else:
                warnings.append("tool directory has no config.json; RequireAnyKey could not be disabled")
            argv = command + [str(req.binary_path), str(req.metadata_path), str(out_stage)]
            sup = run_supervised(argv, cwd=str(stage), env=self._env(req, provisioned), timeout_s=req.timeout_s,
                                 idle_timeout_s=self._idle(req), prompts=self._prompts(), log_path=log_path)
            return self._finish(req, provisioned, sup, out_stage, log_path, warnings, time.monotonic() - t0)
        finally:
            shutil.rmtree(stage, ignore_errors=True)

    @staticmethod
    def _rebase(arg: str, old: Path, new: Path) -> str:
        try:
            rel = Path(arg).resolve().relative_to(old.resolve())
        except (ValueError, OSError):
            return arg
        return str(new / rel)

    def _write_config(self, path: Path, req: Il2CppRunRequest) -> None:
        try:
            cfg = json.loads(path.read_text(encoding="utf-8-sig"))
            if not isinstance(cfg, dict):
                cfg = {}
        except (OSError, ValueError):
            cfg = {}
        cfg.update(self.raw.get("config", {}).get("applied", {}))
        cfg["RequireAnyKey"] = False
        cfg["ForceDump"] = bool(req.force_dump)
        extra = req.extra.get("dumper_config") if isinstance(req.extra, dict) else None
        if isinstance(extra, dict):
            cfg.update(extra)
        with open(str(path), "w", encoding="utf-8", newline="\n") as fh:      # Path.write_text(newline=) needs Python 3.10
            fh.write(json.dumps(cfg, indent=2))

    def _finish(self, req: Il2CppRunRequest, prov: ProvisionResult, sup: SupervisedResult, out_stage: Path,
                log_path: Path, warnings: List[str], dur: float) -> Il2CppRunResult:
        if sup.start_error:
            code = Il2CppErrorCode.E_UNKNOWN
            return self._failure(sup, prov, "could not start the dumper: %s" % sup.start_error, code, log_path, req)
        if sup.timed_out:
            return self._failure(sup, prov, "the dumper exceeded the %ds time limit" % req.timeout_s,
                                 Il2CppErrorCode.E_TIMEOUT, log_path, req)
        lines = sup.all_lines()
        done = any("Done!" in ln for ln in lines)
        dump = out_stage / "dump.cs"
        if _nonempty_file(dump) and done:
            out_dir = Path(req.out_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            artifacts: Dict[str, str] = {}
            for name in DUMPER_ARTIFACTS:
                src = out_stage / name
                if src.exists() and (src.is_dir() or _nonempty_file(src)):
                    _move_into(src, out_dir / name)
                    artifacts[name] = name
            missing = [n for n in DUMPER_ARTIFACTS if n not in artifacts]
            if missing:
                warnings.append("missing optional outputs: " + ", ".join(missing))
            if sup.prompt:
                warnings.append("the tool printed an interactive prompt after finishing: %s" % sup.prompt)
            rel = finish_log(log_path, out_dir)
            if rel:
                artifacts["run.log"] = rel
            msg = "dump completed" + ("; " + "; ".join(warnings) if warnings else "")
            return Il2CppRunResult(ok=True, message=msg, backend=self.name, backend_version=prov.version,
                                   out_dir=out_dir, artifacts=artifacts, stdout_tail=tail_lines(sup.tail, 200),
                                   duration_s=dur)
        code, msg = self._classify(sup)
        if code is None:
            if sup.idle_timeout:
                code, msg = Il2CppErrorCode.E_TIMEOUT, ("the dumper produced no output for %ds (possibly waiting "
                                                        "for input) and was stopped" % int(self._idle(req)))
            elif _nonempty_file(dump):
                code, msg = Il2CppErrorCode.E_UNKNOWN, "dump.cs was written but the tool never reported completion (truncated dump?)"
            elif sup.returncode not in (0, None):
                code, msg = Il2CppErrorCode.E_UNKNOWN, "the dumper exited with code %s and produced no dump.cs" % sup.returncode
            else:
                code, msg = Il2CppErrorCode.E_UNKNOWN, "the dumper finished without producing dump.cs"
        return self._failure(sup, prov, msg, code, log_path, req)


# =============================================================================================================
class Cpp2ILBackend(_ExternalBackend):
    """SamboyCoding/Cpp2IL (single-file native build). Needs the Unity version (all ``--force-*`` options)."""

    name = "cpp2il"

    def run(self, req: Il2CppRunRequest, provisioned: ProvisionResult, cfg: Config) -> Il2CppRunResult:
        t0 = time.monotonic()
        work = Path(req.work_dir) if req.work_dir else Path(os.environ.get("TMPDIR", "."))
        stage = new_stage_dir(work, "cpp2il")
        log_path = stage / "tool.log"
        try:
            deadline = t0 + req.timeout_s
            produced: List[Tuple[str, Path]] = []
            last: Optional[SupervisedResult] = None
            for fmt, required in (("diffable-cs", True), ("dummydll", False)):
                remaining = deadline - time.monotonic()
                if remaining < 3:
                    break
                out_root = stage / ("out-" + fmt)
                out_root.mkdir()
                argv = list(provisioned.command) + [
                    "--force-binary-path", str(req.binary_path), "--force-metadata-path", str(req.metadata_path),
                    "--force-unity-version", str(req.unity_version), "--output-as", fmt, "--output-to", str(out_root)]
                sup = run_supervised(argv, cwd=str(stage), env=self._env(req, provisioned), timeout_s=remaining,
                                     idle_timeout_s=min(self._idle(req), remaining), prompts=self._prompts(),
                                     log_path=log_path)
                last = sup
                if sup.timed_out or sup.idle_timeout:
                    break
                ok = self._has_files(out_root, ".cs") if fmt == "diffable-cs" else any(out_root.iterdir())
                if ok:
                    produced.append((fmt, out_root))
                elif required:
                    break
            if last is None:
                return self._failure(SupervisedResult(), provisioned, "no time left to run Cpp2IL",
                                     Il2CppErrorCode.E_TIMEOUT, None, req)
            if produced and produced[0][0] == "diffable-cs":
                out_dir = Path(req.out_dir)
                out_dir.mkdir(parents=True, exist_ok=True)
                artifacts: Dict[str, str] = {}
                for fmt, root in produced:
                    for child in sorted(root.iterdir()):
                        _move_into(child, out_dir / child.name)
                        artifacts[child.name] = child.name
                rel = finish_log(log_path, out_dir)
                if rel:
                    artifacts["run.log"] = rel
                return Il2CppRunResult(ok=True, message="Cpp2IL output generated (C# tree, no dump.cs)", backend=self.name,
                                       backend_version=provisioned.version, out_dir=out_dir, artifacts=artifacts,
                                       stdout_tail=tail_lines(last.tail, 200), duration_s=time.monotonic() - t0)
            if last.timed_out or last.idle_timeout:
                return self._failure(last, provisioned, "Cpp2IL timed out", Il2CppErrorCode.E_TIMEOUT, log_path, req)
            code, msg = self._classify(last)
            if code is None:
                code, msg = Il2CppErrorCode.E_UNKNOWN, "Cpp2IL produced no C# output (exit code %s)" % last.returncode
            return self._failure(last, provisioned, msg, code, log_path, req)
        finally:
            shutil.rmtree(stage, ignore_errors=True)

    @staticmethod
    def _has_files(root: Path, suffix: str) -> bool:
        for _d, _s, files in os.walk(str(root)):
            if any(f.endswith(suffix) for f in files):
                return True
        return False


# =============================================================================================================
class InspectorReduxBackend(_ExternalBackend):
    """LukeFZ/Il2CppInspectorRedux CLI (``process <files> -o out -s -d``); requires a .NET 10 runtime. UNVERIFIED output names."""

    name = "redux"

    def run(self, req: Il2CppRunRequest, provisioned: ProvisionResult, cfg: Config) -> Il2CppRunResult:
        t0 = time.monotonic()
        work = Path(req.work_dir) if req.work_dir else Path(os.environ.get("TMPDIR", "."))
        stage = new_stage_dir(work, "redux")
        out_stage = stage / "out"
        out_stage.mkdir()
        log_path = stage / "tool.log"
        try:
            argv = list(provisioned.command) + ["process", str(req.metadata_path), str(req.binary_path),
                                                "-o", str(out_stage), "-s", "-d"]
            if req.unity_version:
                argv += ["--unity-version", str(req.unity_version)]
            sup = run_supervised(argv, cwd=str(stage), env=self._env(req, provisioned), timeout_s=req.timeout_s,
                                 idle_timeout_s=self._idle(req), prompts=self._prompts(), log_path=log_path)
            if sup.start_error:
                return self._failure(sup, provisioned, "could not start Il2CppInspectorRedux: %s" % sup.start_error,
                                     Il2CppErrorCode.E_UNKNOWN, log_path, req)
            if sup.timed_out or sup.idle_timeout:
                return self._failure(sup, provisioned, "Il2CppInspectorRedux timed out", Il2CppErrorCode.E_TIMEOUT,
                                     log_path, req)
            cs_dir, dll_dir = out_stage / "cs", out_stage / "dll"
            if cs_dir.is_dir() and Cpp2ILBackend._has_files(cs_dir, ".cs") and sup.returncode == 0:
                out_dir = Path(req.out_dir)
                out_dir.mkdir(parents=True, exist_ok=True)
                artifacts: Dict[str, str] = {}
                for src in (cs_dir, dll_dir):
                    if src.is_dir():
                        _move_into(src, out_dir / src.name)
                        artifacts[src.name] = src.name
                rel = finish_log(log_path, out_dir)
                if rel:
                    artifacts["run.log"] = rel
                return Il2CppRunResult(ok=True, message="Il2CppInspectorRedux output generated (C# stubs)",
                                       backend=self.name, backend_version=provisioned.version, out_dir=out_dir,
                                       artifacts=artifacts, stdout_tail=tail_lines(sup.tail, 200),
                                       duration_s=time.monotonic() - t0)
            code, msg = self._classify(sup)
            if code is None:
                code, msg = Il2CppErrorCode.E_UNKNOWN, "Il2CppInspectorRedux produced no C# output (exit code %s)" % sup.returncode
            return self._failure(sup, provisioned, msg, code, log_path, req)
        finally:
            shutil.rmtree(stage, ignore_errors=True)


BACKEND_CLASSES = {Il2CppDumperBackend.name: Il2CppDumperBackend, Cpp2ILBackend.name: Cpp2ILBackend,
                   InspectorReduxBackend.name: InspectorReduxBackend}


def select_backends(meta_version: Optional[float], unity_version: Optional[str], cfg: Config, *,
                    catalog: Optional[Dict[str, Any]] = None) -> List[Il2CppBackend]:
    """Backends that can handle this metadata/Unity version, in preference order.

    Order: ``cfg.il2cpp.backend_order`` if set, else ``default_order`` of the catalog. Unknown names are
    ignored; a backend is dropped when its metadata-version range (catalog) excludes ``meta_version`` or it
    requires a Unity version that is unknown.
    """
    cat = catalog if catalog is not None else load_catalog()
    order = [n for n in (cfg.il2cpp.backend_order or cat.get("default_order", [])) if n in BACKEND_CLASSES]
    for n in cfg.il2cpp.backend_order or []:
        if n not in BACKEND_CLASSES:
            log.warning("unknown IL2CPP backend %r in backend_order ignored", n)
    out: List[Il2CppBackend] = []
    for n in order:
        b = BACKEND_CLASSES[n](cat)
        if b.supports(meta_version, unity_version):
            out.append(b)
    return out


def catalog_version(backend: Any, cfg: Config, mgr: Any = None) -> str:
    """Version string used in the result-cache key (``custom:<path>`` for user supplied tools)."""
    if backend.name == "il2cppdumper" and cfg.il2cpp.tool_path:
        return "custom:%s" % cfg.il2cpp.tool_path
    return str(backend.raw.get("version", ""))
