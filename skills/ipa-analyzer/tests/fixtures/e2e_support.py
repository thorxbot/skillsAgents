"""Helpers for the end-to-end tests (hermetic CLI / library runs of the synthetic whole-package IPAs).

``runs`` runs every synthetic whole-package fixture (``fixtures.full_ipa_builders``) at most once per
configuration through the *CLI* (``subprocess`` on ``scripts/ipa_analyze.py``, i.e. the no-install entry point) or
through the *library* (``pipeline.run``) and caches the result for the whole session.

All runs are hermetic: an empty ``IPA_ANALYZER_HOME`` (so no cached Il2CppDumper is ever found), ``--offline`` (so
nothing is downloaded), and none of the host-tool environment variables.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pytest

from fixtures.full_ipa_builders import FIXTURES

SKILL_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = SKILL_ROOT / "scripts" / "ipa_analyze.py"
# environment variables that redirect resource / tool lookups or make the host's tools visible
_HOST_ENV_VARS = ("IPA_ANALYZER_DATA_DIR", "IPA_ANALYZER_SCHEMAS_DIR", "IPA_ANALYZER_REFERENCES_DIR",
                  "IL2CPPDUMPER_PATH", "CPP2IL_PATH", "IL2CPPINSPECTOR_PATH", "DOTNET_ROOT", "DOTNET_ROOT_X64",
                  "DOTNET_ROOT_ARM64", "DOTNET_ROLL_FORWARD", "XDG_CACHE_HOME", "XDG_CONFIG_HOME")
CLI_TIMEOUT_S = 180
# deterministic execution order (topological layers, alphabetical inside a layer; ``report`` always last)
STAGE_ORDER = ["ingest", "inventory", "macho", "meta", "engine.fingerprint", "engine.detect", "engine.other",
               "engine.unity", "engine.unity.hotfix", "libs", "classify", "protect", "report"]
BROKEN = [n for n in FIXTURES if n.startswith("broken_")]
GOOD = [n for n in FIXTURES if n not in BROKEN]


def hermetic_env(home: Path, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in _HOST_ENV_VARS}
    env["IPA_ANALYZER_HOME"] = str(home)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env.pop("IPA_ANALYZER_OFFLINE", None)
    env.update(extra or {})
    return {k: v for k, v in env.items() if not (k == "DOTNET_ROOT" and v == "")}


@dataclass
class CliRun:
    name: str
    proc: "subprocess.CompletedProcess[str]"
    out_base: Path
    report: Optional[Dict[str, Any]] = None
    report_path: Optional[Path] = None
    md: Optional[str] = None
    md_path: Optional[Path] = None

    @property
    def returncode(self) -> int:
        return self.proc.returncode

    def findings(self, fid: str) -> List[Dict[str, Any]]:
        return [f for f in (self.report or {}).get("findings", []) if f["id"] == fid]

    def finding(self, fid: str, tag: Optional[str] = None) -> Dict[str, Any]:
        found = [f for f in self.findings(fid) if tag is None or tag in f.get("tags", [])]
        assert found, "no finding %s%s in %s" % (fid, " tagged " + tag if tag else "", self.name)
        return found[0]

    def verdict(self, fid: str, tag: Optional[str] = None) -> str:
        return self.finding(fid, tag)["verdict"]

    def stage(self, name: str) -> Dict[str, Any]:
        return next(s for s in self.report["stages"] if s["name"] == name)

    @property
    def details(self) -> Dict[str, Any]:
        return self.report["engine_details"]


class Runs:
    def __init__(self, ipas: Dict[str, Path], base: Path, home: Path) -> None:
        self.ipas, self.base, self.home = ipas, base, home
        self._cli: Dict[Tuple[str, Tuple[str, ...]], CliRun] = {}
        self._lib: Dict[str, Any] = {}

    # -- CLI ------------------------------------------------------------------------------------------------
    def cli(self, name: str, *args: str, env: Optional[Dict[str, str]] = None, input_path: Optional[Path] = None,
            offline: bool = True) -> CliRun:
        key = (name, tuple(args) + (("--offline",) if offline else ()) + tuple(sorted((env or {}).items()))
               + ((str(input_path),) if input_path else ()))
        if key in self._cli:
            return self._cli[key]
        out_base = self.base / ("out-%d" % len(self._cli))
        run = run_cli(input_path or self.ipas[name], out_base, self.home, args, env=env, offline=offline, name=name)
        self._cli[key] = run
        return run

    # -- library --------------------------------------------------------------------------------------------
    def lib(self, name: str):
        """Run the whole pipeline in-process (offline, hermetic home); returns the (closed) AnalysisContext."""
        if name in self._lib:
            return self._lib[name]
        from ipa_analyzer import pipeline
        from ipa_analyzer.config import Config
        from ipa_analyzer.context import AnalysisContext

        with pytest.MonkeyPatch.context() as mp:
            mp.setenv("IPA_ANALYZER_HOME", str(self.home))
            for var in _HOST_ENV_VARS:
                mp.delenv(var, raising=False)
            cfg = Config(output_dir=self.base / ("lib-" + name), offline=True)
            ctx = AnalysisContext(cfg, self.ipas[name])
            pipeline.ensure_analyzers_loaded()
            try:
                ctx.outcome = pipeline.run(ctx)
            finally:
                ctx.close()
        self._lib[name] = ctx
        return ctx


def run_cli(ipa: Path, out_base: Path, home: Path, args: Sequence[str] = (), *, env: Optional[Dict[str, str]] = None,
            offline: bool = True, name: str = "", command: str = "analyze") -> CliRun:
    cmd = [sys.executable, str(SCRIPT_PATH), command, str(ipa), "-o", str(out_base)] + list(args)
    if offline:
        cmd.append("--offline")
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=CLI_TIMEOUT_S, env=hermetic_env(home, env), cwd=str(SKILL_ROOT))
    run = CliRun(name or ipa.stem, proc, out_base)
    reports = sorted(out_base.glob("*/report.json")) if out_base.exists() else []
    if reports:
        run.report_path = reports[0]
        run.report = json.loads(reports[0].read_text(encoding="utf-8"))
        md = reports[0].parent / "report.md"
        if md.is_file():
            run.md_path, run.md = md, md.read_text(encoding="utf-8")
    return run


def path_without_dotnet(path: Optional[str] = None) -> str:
    """``PATH`` with every directory that contains a ``dotnet`` executable removed."""
    names = ("dotnet", "dotnet.exe")
    keep = []
    for d in (path if path is not None else os.environ.get("PATH", "")).split(os.pathsep):
        if d and not any(os.path.isfile(os.path.join(d, n)) for n in names):
            keep.append(d)
    return os.pathsep.join(keep)


def no_dotnet_env(fake_home: Path) -> Dict[str, str]:
    """Extra environment for a run on a machine without .NET: filtered PATH, no ``DOTNET_ROOT``, empty user home."""
    fake_home.mkdir(parents=True, exist_ok=True)
    return {"PATH": path_without_dotnet(), "HOME": str(fake_home), "USERPROFILE": str(fake_home),
            "DOTNET_ROOT": "", "DOTNET_CLI_HOME": str(fake_home)}


def run_cli_command(args: Sequence[str], home: Path, *, env: Optional[Dict[str, str]] = None,
                    timeout: int = 120) -> "subprocess.CompletedProcess[str]":
    """Run ``ipa_analyze.py <args>`` (any sub-command) hermetically."""
    return subprocess.run([sys.executable, str(SCRIPT_PATH)] + list(args), capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout, env=hermetic_env(home, env),
                          cwd=str(SKILL_ROOT))
