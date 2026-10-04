"""DoD 6: no .NET, no network. ``doctor`` and the analysis still run, the il2cpp part says what to do.

This is also what the CI job ``no-dotnet-offline`` runs (there, ``IPA_EXPECT_NO_DOTNET=1`` additionally asserts that
the runner really has no dotnet).
"""
from __future__ import annotations

import json
import os

import pytest

from fixtures.e2e_support import no_dotnet_env, path_without_dotnet, run_cli, run_cli_command
from fixtures.full_ipa_builders import DUMPER_SCRIPT


@pytest.fixture()
def env(tmp_path):
    return no_dotnet_env(tmp_path / "home-nodotnet")


def test_doctor_works_without_dotnet_and_network(runs, env):
    p = run_cli_command(["doctor", "--offline", "--json"], runs.home, env=env)
    assert p.returncode == 0, p.stderr
    checks = {c["name"]: c for c in json.loads(p.stdout)["checks"]}
    assert checks["network"]["level"] == "skip" and "offline" in checks["network"]["detail"]
    assert checks["stages"]["detail"].startswith("13")
    assert checks["dotnet"]["level"] == "warn" and "not found" in checks["dotnet"]["detail"]
    human = run_cli_command(["doctor", "--offline"], runs.home, env=env)
    assert human.returncode == 0 and "[SKIP] network" in human.stdout


@pytest.mark.skipif(os.environ.get("IPA_EXPECT_NO_DOTNET") != "1", reason="only in the no-dotnet CI job")
def test_ci_runner_really_has_no_dotnet():
    """Guards the CI job itself: if the runner image ships .NET the job would silently test nothing."""
    import shutil
    from pathlib import Path

    assert shutil.which("dotnet") is None
    for p in ("/usr/share/dotnet", "/usr/lib/dotnet", "/usr/local/share/dotnet", "C:\\Program Files\\dotnet"):
        assert not (Path(p) / ("dotnet.exe" if os.name == "nt" else "dotnet")).exists(), p
    assert path_without_dotnet() == os.environ.get("PATH", "")


def test_analysis_is_complete_and_the_dump_is_not_attempted_blindly(runs, tmp_path, env):
    r = run_cli(runs.ipas["unity_il2cpp_plain"], tmp_path / "out", runs.home, [], env=env, name="nodotnet")
    assert r.returncode == 0, r.proc.stderr[-1500:]
    assert [s["status"] for s in r.report["stages"] if s["name"] != "engine.unity"].count("failed") == 0
    st = r.stage("engine.unity")
    assert st["status"] == "partial" and st["reason"].startswith("il2cpp dump failed: E_")
    dump = r.details["unity"]["dump"]
    assert dump["ok"] is False and dump["error_code"] in ("E_TOOL_DOWNLOAD_FAILED", "E_DOTNET_MISSING")
    assert dump["remediation"] and ("--il2cpp-tool" in dump["remediation"] or "dotnet" in dump["remediation"].lower())
    assert r.verdict("unity.il2cpp.precheck") == "yes"                      # the pre-checks themselves passed
    assert "## 7." in r.md and "能否 dump" in r.md


def test_tool_without_dotnet_runtime_reports_e_dotnet_missing(runs, tmp_path, env):
    dll = tmp_path / "tool" / "Il2CppDumper.dll"
    dll.parent.mkdir()
    dll.write_bytes(b"MZ")
    r = run_cli(runs.ipas["unity_il2cpp_plain"], tmp_path / "out", runs.home,
                ["--il2cpp-tool", str(dll), "--dotnet", str(tmp_path / "nowhere" / "dotnet")], env=env, name="nodotnet-dll")
    dump = r.details["unity"]["dump"]
    assert r.returncode == 0 and dump["error_code"] == "E_DOTNET_MISSING"
    assert "--yes" in dump["remediation"] and "install" in dump["remediation"].lower()   # asks before installing anything


def test_python_tool_needs_no_dotnet(runs, tmp_path, env):
    r = run_cli(runs.ipas["unity_il2cpp_plain"], tmp_path / "out", runs.home, ["--il2cpp-tool", str(DUMPER_SCRIPT)],
                env=env, name="nodotnet-fake")
    assert r.verdict("unity.il2cpp.dump") == "yes"


def test_tools_install_offline_refuses_to_download(runs, env):
    p = run_cli_command(["tools", "install", "il2cppdumper", "--offline"], runs.home, env=env)
    assert p.returncode == 4
    assert "offline" in (p.stdout + p.stderr).lower()
    lst = run_cli_command(["tools", "list", "--offline"], runs.home, env=env)
    assert lst.returncode == 0
