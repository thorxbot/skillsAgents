"""dotnet discovery / installation planning (pure functions + fakes; nothing is downloaded)."""
from __future__ import annotations

from pathlib import Path

import pytest

from ipa_analyzer.il2cpp import Il2CppErrorCode as E
from ipa_analyzer.il2cpp import dotnet as D
from ipa_analyzer.il2cpp.errors import ToolDownloadError

SAMPLE = """Microsoft.AspNetCore.App 8.0.25 [/usr/local/share/dotnet/shared/Microsoft.AspNetCore.App]
Microsoft.NETCore.App 6.0.36 [/usr/local/share/dotnet/shared/Microsoft.NETCore.App]
Microsoft.NETCore.App 8.0.25 [/usr/local/share/dotnet/shared/Microsoft.NETCore.App]
Microsoft.NETCore.App 10.0.0-preview.7.25380.108 [C:\\Program Files\\dotnet\\shared\\Microsoft.NETCore.App]
garbage line
"""


@pytest.fixture(autouse=True)
def _no_host_dotnet(monkeypatch):
    """Never discover the host's real dotnet through the well-known install locations (a Windows runner has one in
    ``C:\\Program Files\\dotnet``); tests that want a dotnet create their own."""
    monkeypatch.setattr(D, "_well_known", lambda system, env: [])


def test_parse_runtimes():
    rts = D.parse_runtimes(SAMPLE)
    assert [r.name for r in rts].count("Microsoft.NETCore.App") == 3
    assert D.best_runtime_major(rts) == 10
    pre = rts[-1]
    assert pre.major == 10 and pre.version_tuple == (10, 0, 0) and "Program Files" in pre.path
    assert D.parse_runtimes("") == [] and D.best_runtime_major([]) is None
    assert D.best_runtime_major([rts[0]]) is None      # AspNetCore alone is not Microsoft.NETCore.App


def _fake(tmp_path, name="dotnet.exe"):
    d = tmp_path / "dn"
    d.mkdir(exist_ok=True)
    p = d / name
    p.write_text("x", encoding="utf-8")
    return p


def test_candidate_order(tmp_path):
    root, cache, onpath = tmp_path / "r", tmp_path / "cache", tmp_path / "p"
    for d in (root, cache / "dotnet", onpath):
        d.mkdir(parents=True)
        (d / "dotnet.exe").write_text("x", encoding="utf-8")
        (d / "dotnet.exe").chmod(0o755)
    env = {"DOTNET_ROOT": str(root), "PATH": str(onpath)}
    got = list(D.iter_dotnet_candidates(None, cache_root=cache, env=env, system="Windows"))
    assert got[0].parent == root and got[1].parent == cache / "dotnet"
    assert any(p.parent == onpath for p in got)
    # explicit wins exclusively
    exp = _fake(tmp_path)
    assert list(D.iter_dotnet_candidates(str(exp), cache_root=cache, env=env, system="Windows")) == [exp]
    assert list(D.iter_dotnet_candidates(str(tmp_path / "nope"), cache_root=cache, env=env, system="Windows")) == []
    assert D.find_dotnet(str(exp.parent), env=env, system="Windows") == exp      # directory accepted


def test_dotnet_exe_names():
    assert D.dotnet_exe_name("Windows") == "dotnet.exe" and D.dotnet_exe_name("Linux") == "dotnet"


def test_build_install_command_posix():
    script, install_dir = Path("/c/dotnet-install.sh"), Path("/c/dotnet")      # str() is os-specific (\\ on Windows)
    cmd = D.build_install_command("Linux", script, install_dir=install_dir, channel="8.0")
    assert cmd == ["bash", str(script), "--runtime", "dotnet", "--channel", "8.0",
                   "--install-dir", str(install_dir), "--no-path"]


def test_build_install_command_windows_uses_arg_list_and_bypass_policy():
    cmd = D.build_install_command("Windows", Path(r"C:\c\dotnet-install.ps1"), install_dir=Path(r"C:\Users\x y\dotnet"),
                                  channel="10.0", shell_exe=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    assert cmd[0].endswith("powershell.exe")
    assert cmd[1:8] == ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                        r"C:\c\dotnet-install.ps1", "-Runtime"]
    assert "-Channel" in cmd and cmd[cmd.index("-Channel") + 1] == "10.0"
    assert cmd[cmd.index("-InstallDir") + 1] == r"C:\Users\x y\dotnet"      # one argv element, spaces intact
    assert cmd[-1] == "-NoPath" and all(isinstance(c, str) for c in cmd)


def test_build_env(tmp_path):
    exe = tmp_path / "dotnet"
    exe.write_text("x", encoding="utf-8")
    env = D.build_env(exe)
    assert env["DOTNET_ROLL_FORWARD"] == "Major" and env["DOTNET_CLI_TELEMETRY_OPTOUT"] == "1"
    assert env["DOTNET_NOLOGO"] == "1" and env["NO_COLOR"] == "true"
    assert Path(env["DOTNET_ROOT"]) == tmp_path.resolve()
    assert "DOTNET_ROLL_FORWARD" not in D.build_env(None, roll_forward="")
    assert D.build_env(exe, extra={"A": "b"})["A"] == "b"
    # not a blind copy of the parent environment
    import os
    os.environ["SOME_SECRET_TOKEN"] = "x"
    try:
        assert "SOME_SECRET_TOKEN" not in D.build_env(exe)
    finally:
        del os.environ["SOME_SECRET_TOKEN"]


def test_install_instructions_per_os():
    assert "brew" in D.install_instructions("Darwin") and "winget" in D.install_instructions("Windows")
    assert "apt" in D.install_instructions("Linux") and "10.0" in D.install_instructions("Linux", 10)


def _rts(*versions):
    return lambda _p: [D.RuntimeInfo(D.RUNTIME_NAME, v, "/x") for v in versions]


def test_ensure_runtime_finds_sufficient_runtime(tmp_path):
    exe = _fake(tmp_path)
    r = D.ensure_runtime(6, explicit=str(exe), runtimes_fn=_rts("8.0.25", "6.0.36"), system="Windows")
    assert r.ok and r.dotnet == exe and r.major == 8 and r.version == "8.0.25" and not r.installed


def test_ensure_runtime_self_contained_needs_nothing():
    r = D.ensure_runtime(0)
    assert r.ok and r.dotnet is None


def test_ensure_runtime_too_old_no_consent(tmp_path):
    exe = _fake(tmp_path)
    r = D.ensure_runtime(10, explicit=str(exe), runtimes_fn=_rts("8.0.25"), system="Windows")
    assert not r.ok and r.error_code == E.E_DOTNET_MISSING and "up to major 8" in r.message
    assert "--dotnet" in r.remediation       # explicit path: never installs behind the user's back


def test_ensure_runtime_missing_without_consent_gives_os_specific_guidance(tmp_path):
    called = []
    r = D.ensure_runtime(8, cache_root=tmp_path / "c", env={"PATH": ""}, system="Windows",
                         install_fn=lambda *a, **k: called.append(1))
    assert not r.ok and r.error_code == E.E_DOTNET_MISSING and called == []
    assert "winget" in r.remediation and "--yes" in r.remediation
    r = D.ensure_runtime(8, cache_root=tmp_path / "c", env={"PATH": ""}, system="Windows", consent_cb=lambda m: False,
                         install_fn=lambda *a, **k: called.append(1))
    assert not r.ok and called == []


def test_ensure_runtime_installs_after_consent(tmp_path):
    asked, installed = [], _fake(tmp_path, "dotnet.exe")

    def consent(msg):
        asked.append(msg)
        return True

    def install(channel, **kw):
        assert channel == "8.0" and kw["cache_root"] == tmp_path / "c"
        return installed
    r = D.ensure_runtime(8, cache_root=tmp_path / "c", env={"PATH": ""}, system="Windows", consent_cb=consent,
                         install_fn=install, runtimes_fn=_rts("8.0.31"))
    assert r.ok and r.installed and r.dotnet == installed and len(asked) == 1
    assert "no admin rights" in asked[0] and str(tmp_path / "c") in asked[0]


def test_ensure_runtime_allow_install_flag_skips_prompt(tmp_path):
    exe = _fake(tmp_path)
    r = D.ensure_runtime(8, cache_root=tmp_path / "c", env={"PATH": ""}, system="Windows", allow_install=True,
                         install_fn=lambda ch, **k: exe, runtimes_fn=_rts("8.0.1"))
    assert r.ok and r.installed


def test_ensure_runtime_install_failure_is_download_error(tmp_path):
    def fail(*a, **k):
        raise ToolDownloadError("network down", "network")
    r = D.ensure_runtime(8, cache_root=tmp_path / "c", env={"PATH": ""}, system="Windows", allow_install=True,
                         install_fn=fail)
    assert not r.ok and r.error_code == E.E_TOOL_DOWNLOAD_FAILED and "network down" in r.message


def test_ensure_runtime_install_that_does_not_provide_the_major(tmp_path):
    exe = _fake(tmp_path)
    r = D.ensure_runtime(10, cache_root=tmp_path / "c", env={"PATH": ""}, system="Windows", allow_install=True,
                         install_fn=lambda ch, **k: exe, runtimes_fn=_rts("8.0.1"), channel="8.0")
    assert not r.ok and r.error_code == E.E_DOTNET_MISSING


def test_default_consent(monkeypatch):
    assert D.default_consent(True)("x") is True
    monkeypatch.setattr(D.sys, "stdin", None)
    assert D.default_consent(False)("x") is False        # no TTY => never prompts, never assumes yes


def test_dotnet_is_never_resolved_from_the_working_directory(tmp_path, monkeypatch):
    import os
    cwd, real = tmp_path / "downloads", tmp_path / "bin"
    cwd.mkdir()
    real.mkdir()
    for d in (cwd, real):
        exe = d / D.dotnet_exe_name("Linux")
        exe.write_text("#!/bin/sh\n", encoding="utf-8")
        exe.chmod(0o755)
    monkeypatch.chdir(cwd)
    env = {"PATH": os.pathsep.join(["", ".", str(cwd), str(real)])}
    got = list(D.iter_dotnet_candidates(None, cache_root=tmp_path / "cache", env=env, system="Linux"))
    assert got[0] == real / D.dotnet_exe_name("Linux") and cwd / D.dotnet_exe_name("Linux") not in got
