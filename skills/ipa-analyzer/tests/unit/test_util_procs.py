from __future__ import annotations

import os
import sys
import time

import pytest

from ipa_analyzer.util import procs

PY = sys.executable


def test_run_success_captures_output():
    r = procs.run([PY, "-c", "import sys; print('héllo'); sys.stderr.write('e')"], timeout=20)
    assert r.ok and r.stdout.strip() == "héllo" and r.stderr == "e"


def test_run_nonzero_exit():
    r = procs.run([PY, "-c", "import sys; sys.exit(3)"], timeout=20)
    assert r.returncode == 3 and not r.ok and not r.timed_out


def test_run_missing_executable():
    r = procs.run(["/definitely/not/here/xyz"], timeout=5)
    assert r.error and not r.ok and r.returncode is None


def test_run_timeout_kills_quickly():
    t0 = time.monotonic()
    r = procs.run([PY, "-c", "import time; time.sleep(60)"], timeout=0.5)
    assert r.timed_out and not r.ok
    assert time.monotonic() - t0 < 15


def test_stdin_is_closed_by_default():
    r = procs.run([PY, "-c", "import sys; print(repr(sys.stdin.read()))"], timeout=20)
    assert r.ok and r.stdout.strip() == "''"


def test_input_is_passed():
    r = procs.run([PY, "-c", "import sys; print(sys.stdin.read().upper())"], timeout=20, input=b"abc")
    assert r.stdout.strip() == "ABC"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process groups")
def test_timeout_kills_grandchildren(tmp_path):
    pidfile = tmp_path / "pid"
    code = (
        "import subprocess, sys, time\n"
        "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        "open(%r, 'w').write(str(p.pid))\n"
        "time.sleep(60)\n" % str(pidfile))
    r = procs.run([PY, "-c", code], timeout=1.5)
    assert r.timed_out
    pid = int(pidfile.read_text())
    deadline = time.monotonic() + 5
    alive = True
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            alive = False
            break
        # zombie reaped by init may take a moment
        time.sleep(0.05)
    assert not alive, "grandchild survived kill_tree"


def test_kill_tree_on_finished_process_is_noop():
    p = procs.popen([PY, "-c", "pass"])
    p.wait(timeout=20)
    procs.kill_tree(p)


def test_taskkill_command():
    assert procs.taskkill_command(1234) == ["taskkill", "/PID", "1234", "/T", "/F"]


def test_minimal_env_whitelist(monkeypatch):
    monkeypatch.setenv("SECRET_TOKEN", "x")
    monkeypatch.setenv("DOTNET_ROOT", "/d")
    env = procs.minimal_env({"A": "1"})
    assert "SECRET_TOKEN" not in env and env["DOTNET_ROOT"] == "/d" and env["A"] == "1"


def test_minimal_env_drops_unlisted_dotnet_variables(monkeypatch):
    monkeypatch.setenv("DOTNET_STARTUP_HOOKS", "/evil.dll")
    monkeypatch.setenv("DOTNET_ROLL_FORWARD", "Major")
    env = procs.minimal_env()
    assert "DOTNET_STARTUP_HOOKS" not in env and env["DOTNET_ROLL_FORWARD"] == "Major"


# --- which_safe: never resolve a tool from the working directory ----------------------------------------
def _exe(path):
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def test_which_safe_ignores_cwd_and_empty_path_entries(tmp_path, monkeypatch):
    cwd, real = tmp_path / "cwd", tmp_path / "bin"
    cwd.mkdir()
    real.mkdir()
    _exe(cwd / "mytool")
    monkeypatch.chdir(cwd)
    sep = os.pathsep
    for search in ("", ".", sep + str(real), str(cwd), str(cwd) + sep + "relative-nonexistent"):
        assert procs.which_safe("mytool", search) is None, search
    _exe(real / "mytool")
    assert procs.which_safe("mytool", str(cwd) + sep + str(real)) == os.path.join(str(real), "mytool")
    assert procs.which_safe("mytool", sep + str(real)) == os.path.join(str(real), "mytool")
    assert procs.which_safe("missing", str(real)) is None


def test_which_safe_windows_pathext_and_cwd(tmp_path, monkeypatch):
    cwd, real = tmp_path / "cwd", tmp_path / "bin"
    cwd.mkdir()
    real.mkdir()
    _exe(cwd / "dotnet.EXE")
    _exe(real / "dotnet.EXE")
    monkeypatch.chdir(cwd)
    got = procs.which_safe("dotnet", str(cwd) + os.pathsep + str(real), pathext=".COM;.EXE", windows=True)
    assert got == os.path.join(str(real), "dotnet.EXE")
    assert procs.which_safe("dotnet.EXE", str(cwd), pathext=".EXE", windows=True) is None
