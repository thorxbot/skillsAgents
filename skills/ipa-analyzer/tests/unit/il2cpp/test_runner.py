"""run_il2cpp_dump against the fake dumper: success / failure / timeout / interactive stall + pre-flight + cache."""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from ipa_analyzer.il2cpp import Il2CppErrorCode as E
from ipa_analyzer.il2cpp import run_il2cpp_dump
from ipa_analyzer.il2cpp import backends as backends_mod
from ipa_analyzer.il2cpp.runner import (CACHE_MARKER, PromptRule, extract_slice, inspect_macho, run_supervised)
from ipa_analyzer.il2cpp.tools import ToolManager


posix_only = pytest.mark.skipif(os.name == "nt", reason="uses POSIX process-group checks")


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    # a zombie still answers kill(0); treat "not running" via /proc or ps when available
    try:
        import subprocess
        out = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
        return bool(out) and not out.startswith("Z")
    except OSError:
        return True


def run(req, cfg_fake):
    return run_il2cpp_dump(req, ToolManager(cfg_fake, cache_root=req.work_dir.parent / "cache", offline=True), cfg_fake)


def test_success_collects_artifacts_and_rewrites_config(make_req, cfg_fake):
    # FAKE_DUMPER_CONFIG_AWARE=1 + RequireAnyKey=true in the tool's config.json: the run only finishes
    # promptly (and without a warning) if the runner wrote RequireAnyKey=false into its private tool copy.
    req = make_req("success")
    res = run(req, cfg_fake)
    assert res.ok, res.message
    assert res.backend == "il2cppdumper" and not res.cached
    for name in ("dump.cs", "script.json", "il2cpp.h", "stringliteral.json", "DummyDll", "run.log"):
        assert name in res.artifacts and (req.out_dir / res.artifacts[name]).exists(), name
    assert (req.out_dir / "DummyDll" / "Assembly-CSharp.dll").is_file()
    assert "prompt" not in res.message
    assert res.attempts[0]["ok"] is True
    assert any("Done!" in ln for ln in res.stdout_tail)
    # the cached tool copy / original config.json must be untouched
    assert '"RequireAnyKey": true' in (Path(cfg_fake.il2cpp.tool_path).parent / "config.json").read_text(encoding="utf-8")
    # work dir is cleaned
    assert not any(p.name.startswith("il2cpp-") for p in req.work_dir.iterdir())


def test_second_run_reuses_cached_result(make_req, cfg_fake):
    req = make_req("success")
    first = run(req, cfg_fake)
    assert first.ok and (req.out_dir / CACHE_MARKER).is_file()
    # a failing tool would be an error if it really ran again
    req2 = make_req("fail_nonzero")
    second = run(req2, cfg_fake)
    assert second.ok and second.cached and second.message == "reused cached dump"
    assert second.artifacts == first.artifacts


def test_cache_invalidated_when_inputs_change(make_req, cfg_fake, inputs, builders):
    macho_thin, macho_fat, metadata_bytes = builders.macho_thin, builders.macho_fat, builders.metadata_bytes
    CPU_ARM64, CPU_X86_64 = builders.CPU_ARM64, builders.CPU_X86_64
    assert run(make_req("success"), cfg_fake).ok
    (inputs / "global-metadata.dat").write_bytes(metadata_bytes(24, size=8192))
    res = run(make_req("fail_nonzero"), cfg_fake)
    assert not res.ok and not res.cached


def test_nonzero_exit_is_unknown_with_tail(make_req, cfg_fake):
    res = run(make_req("fail_nonzero"), cfg_fake)
    assert not res.ok and res.error_code == E.E_UNKNOWN
    assert "exited with code 3" in res.message
    assert any("exploded" in ln for ln in res.stdout_tail)
    assert res.remediation


def test_exit_zero_with_error_text_is_classified(make_req, cfg_fake):
    # the real Il2CppDumper exits 0 on errors; the classification must come from its output
    res = run(make_req("metadata_encrypted"), cfg_fake)
    assert res.error_code == E.E_METADATA_ENCRYPTED


def test_unsupported_metadata_version(make_req, cfg_fake):
    res = run(make_req("unsupported_version"), cfg_fake)
    assert res.error_code == E.E_METADATA_VERSION_UNSUPPORTED
    assert "35" in res.message


def test_registration_prompt_is_detected_and_killed(make_req, cfg_fake):
    t0 = time.monotonic()
    res = run(make_req("registration", timeout_s=60), cfg_fake)
    assert res.error_code == E.E_REGISTRATION_NOT_FOUND
    assert time.monotonic() - t0 < 20   # killed on the prompt, not on the timeout


def test_interactive_press_any_key_stall(make_req, cfg_fake):
    t0 = time.monotonic()
    res = run(make_req("prompt", timeout_s=60), cfg_fake)
    assert not res.ok and res.error_code == E.E_UNKNOWN
    assert "waiting for interactive input" in res.message
    assert time.monotonic() - t0 < 20


def test_fat_prompt_partial_line_detected(make_req, cfg_fake):
    res = run(make_req("fat_prompt", timeout_s=60), cfg_fake)
    assert not res.ok and "Select Platform" in res.message


def test_dotnet_host_failure_maps_to_dotnet_missing(make_req, cfg_fake):
    res = run(make_req("dotnet_missing"), cfg_fake)
    assert res.error_code == E.E_DOTNET_MISSING


def test_truncated_dump_is_not_success(make_req, cfg_fake):
    res = run(make_req("truncated"), cfg_fake)
    assert not res.ok and "truncated" in res.message


def test_idle_timeout_when_tool_is_silent(make_req, cfg_fake):
    t0 = time.monotonic()
    res = run(make_req("silent", timeout_s=60, extra={"idle_timeout_s": 6}), cfg_fake)
    assert res.error_code == E.E_TIMEOUT and "no output" in res.message
    assert time.monotonic() - t0 < 30


@posix_only
def test_global_timeout_kills_the_whole_process_tree(make_req, cfg_fake, tmp_path):
    pidfile = tmp_path / "pids.txt"
    req = make_req("hang", timeout_s=7, extra_env={"FAKE_DUMPER_PIDFILE": str(pidfile)},
                   extra={"idle_timeout_s": 600})
    res = run(req, cfg_fake)
    assert res.error_code == E.E_TIMEOUT
    parent, child = (int(x) for x in pidfile.read_text(encoding="utf-8").split())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and (_alive(parent) or _alive(child)):
        time.sleep(0.1)
    assert not _alive(parent), "dumper process survived the timeout"
    assert not _alive(child), "grandchild survived the timeout (process tree not killed)"


# --- validation / pre-flight ---------------------------------------------------------------------------------
def test_missing_inputs(make_req, cfg_fake, inputs):
    (inputs / "bin").unlink()
    res = run(make_req("success"), cfg_fake)
    assert res.error_code == E.E_UNKNOWN and "not found" in res.message


def test_wrong_metadata_magic_fails_fast(make_req, cfg_fake, inputs):
    (inputs / "global-metadata.dat").write_bytes(b"\x01\x02\x03\x04" * 1000)
    res = run(make_req("success"), cfg_fake)
    assert res.error_code == E.E_METADATA_ENCRYPTED and res.attempts == []


def test_force_dump_skips_the_magic_check(make_req, cfg_fake, inputs):
    (inputs / "global-metadata.dat").write_bytes(b"\x01\x02\x03\x04" * 1000)
    res = run(make_req("metadata_encrypted", force_dump=True), cfg_fake)
    assert res.error_code == E.E_METADATA_ENCRYPTED and res.attempts   # the tool ran and said so itself


def test_fairplay_binary_is_refused(make_req, cfg_fake, inputs, builders):
    macho_thin, macho_fat, metadata_bytes = builders.macho_thin, builders.macho_fat, builders.metadata_bytes
    CPU_ARM64, CPU_X86_64 = builders.CPU_ARM64, builders.CPU_X86_64
    (inputs / "bin").write_bytes(macho_thin(cryptid=1))
    res = run(make_req("success"), cfg_fake)
    assert res.error_code == E.E_BINARY_FAIRPLAY and res.attempts == []
    assert "decrypt" in res.remediation.lower()


def test_decrypted_binary_with_encryption_command_is_accepted(make_req, cfg_fake, inputs, builders):
    macho_thin, macho_fat, metadata_bytes = builders.macho_thin, builders.macho_fat, builders.metadata_bytes
    CPU_ARM64, CPU_X86_64 = builders.CPU_ARM64, builders.CPU_X86_64
    (inputs / "bin").write_bytes(macho_thin(cryptid=0))
    assert run(make_req("success"), cfg_fake).ok


def test_fat_binary_is_thinned_to_arm64(make_req, cfg_fake, inputs, tmp_path, builders):
    macho_thin, macho_fat, metadata_bytes = builders.macho_thin, builders.macho_fat, builders.metadata_bytes
    CPU_ARM64, CPU_X86_64 = builders.CPU_ARM64, builders.CPU_X86_64
    arm, x86 = macho_thin(CPU_ARM64, payload=300), macho_thin(CPU_X86_64, payload=500)
    (inputs / "bin").write_bytes(macho_fat([(CPU_X86_64, x86), (CPU_ARM64, arm)]))
    info = inspect_macho(inputs / "bin")
    assert info.is_fat and [s.cputype for s in info.slices] == [CPU_X86_64, CPU_ARM64]
    out = extract_slice(inputs / "bin", info.preferred(), tmp_path / "thin")
    assert out.read_bytes() == arm
    assert run(make_req("success"), cfg_fake).ok


def test_fat_with_encrypted_arm64_slice(make_req, cfg_fake, inputs, builders):
    macho_thin, macho_fat, metadata_bytes = builders.macho_thin, builders.macho_fat, builders.metadata_bytes
    CPU_ARM64, CPU_X86_64 = builders.CPU_ARM64, builders.CPU_X86_64
    enc = macho_thin(CPU_ARM64, cryptid=1)
    (inputs / "bin").write_bytes(macho_fat([(CPU_X86_64, macho_thin(CPU_X86_64)), (CPU_ARM64, enc)]))
    assert run(make_req("success"), cfg_fake).error_code == E.E_BINARY_FAIRPLAY


def test_output_dir_guard(make_req, cfg_fake, tmp_path):
    req = make_req("success")
    req.out_dir = Path(Path.home().resolve())
    assert run(req, cfg_fake).error_code == E.E_UNKNOWN
    req = make_req("success", extra={"allowed_root": str(tmp_path / "elsewhere")})
    res = run(req, cfg_fake)
    assert res.error_code == E.E_UNKNOWN and "outside the allowed root" in res.message


def test_garbage_binary_is_still_staged(make_req, cfg_fake, inputs):
    (inputs / "bin").write_bytes(b"\x7fELF" + b"\0" * 100)   # non Mach-O: no pre-flight verdict, tool decides
    assert run(make_req("success"), cfg_fake).ok


# --- backend chain ------------------------------------------------------------------------------------------------
class _StubBackend:
    def __init__(self, name, outcome):
        self.name, self.outcome, self.calls = name, outcome, 0
        self.raw = {"version": "1.0"}

    def supports(self, mv, uv):
        return True

    def provision(self, tools, cfg):
        from ipa_analyzer.il2cpp import ProvisionResult
        if self.outcome == "provision_dotnet":
            return ProvisionResult(False, error_code=E.E_DOTNET_MISSING, message="no dotnet")
        return ProvisionResult(True, command=["x"], version="1.0")

    def run(self, req, prov, cfg):
        from ipa_analyzer.il2cpp import Il2CppRunResult
        self.calls += 1
        if self.outcome == "ok":
            (req.out_dir).mkdir(parents=True, exist_ok=True)
            (req.out_dir / "dump.cs").write_text("x", encoding="utf-8")
            return Il2CppRunResult(ok=True, artifacts={"dump.cs": "dump.cs"}, out_dir=req.out_dir)
        return Il2CppRunResult(ok=False, error_code=E(self.outcome), message=self.outcome)


@pytest.mark.parametrize("first,expect_second_called", [
    ("E_REGISTRATION_NOT_FOUND", True), ("E_METADATA_VERSION_UNSUPPORTED", True), ("provision_dotnet", True),
    ("E_TIMEOUT", False), ("E_METADATA_ENCRYPTED", False), ("E_BINARY_FAIRPLAY", False)])
def test_fallback_policy(first, expect_second_called, make_req, cfg, monkeypatch, tmp_path):
    a, b = _StubBackend("a", first), _StubBackend("b", "ok")
    monkeypatch.setattr(backends_mod, "select_backends", lambda mv, uv, c, **k: [a, b])
    mgr = ToolManager(cfg, cache_root=tmp_path / "c", offline=True)
    res = run_il2cpp_dump(make_req("success"), mgr, cfg)
    assert (b.calls == 1) == expect_second_called
    assert res.ok == expect_second_called
    assert [x["backend"] for x in res.attempts][0] == "a"
    if expect_second_called:
        assert res.backend == "b" and len(res.attempts) == 2
    else:
        assert res.error_code == E(first if first != "provision_dotnet" else "E_DOTNET_MISSING")


def test_all_backends_fail_reports_first_failure(make_req, cfg, monkeypatch, tmp_path):
    a, b = _StubBackend("a", "E_REGISTRATION_NOT_FOUND"), _StubBackend("b", "E_UNKNOWN")
    monkeypatch.setattr(backends_mod, "select_backends", lambda mv, uv, c, **k: [a, b])
    res = run_il2cpp_dump(make_req("success"), ToolManager(cfg, cache_root=tmp_path / "c", offline=True), cfg)
    assert not res.ok and res.error_code == E.E_REGISTRATION_NOT_FOUND and len(res.attempts) == 2


def test_no_backend_supports_version(make_req, cfg, monkeypatch, tmp_path):
    monkeypatch.setattr(backends_mod, "select_backends", lambda mv, uv, c, **k: [])
    res = run_il2cpp_dump(make_req("success"), ToolManager(cfg, cache_root=tmp_path / "c", offline=True), cfg)
    assert res.error_code == E.E_METADATA_VERSION_UNSUPPORTED


# --- the supervisor itself ----------------------------------------------------------------------------------------
def _py(code):
    return [sys.executable, "-u", "-c", code]


def test_supervisor_answers_answerable_prompts():
    code = "import sys\nsys.stdout.write('Continue? ')\nsys.stdout.flush()\nl=sys.stdin.readline()\nprint('got', l.strip())"
    rule = PromptRule(__import__("re").compile("Continue\\?"), "yes\n", "continue")
    r = run_supervised(_py(code), cwd=None, env=None, timeout_s=20, prompts=[rule])
    assert r.returncode == 0 and r.answered == 1 and "got yes" in r.all_lines()


def test_supervisor_merges_stderr_and_keeps_tail_bounded():
    code = "import sys\nfor i in range(1000): print('line', i)\nprint('E', file=sys.stderr)"
    r = run_supervised(_py(code), cwd=None, env=None, timeout_s=20, tail_n=50)
    assert r.returncode == 0 and r.lines_total == 1001 and len(r.tail) == 50
    assert "E" in r.tail or "E" in r.head


def test_supervisor_start_error():
    r = run_supervised(["/definitely/not/here"], cwd=None, env=None, timeout_s=5)
    assert r.start_error and r.returncode is None


def test_supervisor_redacts_user_paths():
    code = "print('/Users/someone/work/file')\nprint(r'C:\\Users\\Bob\\x')"
    r = run_supervised(_py(code), cwd=None, env=None, timeout_s=20)
    joined = "\n".join(r.all_lines())
    assert "someone" not in joined and "Bob" not in joined and "<user>" in joined
