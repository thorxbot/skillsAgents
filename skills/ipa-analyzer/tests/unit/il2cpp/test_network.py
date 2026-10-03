"""Real-network smoke tests (IPA_TEST_NETWORK=1): downloads Il2CppDumper into a temporary cache."""
from __future__ import annotations

import pytest

from ipa_analyzer.config import Config
from ipa_analyzer.il2cpp import Il2CppErrorCode as E
from ipa_analyzer.il2cpp import Il2CppRunRequest, run_il2cpp_dump
from ipa_analyzer.il2cpp import dotnet as D
from ipa_analyzer.il2cpp.runner import run_supervised
from ipa_analyzer.il2cpp.tools import ToolManager

pytestmark = pytest.mark.network


def test_download_install_and_help_smoke(tmp_path):
    cfg = Config()
    mgr = ToolManager(cfg, cache_root=tmp_path / "cache")
    res = mgr.install("il2cppdumper")
    assert res.ok, res.message               # SHA256 pinned in the catalog was verified by the download
    assert res.entry.name == "Il2CppDumper.dll" and (res.entry.parent / "config.json").is_file()
    dn = D.ensure_runtime(res.min_dotnet, cache_root=tmp_path / "cache")
    if not dn.ok:
        pytest.skip("no usable .NET runtime on this machine: " + dn.message)
    env = D.build_env(dn.dotnet)
    # --help and no-arguments must return immediately instead of hanging on a prompt
    for args in (["--help"], []):
        r = run_supervised([str(dn.dotnet), str(res.entry)] + args, cwd=str(tmp_path), env=env, timeout_s=60,
                           idle_timeout_s=30)
        assert r.returncode == 0 and any("usage:" in ln for ln in r.all_lines()), r.all_lines()


def test_real_dumper_on_synthetic_inputs_is_classified(tmp_path, builders):
    cfg = Config()
    cfg.il2cpp.backend_order = ["il2cppdumper"]
    mgr = ToolManager(cfg, cache_root=tmp_path / "cache")
    if not mgr.install("il2cppdumper").ok or not D.ensure_runtime(6, cache_root=tmp_path / "cache").ok:
        pytest.skip("tool or .NET unavailable")
    (tmp_path / "bin").write_bytes(builders.macho_thin())
    (tmp_path / "meta.dat").write_bytes(builders.metadata_bytes(24))
    req = Il2CppRunRequest(tmp_path / "bin", tmp_path / "meta.dat", tmp_path / "out", timeout_s=120, work_dir=tmp_path / "w")
    r = run_il2cpp_dump(req, mgr, cfg)
    assert not r.ok and r.error_code == E.E_REGISTRATION_NOT_FOUND and r.backend_version == "6.7.46"
