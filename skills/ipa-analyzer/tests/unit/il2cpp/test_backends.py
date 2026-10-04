"""Backend support matrix, ordering and provisioning (fake dotnet / fake downloads only)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from ipa_analyzer.config import Config
from ipa_analyzer.il2cpp import Il2CppErrorCode as E
from ipa_analyzer.il2cpp import backends as B
from ipa_analyzer.il2cpp import dotnet as D
from ipa_analyzer.il2cpp.runner import inspect_macho
from ipa_analyzer.il2cpp.tools import ToolManager


@pytest.mark.parametrize("mv,uv,expected", [
    (24, None, ["il2cppdumper", "redux"]),
    (31, None, ["il2cppdumper", "redux"]),
    (31, "2022.3.40f1", ["il2cppdumper", "cpp2il", "redux"]),
    (35, None, ["redux"]),
    (35, "6000.3.0f1", ["cpp2il", "redux"]),
    (15, "5.2.0f1", []),
    (16, None, ["il2cppdumper", "redux"]),
    (None, None, ["il2cppdumper", "redux"]),
    (110, "6000.7.0a3", ["redux"]),
    (150, "6000.9", []),
])
def test_default_selection_matrix(mv, uv, expected):
    assert [b.name for b in B.select_backends(mv, uv, Config())] == expected


def test_backend_order_override_and_unknown_names():
    cfg = Config()
    cfg.il2cpp.backend_order = ["redux", "bogus", "il2cppdumper"]
    assert [b.name for b in B.select_backends(31, None, cfg)] == ["redux", "il2cppdumper"]
    cfg.il2cpp.backend_order = ["cpp2il"]
    assert B.select_backends(31, None, cfg) == []         # needs the Unity version


def test_fractional_versions():
    d = B.Il2CppDumperBackend()
    assert d.supports(24.2, None) and d.supports(29.1, None) and not d.supports(31.5, None)


def test_backends_satisfy_protocol():
    from ipa_analyzer.il2cpp import Il2CppBackend
    for cls in B.BACKEND_CLASSES.values():
        assert isinstance(cls(), Il2CppBackend)


def test_catalog_version_for_cache_key():
    cfg = Config()
    d = B.Il2CppDumperBackend()
    assert B.catalog_version(d, cfg) == "6.7.46"
    cfg.il2cpp.tool_path = "/x/tool"
    assert B.catalog_version(d, cfg) == "custom:/x/tool"


def _dll_tool(tmp_path, major=6):
    d = tmp_path / "t"
    d.mkdir()
    (d / "Il2CppDumper.dll").write_bytes(b"x")
    (d / "config.json").write_text("{}", encoding="utf-8")
    (d / "Il2CppDumper.runtimeconfig.json").write_text(
        json.dumps({"runtimeOptions": {"framework": {"name": "Microsoft.NETCore.App", "version": "%d.0.0" % major}}}), encoding="utf-8")
    return d / "Il2CppDumper.dll"


def test_provision_explicit_python_tool_needs_no_dotnet(fake_tool, tmp_path, cfg):
    cfg.il2cpp.tool_path = str(fake_tool)
    prov = B.Il2CppDumperBackend().provision(ToolManager(cfg, cache_root=tmp_path / "c", offline=True), cfg)
    assert prov.ok and prov.command == [sys.executable, str(fake_tool)] and prov.kind == "python"
    assert prov.source == "explicit" and prov.version == "custom" and prov.tool_dir == fake_tool.parent
    assert prov.env["DOTNET_CLI_TELEMETRY_OPTOUT"] == "1" and prov.env["NO_COLOR"] == "true"


def test_provision_dll_uses_dotnet_with_roll_forward(tmp_path, cfg, monkeypatch):
    dll = _dll_tool(tmp_path)
    dn = tmp_path / "dn" / "dotnet"
    dn.parent.mkdir()
    dn.write_text("x", encoding="utf-8")
    monkeypatch.setattr(D, "list_runtimes", lambda p, **k: [D.RuntimeInfo(D.RUNTIME_NAME, "8.0.25", "/x")])
    cfg.il2cpp.tool_path, cfg.il2cpp.dotnet_path = str(dll), str(dn)
    prov = B.Il2CppDumperBackend().provision(ToolManager(cfg, cache_root=tmp_path / "c", offline=True), cfg)
    assert prov.ok and prov.command == [str(dn), str(dll)] and prov.kind == "dotnet_dll"
    assert prov.env["DOTNET_ROLL_FORWARD"] == "Major" and Path(prov.env["DOTNET_ROOT"]) == dn.parent.resolve()


def test_provision_dotnet_missing_without_consent_does_not_download(tmp_path, cfg, monkeypatch):
    monkeypatch.setattr(D, "list_runtimes", lambda p, **k: [])
    monkeypatch.setattr(D, "iter_dotnet_candidates", lambda *a, **k: iter(()))

    def boom(*a, **k):
        raise AssertionError("downloaded although .NET is not available/authorised")
    mgr = ToolManager(cfg, cache_root=tmp_path / "c", downloader=boom, env={"PATH": ""}, system="Linux")
    prov = B.Il2CppDumperBackend().provision(mgr, cfg)
    assert not prov.ok and prov.error_code == E.E_DOTNET_MISSING and "--yes" in prov.message


def test_provision_missing_tool_offline(tmp_path, cfg):
    mgr = ToolManager(cfg, cache_root=tmp_path / "c", offline=True, env={"PATH": ""})
    prov = B.Il2CppDumperBackend().provision(mgr, cfg)
    assert not prov.ok and prov.error_code == E.E_TOOL_DOWNLOAD_FAILED


def test_thin_macho_cputype_is_read_correctly(tmp_path, builders):
    p = tmp_path / "bin"
    p.write_bytes(builders.macho_thin(builders.CPU_X86_64))
    info = inspect_macho(p)
    assert info.slices[0].cputype == builders.CPU_X86_64 and info.preferred() is info.slices[0]


@pytest.mark.parametrize("force", [True, False])
def test_force_dump_is_written_to_the_dumper_config(tmp_path, force):
    from ipa_analyzer.il2cpp import Il2CppRunRequest
    backend = B.BACKEND_CLASSES["il2cppdumper"](B.load_catalog())
    cfg_file = tmp_path / "config.json"
    cfg_file.write_text(json.dumps({"RequireAnyKey": True, "ForceDump": not force}), encoding="utf-8")
    req = Il2CppRunRequest(binary_path=tmp_path / "b", metadata_path=tmp_path / "m", out_dir=tmp_path / "o",
                           force_dump=force)
    backend._write_config(cfg_file, req)
    written = json.loads(cfg_file.read_text(encoding="utf-8"))
    assert written["ForceDump"] is force and written["RequireAnyKey"] is False
    # an explicit dumper_config override from the caller still wins
    req2 = Il2CppRunRequest(binary_path=tmp_path / "b", metadata_path=tmp_path / "m", out_dir=tmp_path / "o",
                            force_dump=force, extra={"dumper_config": {"ForceDump": not force}})
    backend._write_config(cfg_file, req2)
    assert json.loads(cfg_file.read_text(encoding="utf-8"))["ForceDump"] is (not force)
