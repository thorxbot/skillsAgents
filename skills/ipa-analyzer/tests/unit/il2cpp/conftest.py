"""Shared fixtures for the IL2CPP toolchain tests (fake dumper, synthetic Mach-O / metadata inputs)."""
from __future__ import annotations

import json
import shutil
import struct
from pathlib import Path

import pytest

from ipa_analyzer.config import Config
from ipa_analyzer.il2cpp import Il2CppRunRequest
from ipa_analyzer.il2cpp.tools import ToolManager

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
FAKE_DUMPER = FIXTURES / "fake_dumper.py"

MH_MAGIC_64 = 0xFEEDFACF
CPU_ARM64 = 0x0100000C
CPU_X86_64 = 0x01000007


def macho_thin(cputype: int = CPU_ARM64, *, cryptid: int | None = None, payload: int = 256) -> bytes:
    """Minimal thin 64-bit Mach-O; with ``cryptid`` an LC_ENCRYPTION_INFO_64 command is added."""
    cmds = b""
    if cryptid is not None:
        cmds = struct.pack("<IIIIII", 0x2C, 24, 0x4000, 0x1000, cryptid, 0)
    header = struct.pack("<IiiIIIII", MH_MAGIC_64, cputype, 0, 2, 1 if cmds else 0, len(cmds), 0, 0)
    return header + cmds + b"\0" * payload


def macho_fat(slices) -> bytes:
    """Big-endian fat file from [(cputype, thin_bytes)]."""
    n = len(slices)
    off = 8 + 20 * n
    off = (off + 15) & ~15
    table, body = b"", b""
    for cpu, data in slices:
        pad = (-(off + len(body))) % 16
        body += b"\0" * pad
        table += struct.pack(">iiIII", cpu, 0, off + len(body), len(data), 4)
        body += data
    return struct.pack(">II", 0xCAFEBABE, n) + table + b"\0" * (off - 8 - len(table)) + body


def metadata_bytes(version: int = 24, size: int = 4096) -> bytes:
    return struct.pack("<Ii", 0xFAB11BAF, version) + b"\0" * size


@pytest.fixture
def builders():
    """Synthetic Mach-O / metadata builders (conftest modules cannot be imported by name)."""
    import types
    return types.SimpleNamespace(macho_thin=macho_thin, macho_fat=macho_fat, metadata_bytes=metadata_bytes,
                                 CPU_ARM64=CPU_ARM64, CPU_X86_64=CPU_X86_64)


@pytest.fixture
def cfg() -> Config:
    c = Config()
    c.il2cpp.timeout_s = 60
    return c


@pytest.fixture
def inputs(tmp_path):
    d = tmp_path / "in"
    d.mkdir()
    (d / "bin").write_bytes(macho_thin())
    (d / "global-metadata.dat").write_bytes(metadata_bytes(24))
    return d


@pytest.fixture
def fake_tool(tmp_path) -> Path:
    """A tool directory laid out like Il2CppDumper's: fake_dumper.py + config.json (RequireAnyKey=true)."""
    d = tmp_path / "faketool"
    d.mkdir()
    shutil.copyfile(str(FAKE_DUMPER), str(d / "fake_dumper.py"))
    (d / "config.json").write_text(json.dumps({"RequireAnyKey": True, "DumpMethod": True}), encoding="utf-8")
    return d / "fake_dumper.py"


@pytest.fixture
def make_req(tmp_path, inputs):
    def _make(mode: str = "success", *, extra_env=None, timeout_s: int = 30, **kw) -> Il2CppRunRequest:
        env = {"FAKE_DUMPER_MODE": mode, "FAKE_DUMPER_CONFIG_AWARE": "1"}
        env.update(extra_env or {})
        extra = kw.pop("extra", {})
        extra = dict(extra, env=env)
        return Il2CppRunRequest(binary_path=inputs / "bin", metadata_path=inputs / "global-metadata.dat",
                                out_dir=tmp_path / "out" / "il2cpp", timeout_s=timeout_s, extra=extra,
                                work_dir=tmp_path / "work", **kw)
    return _make


@pytest.fixture
def mgr(tmp_path, cfg):
    return ToolManager(cfg, cache_root=tmp_path / "cache", offline=True)


@pytest.fixture
def cfg_fake(cfg, fake_tool):
    cfg.il2cpp.tool_path = str(fake_tool)
    cfg.il2cpp.backend_order = ["il2cppdumper"]
    cfg.offline = True
    return cfg
