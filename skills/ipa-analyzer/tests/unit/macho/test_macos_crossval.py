"""Optional cross-validation against Apple's tools (macOS only, never required).

Skipped on other platforms and when ``otool`` / ``codesign`` are missing: the parser itself never
shells out. System binaries differ between macOS releases, so only invariants are compared.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ipa_analyzer.macho import parse

pytestmark = pytest.mark.macos_only

CANDIDATES = ["/bin/ls", "/usr/bin/true", "/usr/bin/python3", "/Applications/Xcode.app/Contents/MacOS/Xcode",
              str(Path(sys.executable).resolve())]


def _targets():
    return [p for p in CANDIDATES if Path(p).is_file()]


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, shell=False)


@pytest.mark.skipif(shutil.which("otool") is None, reason="otool not available")
@pytest.mark.parametrize("path", _targets())
def test_dylibs_uuid_and_platform_match_otool(path):
    with parse(path) as mf:
        for sl in mf.slices:
            arch = sl.arch_name if mf.is_fat else None
            base = ["otool"] + (["-arch", arch] if arch else [])
            lib = _run(base + ["-L", path])
            if lib.returncode != 0:
                pytest.skip("otool cannot read %s (%s)" % (arch, lib.stderr.strip()[:80]))
            expect = [m.group(1) for m in re.finditer(r"^\s+(\S+) \(compatibility", lib.stdout, re.M)]
            assert [d.path for d in sl.dylibs] == expect
            full = _run(base + ["-l", path]).stdout
            uuid = re.search(r"LC_UUID\s+cmdsize \d+\s+uuid ([0-9A-F-]{36})", full)
            assert uuid and sl.uuid == uuid.group(1)
            plat = re.search(r"LC_BUILD_VERSION.*?platform (\S+)\s+minos (\S+)\s+sdk (\S+)", full, re.S)
            if plat:
                assert (sl.min_os, sl.sdk) == (plat.group(2), plat.group(3))
            rpaths = re.findall(r"LC_RPATH\s+cmdsize \d+\s+path (.+?) \(offset", full)
            assert sl.rpaths == rpaths


@pytest.mark.skipif(shutil.which("lipo") is None, reason="lipo not available")
@pytest.mark.parametrize("path", _targets())
def test_architectures_match_lipo(path):
    out = _run(["lipo", "-archs", path])
    if out.returncode != 0:
        pytest.skip("lipo failed")
    with parse(path) as mf:
        assert sorted(mf.arch_names) == sorted(out.stdout.split())


@pytest.mark.skipif(shutil.which("codesign") is None, reason="codesign not available")
@pytest.mark.parametrize("path", _targets())
def test_cdhash_and_identity_match_codesign(path):
    with parse(path) as mf:
        for sl in mf.slices:
            sig = sl.code_signature
            if sig is None or sig.parse_error:
                continue
            cmd = ["codesign", "-dvvv"] + (["--arch", sl.arch_name] if mf.is_fat else []) + [path]
            out = _run(cmd)
            text = out.stderr
            if out.returncode != 0 or "CDHash=" not in text:
                continue
            assert "CDHash=%s" % sig.cdhash in text
            assert "Identifier=%s" % sig.identifier in text
            team = re.search(r"TeamIdentifier=(.+)", text).group(1).strip()
            assert (sig.team_id or "not set") == team
