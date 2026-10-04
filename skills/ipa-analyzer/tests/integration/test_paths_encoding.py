"""Paths, names and encodings: CJK / space / emoji in input path, output directory and bundle name, long names,
Windows reserved names (pure functions are parametrised so they also run on macOS / Linux), CRLF-stable output.
"""
from __future__ import annotations

import json
import plistlib
import re
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from fixtures.e2e_support import run_cli
from fixtures.ipa_builder import build_ipa
from fixtures.macho_builder import build_macho
from ipa_analyzer.util import paths as P

IS_WINDOWS = sys.platform == "win32"
APP = "我的 游戏 😀"


def make_ipa(path: Path, app_name: str = APP, extra=None) -> Path:
    files = {"Info.plist": plistlib.dumps({"CFBundleExecutable": "Main", "CFBundleIdentifier": "com.example.cn",
                                           "CFBundleDisplayName": "中文名 😀"}),
             "Main": build_macho(arch="arm64", strings=["x"]), "res/图片 1.png": b"\x89PNG\r\n\x1a\n" + b"0" * 40}
    files.update(extra or {})
    return build_ipa(path, files, app_name=app_name)


def test_cjk_space_emoji_in_input_path_output_dir_and_bundle_name(tmp_path, runs):
    ipa = make_ipa(tmp_path / "输入 目录 📦" / "应用 包 v1.ipa")
    out = tmp_path / "输出 目录 🎮"
    r = run_cli(ipa, out, runs.home, ["--extract", "binary"], name="unicode")
    assert r.returncode == 0, r.proc.stderr[-1000:]
    assert r.report["app"]["selected_name"] == "中文名 😀"
    assert "中文名 😀" in r.md and "Main" in r.md
    assert r.report_path.parent.parent == out and r.report_path.parent.name.startswith("应用 包 v1-")
    assert (r.report_path.parent / "split" / "binary" / "Main").is_file()
    json.loads(r.report_path.read_text(encoding="utf-8"))
    # the same input through the "stdout" side: the summary lines print without raising on a narrow console encoding
    assert "report:" in r.proc.stdout


def test_ascii_only_console_does_not_break_the_run(tmp_path, runs):
    ipa = make_ipa(tmp_path / "应用.ipa")
    r = run_cli(ipa, tmp_path / "o", runs.home, [], env={"PYTHONUTF8": "0", "PYTHONIOENCODING": "ascii", "LC_ALL": "C"},
                name="ascii-console")
    assert r.returncode == 0, r.proc.stderr[-800:]
    assert r.report is not None and "Traceback" not in r.proc.stderr


def test_long_input_name_and_deep_output_directory(tmp_path, runs):
    n = 120 if IS_WINDOWS else 200                                   # Windows: stay below MAX_PATH without long-path support
    ipa = make_ipa(tmp_path / ("长 名字 " + "x" * n + ".ipa"))
    out = tmp_path / "输出" / ("deep" * (5 if IS_WINDOWS else 30))
    r = run_cli(ipa, out, runs.home, [], name="long")
    assert r.returncode == 0, r.proc.stderr[-800:]
    assert r.report is not None and len(r.report_path.parent.name) <= 255


def test_archive_names_that_windows_cannot_store_are_sanitised_on_extraction(tmp_path, runs):
    extra = {"CON.png": b"\x89PNG\r\n\x1a\n" + b"0" * 50, "aux.txt": b"hello", "a:b?.txt": b"x", "trail.": b"y",
             "dir/Nul.txt": b"q", "COM1": b"c", "Résumé/éa.txt": b"z", "Dup.txt": b"1", "dup.txt": b"2"}
    ipa = make_ipa(tmp_path / "w.ipa", app_name="App", extra=extra)
    r = run_cli(ipa, tmp_path / "o", runs.home, ["--extract", "all"], name="reserved")
    assert r.returncode == 0, r.proc.stderr[-800:]
    split = r.report_path.parent / "split" / "all"
    names = {p.name for p in split.rglob("*") if p.is_file()}
    assert "CON.png" not in names and "aux.txt" not in names and "COM1" not in names      # no reserved device names
    assert not any(re.search(r'[<>:"|?*]', n) or n.endswith((".", " ")) for n in names), names
    assert len({n.lower() for n in names}) == len(names), "case-insensitive collisions must be disambiguated"
    manifest = json.loads((split.parent / "all.manifest.json").read_text(encoding="utf-8"))
    assert manifest, "extraction must record the name mapping"


@pytest.mark.parametrize("name", ["CON", "con", "PRN", "AUX", "NUL", "COM1", "com9", "LPT1", "lpt9", "CON.txt", "nul.tar.gz",
                                  "aux.png", "COM1.dll"])
def test_windows_reserved_names_are_detected_and_renamed(name):
    assert P.is_windows_reserved(name)
    safe = P.sanitize_component(name)
    assert not P.is_windows_reserved(safe) and safe and safe != name


@pytest.mark.parametrize("name", ["console", "CONSOLE.txt", "com10", "lpt0x", "auxiliary", "nulled.bin", "COM", "main"])
def test_similar_but_legal_names_are_untouched(name):
    assert not P.is_windows_reserved(name)
    assert P.sanitize_component(name) == name


@pytest.mark.parametrize("raw", ['a<b>c', 'a:b', 'q?"x"', 'pipe|name', 'star*', 'trail.', 'trail ', 'ctl\x01x', '..', '.', '', ' '])
def test_sanitize_component_never_yields_unsafe_names(raw):
    out = P.sanitize_component(raw)
    assert out and out not in (".", "..") and not re.search(r'[<>:"|?*\x00-\x1f/\\]', out)
    assert not out.endswith((".", " ")) and not P.is_windows_reserved(out)


def test_sanitize_component_length_and_unicode():
    assert len(P.sanitize_component("é" * 400, max_len=255).encode("utf-8")) <= 255 * 4          # bounded
    assert len(P.sanitize_component("a" * 400, max_len=255)) <= 255
    assert P.sanitize_component("我的游戏 😀") == "我的游戏 😀"


@pytest.mark.parametrize("base,child,expected", [
    ("C:\\out", "C:\\out\\a\\b.txt", True), ("C:\\out", "C:\\out\\..\\evil", False), ("C:\\out", "D:\\out\\a", False),
    ("C:\\out", "c:\\OUT\\a", True), ("C:\\out", "C:\\outside\\a", False), ("C:\\out", "\\\\server\\share\\a", False)])
def test_is_within_windows_paths_pure(base, child, expected):
    assert P.is_within(PureWindowsPath(base), PureWindowsPath(child), resolve=False) is expected


@pytest.mark.parametrize("base,child,expected", [("/out", "/out/a/b", True), ("/out", "/out/../etc", False),
                                                 ("/out", "/outside/x", False), ("/out", "/out", True)])
def test_is_within_posix_paths_pure(base, child, expected):
    assert P.is_within(PurePosixPath(base), PurePosixPath(child), resolve=False) is expected


@pytest.mark.skipif(not IS_WINDOWS, reason="long-path prefix is Windows only")
def test_long_path_prefix_on_windows(tmp_path):
    p = P.to_long_path(tmp_path / ("a" * 100) / ("b" * 100) / ("c" * 100))
    assert str(p).startswith("\\\\?\\")


def test_crlf_does_not_change_json_stability(runs):
    """The reports are written with ``\\n`` only; re-reading with universal newlines or CRLF yields identical JSON."""
    raw = runs.cli("custom_engine").report_path.read_bytes()
    assert b"\r" not in raw
    a = json.loads(raw.decode("utf-8"))
    b = json.loads(raw.decode("utf-8").replace("\n", "\r\n"))
    assert a == b
    again = run_cli(runs.ipas["custom_engine"], runs.base / "again", runs.home, [], name="again")

    def scrub(o):
        """Drop every timing field (``duration_s`` also appears inside engine details and checker states)."""
        if isinstance(o, dict):
            return {k: scrub(v) for k, v in o.items() if k != "duration_s"}
        if isinstance(o, list):
            return [scrub(v) for v in o]
        return o

    def norm(rep):
        rep = scrub(json.loads(json.dumps(rep)))
        rep.pop("generated_at", None)
        rep["input"].pop("path", None)
        rep.pop("artifacts", None)
        rep.pop("config", None)
        return json.dumps(rep, sort_keys=True)

    # same input, same version -> identical JSON apart from time / duration / the temporary paths
    first = runs.cli("custom_engine").report
    assert norm(first).replace(str(runs.base), "") == norm(again.report).replace(str(runs.base), "")


def test_crlf_input_plists_and_text_files_are_handled(tmp_path, runs):
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\r\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
           '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\r\n<plist version="1.0">\r\n<dict>\r\n'
           '<key>CFBundleExecutable</key>\r\n<string>Main</string>\r\n<key>CFBundleIdentifier</key>\r\n'
           '<string>com.example.crlf</string>\r\n<key>CFBundleName</key>\r\n<string>CRLF App</string>\r\n'
           '</dict>\r\n</plist>\r\n').encode("utf-8")
    ipa = make_ipa(tmp_path / "crlf.ipa", app_name="Crlf", extra={"Info.plist": xml, "res/a.strings": b'"k" = "v";\r\n'})
    r = run_cli(ipa, tmp_path / "o", runs.home, [], name="crlf")
    assert r.returncode == 0 and r.report["app"]["bundle_id"] == "com.example.crlf"
