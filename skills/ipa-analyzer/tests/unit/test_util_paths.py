from __future__ import annotations

from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from ipa_analyzer.util import paths


def test_cache_dir_per_platform():
    home = Path("/home/u")
    assert paths._pure_dirs("Darwin", {}, home, "cache") == PurePosixPath("/home/u/Library/Caches/ipa-analyzer")
    assert paths._pure_dirs("Linux", {}, home, "cache") == PurePosixPath("/home/u/.cache/ipa-analyzer")
    assert paths._pure_dirs("Linux", {"XDG_CACHE_HOME": "/x"}, home, "cache") == PurePosixPath("/x/ipa-analyzer")
    assert paths._pure_dirs("Windows", {"LOCALAPPDATA": "C:\\L"}, PureWindowsPath("C:/U"), "cache") == \
        PureWindowsPath("C:\\L\\ipa-analyzer\\cache")
    assert paths._pure_dirs("Windows", {}, PureWindowsPath("C:/U"), "cache") == \
        PureWindowsPath("C:/U/AppData/Local/ipa-analyzer/cache")
    assert paths._pure_dirs("Linux", {}, home, "data") == PurePosixPath("/home/u/.config/ipa-analyzer")
    assert paths._pure_dirs("Windows", {"APPDATA": "C:\\R"}, PureWindowsPath("C:/U"), "data") == \
        PureWindowsPath("C:\\R\\ipa-analyzer")
    assert paths._pure_dirs("Darwin", {}, home, "data").name == "ipa-analyzer"


def test_env_override_wins(tmp_path):
    env = {"IPA_ANALYZER_HOME": str(tmp_path / "h")}
    assert paths.cache_dir(env=env) == tmp_path / "h"
    assert paths.user_data_dir(env=env) == tmp_path / "h"
    assert paths._pure_dirs("Windows", {"IPA_ANALYZER_HOME": "D:\\h"}, PureWindowsPath("C:/U"), "cache") == \
        PureWindowsPath("D:\\h")


def test_cache_dir_default_is_absolute():
    assert paths.cache_dir().is_absolute()


def test_is_within_real_paths(tmp_path):
    base = tmp_path / "out"
    base.mkdir()
    assert paths.is_within(base, base)
    assert paths.is_within(base, base / "a" / "b.txt")
    assert not paths.is_within(base, base / ".." / "evil")
    assert not paths.is_within(base, tmp_path / "out2" / "x")
    assert not paths.is_within(base, tmp_path)


def test_is_within_symlink_escape(tmp_path):
    base = tmp_path / "out"
    base.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = base / "lnk"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    assert not paths.is_within(base, link / "f")


@pytest.mark.parametrize("base,p,expected", [
    ("C:\\out", "C:\\out\\a\\b", True),
    ("C:\\out", "c:\\OUT\\a", True),
    ("C:\\out", "C:\\out\\..\\x", False),
    ("C:\\out", "D:\\out\\a", False),
    ("C:\\out", "C:\\outside", False),
    ("C:\\out", "C:\\out\\a\\..\\b", True),
    ("\\\\srv\\share\\o", "\\\\srv\\share\\o\\f", True),
])
def test_is_within_windows_lexical(base, p, expected):
    assert paths.is_within(PureWindowsPath(base), PureWindowsPath(p), resolve=False) is expected


def test_is_within_mixed_flavours():
    assert not paths.is_within(PureWindowsPath("C:/a"), PurePosixPath("/a/b"), resolve=False)


@pytest.mark.parametrize("name", ["CON", "con", "CON.txt", "nul.tar.gz", "COM1", "lpt9.log", "AUX ", "COM\u00b9",
                                  "CONIN$"])
def test_reserved_detected_and_sanitised(name):
    assert paths.is_windows_reserved(name)
    s = paths.sanitize_component(name)
    assert not paths.is_windows_reserved(s)


@pytest.mark.parametrize("name", ["console", "COM10", "comma", "LPT", "my.CON.txt", "auxiliary"])
def test_non_reserved(name):
    assert not paths.is_windows_reserved(name)
    assert paths.sanitize_component(name) == name


@pytest.mark.parametrize("raw,expected", [
    ("a<b>c:d\"e|f?g*h", "a_b_c_d_e_f_g_h"),
    ("trailing. ", "trailing"),
    ("dots...", "dots"),
    ("", "_"),
    (".", "_"),
    ("..", "_"),
    ("a/b\\c", "a_b_c"),
    ("tab\there", "tab_here"),
    ("\u4e2d\u6587 \U0001f600.png", "\u4e2d\u6587 \U0001f600.png"),
])
def test_sanitize_component(raw, expected):
    assert paths.sanitize_component(raw) == expected


def test_sanitize_truncates_keeping_extension():
    s = paths.sanitize_component("x" * 400 + ".png", max_len=100)
    assert len(s) == 100 and s.endswith(".png")
    assert len(paths.sanitize_component("y" * 400, max_len=50)) == 50


def test_to_long_path():
    assert paths.to_long_path("C:/a/b", system="Windows") == "\\\\?\\C:\\a\\b"
    assert paths.to_long_path("\\\\srv\\sh\\f", system="Windows") == "\\\\?\\UNC\\srv\\sh\\f"
    assert paths.to_long_path("\\\\?\\C:\\a", system="Windows") == "\\\\?\\C:\\a"
    assert paths.to_long_path("/tmp/x", system="Linux") == "/tmp/x"


def test_resource_dir_finds_skill_data():
    assert paths.resource_dir("schemas").is_dir()
