from __future__ import annotations

import pytest

from ipa_analyzer.libs import LibMatcher, Signal, load_kb, load_sysframeworks, normalize_dylib_name


@pytest.mark.parametrize("path,expected", [
    ("/usr/lib/libc++.1.dylib", "libc++"), ("/usr/lib/libSystem.B.dylib", "libSystem"), ("libz.1.2.11.dylib", "libz"),
    ("/usr/lib/libicucore.A.dylib", "libicucore"), ("/usr/lib/libobjc.A.dylib", "libobjc"), ("libsqlite3.dylib", "libsqlite3")])
def test_normalize_dylib_name(path, expected):
    assert normalize_dylib_name(path) == expected


def test_sysframework_lookup_variants():
    sf = load_sysframeworks()
    assert sf.lookup("/usr/lib/libsqlite3.dylib").name == "libsqlite3"
    assert sf.lookup("/usr/lib/swift/libswiftCore.dylib").purpose_en.startswith("Swift runtime")
    assert sf.lookup("/System/Library/Frameworks/NoSuch.framework/NoSuch") is None
    assert sf.lookup("/usr/lib/libdoesnotexist.dylib") is None


def test_framework_and_bundle_rules_with_confidence_growth():
    m = LibMatcher(load_kb(None))
    assert m.add(Signal("framework", "FirebaseCore", ref="a", via="dir")) == ["firebase_core"]
    c1 = m.items()[0]["confidence"]
    m.add(Signal("framework", "FirebaseCore", ref="b", via="load"))
    m.add(Signal("bundle", "FirebaseCore_Privacy", ref="b"))
    item = m.items()[0]
    assert item["id"] == "firebase_core" and item["kind"] == "framework" and item["confidence"] > c1
    assert item["confidence"] <= 0.97 and {e["kind"] for e in item["evidence"]} >= {"file", "macho"}


def test_glob_bundle_file_and_namespace_rules():
    m = LibMatcher(load_kb(None))
    assert m.add(Signal("bundle", "KSUSplashAdResource", ref="x")) == ["ksad"]
    assert m.add(Signal("bundle", "KSUSplashAdResource.bundle", ref="x")) == ["ksad"]
    assert m.add(Signal("file", "GoogleService-Info.plist", ref="x")) == ["firebase_core"]
    assert m.add(Signal("file", "sub/dir/GoogleService-Info.plist", ref="x")) == ["firebase_core"]
    assert m.add(Signal("namespace", "XLua.LuaDLL", ref="d")) == ["xlua"]
    assert m.add(Signal("namespace", "XLuaX", ref="d")) == []
    assert m.add(Signal("dylib", "libswiftCore.dylib", ref="b")) == ["swift_runtime"]
    assert m.add(Signal("framework", "TotallyUnknownKit", ref="b")) == []


def test_direct_signal_merges_into_kb_entry_and_synthesizes_missing():
    m = LibMatcher(load_kb(None))
    m.add(Signal("direct", lib_id="luajit", source_kind="hotfix", confidence=0.8, version="2.1", name="LuaJIT", category="hotfix"))
    m.add(Signal("direct", lib_id="zz_new", source_kind="fingerprint", confidence=0.6, name="Zz", category="engine",
                 purpose_en="Physics engine", purpose_zh="物理"))
    items = {i["id"]: i for i in m.items()}
    assert items["luajit"]["version"] == "2.1" and items["luajit"]["purpose_en"] and items["luajit"]["kind"] == "static_sdk"
    assert items["luajit"]["category"] == "hotfix"
    assert items["zz_new"]["name"] == "Zz" and items["zz_new"]["confidence"] == pytest.approx(0.54)
