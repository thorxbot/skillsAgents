from __future__ import annotations

import pytest

from ipa_analyzer.engines.api import EngineSignature, SignalSpec
from ipa_analyzer.engines.scoring import (BinaryRec, EvidenceBundle, FileRec, detect_engines, glob_to_regex,
                                          infer_languages, match_signal, score_signature)
from ipa_analyzer.engines.signatures import SignatureSet

APP = "Payload/T.app/"


def files(*items):
    out = []
    for it in items:
        path, magic, size = (it, "unknown", 10) if isinstance(it, str) else it
        ext = ("." + path.rsplit(".", 1)[1].lower()) if "." in path.rsplit("/", 1)[-1] else ""
        out.append(FileRec(path=APP + path, rel=path, size=size, magic=magic, ext=ext))
    return out


def sig(id_, signals, *, thr=0.7, kind="game_engine", excl=(), family="", name=None):
    return EngineSignature(id=id_, name=name or id_, family=family, kind=kind, confirm_threshold=thr, exclusive_with=list(excl),
                           signals=[SignalSpec(**s) for s in signals])


def m(bundle, t, p, w=0.5):
    return match_signal(bundle, SignalSpec(t, p, w))


# --- file / dir globs ---------------------------------------------------------------------------------------------
def test_glob_regex_semantics():
    assert glob_to_regex("a/*.js").match("a/b.js") and not glob_to_regex("a/*.js").match("a/b/c.js")
    assert glob_to_regex("a/**/c.js").match("a/c.js") and glob_to_regex("a/**/c.js").match("a/x/y/c.js")
    assert glob_to_regex("a?c").match("abc") and not glob_to_regex("a?c").match("a/c")
    assert glob_to_regex("x.y").match("x.y") and not glob_to_regex("x.y").match("xzy")


def test_file_matching_anchored_basename_ext_and_case():
    b = EvidenceBundle(files("Data/Managed/Metadata/global-metadata.dat", "Foo/Bar.PAK", "a.txt", "deep/a/b/c/main.lua"))
    assert m(b, "file", "/Data/Managed/Metadata/global-metadata.dat")             # anchored, exact
    assert m(b, "file", "/data/managed/metadata/GLOBAL-METADATA.dat")             # case-insensitive
    assert not m(b, "file", "/global-metadata.dat")                               # anchored at the root only
    assert m(b, "file", "global-metadata.dat")                                    # basename anywhere
    assert m(b, "file", "*.pak") and m(b, "file", "*.lua") and not m(b, "file", "*.luac")
    assert m(b, "file", "Data/**/*.dat") and m(b, "file", "**/main.lua") and not m(b, "file", "Data/*.dat")
    assert m(b, "file", "main.*")
    r = m(b, "file", "*.pak")
    assert r.refs == [APP + "Foo/Bar.PAK"] and r.count == 1


def test_file_min_count_magic_and_head():
    fl = [FileRec(path=APP + "t/%d.bin" % i, rel="t/%d.bin" % i, magic="ccz", ext=".bin") for i in range(5)]
    fl += [FileRec(path=APP + "p/a.bin", rel="p/a.bin", magic="unknown", ext=".bin")]
    b = EvidenceBundle(fl, heads={APP + "p/a.bin": b"NXPK\x01\x02"})
    assert m(b, "file", "magic:ccz") and m(b, "file", "magic:ccz#5") and not m(b, "file", "magic:ccz#6")
    assert m(b, "file", "head:NXPK") and not m(b, "file", "head:NHPK")
    lazy = EvidenceBundle(fl, head_loader=lambda: {APP + "p/a.bin": b"NHPK"})
    assert m(lazy, "file", "head:NHPK")                                           # loaded on demand


def test_dir_matching():
    b = EvidenceBundle(files("Frameworks/Unity.framework/Unity", "cookeddata/Game/Content/a.pak", "x/assets/y.png"))
    assert m(b, "dir", "/Frameworks/Unity.framework") and m(b, "dir", "/cookeddata") and m(b, "dir", "assets")
    assert not m(b, "dir", "/assets") and m(b, "dir", "/x/assets") and m(b, "dir", "Frameworks/*.framework")
    assert m(b, "dir", "cookeddata/**/content") is not None
    assert not m(b, "dir", "/Frameworks/Missing.framework")


# --- binary side ----------------------------------------------------------------------------------------------------
def bin_bundle(**kw):
    rec = BinaryRec(rel="Test", path=APP + "Test", role="main", **kw)
    return EvidenceBundle(files("Test"), binaries=[rec])


def test_string_symbol_class_dylib_section_and_plist():
    b = bin_bundle(strings=[b"hello UnityAppController world", b"cocos2d-x 3.17.2"], symbols=["luaL_newstate", "ZN7cocos2d8Director4initEv", "OBJC_CLASS_$_CCDirector"],
                   classes=["CCDirector", "AppDelegate"], dylibs=["/System/Library/Frameworks/Metal.framework/Metal"],
                   sections=["__TEXT,__cstring"])
    b.plist["UIMainStoryboardFile"] = "Main"
    assert m(b, "string", "UnityAppController").refs == ["Test"]
    assert m(b, "string", r"re:cocos2d-x ([0-9.]+)") and not m(b, "string", "Unity Engine")
    assert m(b, "symbol", "luaL_newstate") and not m(b, "symbol", "luaL_newstat")
    assert m(b, "symbol", "ZN7cocos2d*") and m(b, "symbol", "*Director*") and m(b, "symbol", "re:^luaL_")
    assert not m(b, "symbol", "ZN8cocos2d*")
    assert m(b, "objc_prefix", "CCDir") and not m(b, "objc_prefix", "XXDir")
    assert m(b, "dylib", "metal.framework/metal") and m(b, "dylib", "Metal.framework") and not m(b, "dylib", "OpenGLES")
    assert m(b, "binary_section", "__TEXT,__cstring") and not m(b, "binary_section", "__DATA,__x")
    assert m(b, "plist_key", "UIMainStoryboardFile") and m(b, "plist_key", "UIMainStoryboardFile=Main")
    assert not m(b, "plist_key", "UIMainStoryboardFile=Other") and not m(b, "plist_key", "Nope")


def test_string_owner_is_the_binary_that_contains_it():
    a = BinaryRec(rel="A", strings=[b"alpha-only"])
    c = BinaryRec(rel="C", strings=[b"gamma-only"])
    b = EvidenceBundle([], binaries=[a, c])
    assert m(b, "string", "alpha-only").refs == ["A"] and m(b, "string", "gamma-only").refs == ["C"]


# --- scoring --------------------------------------------------------------------------------------------------------
def test_score_adds_weights_and_confirms_by_threshold_or_strong():
    b = EvidenceBundle(files("a.x", "b.y"))
    s = sig("e", [dict(type="file", pattern="a.x", weight=0.4), dict(type="file", pattern="b.y", weight=0.3),
                  dict(type="file", pattern="c.z", weight=0.9)])
    sc = score_signature(b, s)
    assert sc.score == pytest.approx(0.7) and sc.confirmed and sc.confidence == pytest.approx(0.7)
    assert not score_signature(b, sig("e", [dict(type="file", pattern="a.x", weight=0.4)])).confirmed
    strong = sig("e", [dict(type="file", pattern="a.x", weight=0.9, strong=True)], thr=2.0)
    sc = score_signature(b, strong)
    assert sc.confirmed and sc.confidence >= 0.9
    nothing = score_signature(b, sig("e", [dict(type="file", pattern="zzz", weight=0.9, strong=True)]))
    assert not nothing.confirmed and nothing.confidence == 0.0


def sigset_of(*sigs, extras=None):
    ss = SignatureSet()
    for s in sigs:
        ss.signatures[s.id] = s
        ss.extras[s.id] = (extras or {}).get(s.id, {})
    return ss


def test_exclusive_with_keeps_the_better_supported_engine():
    b = EvidenceBundle(files("a", "b", "c"))
    cpp = sig("cpp", [dict(type="file", pattern="a", weight=0.8)], excl=["lua"])
    lua = sig("lua", [dict(type="file", pattern="a", weight=0.5), dict(type="file", pattern="b", weight=0.3),
                      dict(type="file", pattern="c", weight=0.3)], excl=["cpp"])
    res = detect_engines(b, sigset_of(cpp, lua))
    assert res.primary_id == "lua"
    cands = {c.id: c for c in res.candidates}
    assert cands["cpp"].extra["suppressed_by"] == "lua" and cands["cpp"].confirmed is False
    assert res.candidate_ids(confirmed_only=True) == ["lua"]


def test_one_sided_exclusive_declaration_is_honoured():
    b = EvidenceBundle(files("a", "b"))
    weak = sig("weak", [dict(type="file", pattern="a", weight=0.8)])
    strong = sig("strong", [dict(type="file", pattern="a", weight=0.5), dict(type="file", pattern="b", weight=0.5)], excl=["weak"])
    res = detect_engines(b, sigset_of(weak, strong))
    assert res.primary_id == "strong" and {c.id: c.confirmed for c in res.candidates} == {"strong": True, "weak": False}


def test_family_level_entry_yields_to_a_confirmed_variant_but_stands_alone():
    fam = sig("fam", [dict(type="file", pattern="a", weight=0.9)], family="f")
    var = sig("var", [dict(type="file", pattern="b", weight=0.8)], family="f")
    ss = sigset_of(fam, var, extras={"fam": {"role": "family"}})
    only_family = detect_engines(EvidenceBundle(files("a")), ss)
    assert only_family.primary_id == "fam"
    both = detect_engines(EvidenceBundle(files("a", "b")), ss)
    assert both.primary_id == "var" and {c.id: c.confirmed for c in both.candidates} == {"var": True, "fam": False}
    # a variant that is not confirmed does not suppress the family entry
    weak_var = sig("var", [dict(type="file", pattern="b", weight=0.3)], family="f")
    res = detect_engines(EvidenceBundle(files("a", "b")), sigset_of(fam, weak_var, extras={"fam": {"role": "family"}}))
    assert res.primary_id == "fam"


def test_fallback_native_never_wins_over_a_real_engine_but_can_be_primary_alone():
    native = sig("native", [dict(type="file", pattern="n", weight=0.9)], kind="native")
    engine = sig("eng", [dict(type="file", pattern="e", weight=0.8)])
    ss = sigset_of(native, engine, extras={"native": {"role": "fallback"}})
    assert detect_engines(EvidenceBundle(files("n", "e")), ss).primary_id == "eng"
    res = detect_engines(EvidenceBundle(files("n")), ss)
    assert res.primary_id == "native"
    both = detect_engines(EvidenceBundle(files("n", "e")), ss)
    assert {c.id: c.confirmed for c in both.candidates}["native"] is False


def test_kind_rank_prefers_engines_over_libraries():
    lib = sig("lib", [dict(type="file", pattern="l", weight=0.95)], kind="open_source_lib")
    eng = sig("eng", [dict(type="file", pattern="e", weight=0.75)])
    res = detect_engines(EvidenceBundle(files("l", "e")), sigset_of(lib, eng))
    assert res.primary_id == "eng" and res.is_game_engine
    assert detect_engines(EvidenceBundle(files("l")), sigset_of(lib, eng)).is_game_engine is False


def test_no_match_gives_empty_result_and_ties_sort_deterministically():
    res = detect_engines(EvidenceBundle(files("zzz")), sigset_of(sig("a", [dict(type="file", pattern="a", weight=0.9)])))
    assert res.primary is None and res.candidates == [] and res.wrapper is None
    b = EvidenceBundle(files("a"))
    res = detect_engines(b, sigset_of(*[sig(i, [dict(type="file", pattern="a", weight=0.9)]) for i in ("c", "a", "b")]))
    assert [c.id for c in res.candidates] == ["a", "b", "c"]


def test_wrapper_host_and_embedded():
    host = sig("cordova", [dict(type="file", pattern="h", weight=0.9)], kind="web_hybrid")
    emb = sig("unity", [dict(type="file", pattern="u", weight=0.9)])
    ss = sigset_of(host, emb, extras={"cordova": {"wrapper_host": True}, "unity": {"embeddable": True}})
    res = detect_engines(EvidenceBundle(files("h", "u")), ss)
    assert res.wrapper["host"]["id"] == "cordova" and [e["id"] for e in res.wrapper["embedded"]] == ["unity"]
    assert detect_engines(EvidenceBundle(files("h")), ss).wrapper is None
    # a non-embeddable engine is not reported as embedded in a native-style host
    rn = sig("rn", [dict(type="file", pattern="r", weight=0.9)], kind="cross_platform_ui")
    ss2 = sigset_of(rn, emb, extras={"rn": {"wrapper_host": True}})
    assert detect_engines(EvidenceBundle(files("r", "u")), ss2).wrapper is None


def test_version_hint_from_strings():
    b = bin_bundle(strings=[b"Unity 2021.3.16f1 player"])
    s = sig("unity", [dict(type="string", pattern="Unity ", weight=0.9)])
    ss = sigset_of(s, extras={"unity": {"version_regex": r"(20[12][0-9]\.[0-9]+\.[0-9]+[fpab][0-9]+)"}})
    assert detect_engines(b, ss).primary.extra["version_hint"] == "2021.3.16f1"


def test_evidence_lists_every_matched_signal_with_weight():
    b = EvidenceBundle(files("a.pak", "b.dat"))
    res = detect_engines(b, sigset_of(sig("e", [dict(type="file", pattern="*.pak", weight=0.5), dict(type="file", pattern="*.dat", weight=0.3, unverified=True)], thr=0.7)))
    p = res.primary
    assert [e.kind for e in p.evidence] == ["file", "file"] and "weight 0.50" in p.evidence[0].detail
    assert "unverified" in p.evidence[1].detail and [s["pattern"] for s in p.signals_matched] == ["*.pak", "*.dat"]


# --- languages ---------------------------------------------------------------------------------------------------------
def test_languages_from_flags_files_and_engine_hints():
    rec = BinaryRec(rel="T", role="main", has_objc=True, has_cpp=True, has_swift=False)
    b = EvidenceBundle(files("a.lua", "b.lua", "c.js", "d.js", "e.js", ("Data/Managed/x.dll", "unknown", 5)), binaries=[rec])
    unity = sig("unity", [dict(type="file", pattern="a.lua", weight=0.9)])
    det = detect_engines(b, sigset_of(unity))
    unity_ss = sigset_of(EngineSignature(id="unity", name="Unity", language_hints=["csharp"],
                                         signals=[SignalSpec("file", "a.lua", 0.9)], confirm_threshold=0.7))
    det = detect_engines(b, unity_ss)
    langs = {l["lang"]: l for l in infer_languages(b, det, unity_ss, ["lua"])}
    assert {"objc", "cpp", "lua", "javascript", "csharp"} <= set(langs)
    assert "swift" not in langs and langs["objc"]["evidence"][0]["kind"] == "macho"
