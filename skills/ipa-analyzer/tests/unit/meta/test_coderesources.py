from __future__ import annotations

import hashlib
import plistlib
import time
import zipfile

import pytest

from ipa_analyzer.ingest.minimal_zip import ZipSource
from ipa_analyzer.meta import coderesources as cr

APPROOT = "Payload/Foo.app/"
FILES = {"Info.plist": b"plist-bytes", "assets/a.bin": b"A" * 5000, "assets/b.bin": b"B" * 100,
         "en.lproj/Localizable.strings": b"x"}


def _src(tmp_path, files, name="t.ipa"):
    p = tmp_path / name
    with zipfile.ZipFile(p, "w") as zf:
        for n, d in files.items():
            zf.writestr(APPROOT + n, d)
    return ZipSource(p)


def _verify(src, seal_bytes, **kw):
    plist = cr.parse_code_resources(seal_bytes)
    assert plist is not None
    return cr.verify_code_resources(src, APPROOT, plist, src.namelist(), **kw)


def _pack(files, seal_bytes, extra=None):
    out = dict(files)
    out["_CodeSignature/CodeResources"] = seal_bytes
    out.update(extra or {})
    return out


def test_clean_package(builders, tmp_path):
    s = builders.seal(FILES)
    res = _verify(_src(tmp_path, _pack(FILES, s, {"Foo": b"\xcf\xfa"})), s, executable="Foo")
    assert (res["checked"], res["missing"], res["modified"], res["extra"]) == (4, 0, 0, 0)
    assert res["examples"] == [] and res["details"]["table"] == "files2" and res["details"]["truncated"] is False


def test_modified_missing_extra(builders, tmp_path):
    s = builders.seal(FILES)
    actual = dict(FILES)
    actual["assets/a.bin"] = b"TAMPERED"
    del actual["assets/b.bin"]
    res = _verify(_src(tmp_path, _pack(actual, s, {"injected.dylib": b"evil", "Foo": b"x"})), s, executable="Foo")
    assert (res["modified"], res["missing"], res["extra"]) == (1, 1, 1)
    kinds = [(e["kind"], e["path"]) for e in res["examples"]]
    assert kinds == [("modified", "assets/a.bin"), ("missing", "assets/b.bin"), ("extra", "injected.dylib")]


def test_examples_limited_to_ten(builders, tmp_path):
    files = {"f%02d" % i: b"data%d" % i for i in range(30)}
    s = builders.seal(files)
    tampered = {k: v + b"!" for k, v in files.items()}
    res = _verify(_src(tmp_path, _pack(tampered, s)), s)
    assert res["modified"] == 30 and len(res["examples"]) == cr.MAX_EXAMPLES


def test_optional_missing_is_fine(builders, tmp_path):
    s = builders.seal(FILES, optional={"en.lproj/Localizable.strings"})
    actual = {k: v for k, v in FILES.items() if k != "en.lproj/Localizable.strings"}
    res = _verify(_src(tmp_path, _pack(actual, s)), s)
    assert res["missing"] == 0 and res["checked"] == 3


def test_sha1_only_legacy_files_table(builders, tmp_path):
    s = builders.seal(FILES, sha1_only=True)
    res = _verify(_src(tmp_path, _pack(FILES, s)), s)
    assert res["details"]["table"] == "files" and res["checked"] == 4 and res["modified"] == 0
    bad = dict(FILES, **{"assets/b.bin": b"C" * 100})
    assert _verify(_src(tmp_path, _pack(bad, s), "t2.ipa"), s)["modified"] == 1


def test_algorithm_chosen_by_digest_length(tmp_path):
    data = b"hello"
    seal = plistlib.dumps({"files2": {"a": {"hash": hashlib.sha256(data).digest()},
                                      "b": {"hash2": hashlib.sha1(data).digest()},
                                      "c": {"hash2": b"\x00" * 7}}, "rules2": {"^.*": True}})
    src = _src(tmp_path, _pack({"a": data, "b": data, "c": data}, seal))
    res = _verify(src, seal)
    assert res["checked"] == 2 and res["modified"] == 0 and res["details"]["unsupported_digest"] == 1


def test_nested_bundles_are_skipped_not_missing(builders, tmp_path):
    files = dict(FILES)
    files["Frameworks/Lib.framework/Lib"] = b"macho"
    files["Frameworks/Lib.framework/Info.plist"] = b"p"
    files["Frameworks/Lib.framework/_CodeSignature/CodeResources"] = b"nested seal"
    s = builders.seal(FILES, nested=["Frameworks/Lib.framework"])
    res = _verify(_src(tmp_path, _pack(files, s)), s)
    assert (res["missing"], res["modified"], res["extra"]) == (0, 0, 0)
    assert res["details"]["skipped"] == 1 and res["details"]["nested_bundles"] == 1
    # a nested bundle that disappeared IS missing
    res = _verify(_src(tmp_path, _pack(FILES, s), "t3.ipa"), s)
    assert res["missing"] == 1


def test_rules_omit_and_ignored_paths(builders, tmp_path):
    s = builders.seal(FILES)
    extra = {"PkgInfo": b"APPL", "SC_Info/Foo.sinf": b"s", ".DS_Store": b"junk", "Foo": b"exe",
             "Base.lproj/Main.storyboardc/x": b"unsealed"}
    res = _verify(_src(tmp_path, _pack(FILES, s, extra)), s, executable="Foo")
    assert res["extra"] == 1 and res["examples"][0]["path"] == "Base.lproj/Main.storyboardc/x"


def test_budget_truncates_and_is_reported(builders, tmp_path):
    s = builders.seal(FILES)
    res = _verify(_src(tmp_path, _pack(FILES, s)), s, max_bytes=200)
    assert res["details"]["truncated"] is True and res["details"]["unchecked_budget"] >= 1
    assert res["checked"] < 4
    res = _verify(_src(tmp_path, _pack(FILES, s), "t4.ipa"), s, max_seconds=-1.0)
    assert res["checked"] == 0 and res["details"]["unchecked_budget"] == 4


def test_unicode_normalization_difference(builders, tmp_path):
    nfc, nfd = "café.txt", "café.txt"
    s = builders.seal({nfc: b"data"})
    res = _verify(_src(tmp_path, _pack({nfd: b"data"}, s)), s)
    assert (res["checked"], res["missing"], res["modified"], res["extra"]) == (1, 0, 0, 0)


def test_corrupt_inputs():
    assert cr.parse_code_resources(b"garbage") is None
    assert cr.parse_code_resources(plistlib.dumps({"unrelated": 1})) is None
    assert cr.parse_code_resources(plistlib.dumps([1])) is None


def test_invalid_regex_rules_are_skipped():
    rules = cr.compile_rules({"([": True, "^ok": {"weight": 2.0}, "^omit": {"omit": True}, "^no$": False})
    assert len(rules) == 3
    assert cr.rule_expects(rules, "ok/x") is True and cr.rule_expects(rules, "omit") is False
    assert cr.rule_expects(rules, "no") is False and cr.rule_expects(rules, "other") is False


# --- ReDoS hardening (rules2 regexes come from the untrusted IPA) ------------------------------
REAL_APPLE_RULES = [
    r"^(Frameworks|SharedFrameworks|PlugIns|Plug-ins|XPCServices|Helpers|MacOS|Library/(Automator|Spotlight|LoginItems))/",
    r"^.*", r"^.*\.dSYM($|/)", r"^(.*/)?\.DS_Store$", r"^[^/]+$", r"^embedded\.provisionprofile$",
    r"^Resources/.*\.lproj/", r"^Resources/.*\.lproj/locversion.plist", r"^(.*/)?Info\.plist$", r"^Base\.lproj/",
]


@pytest.mark.parametrize("pat", REAL_APPLE_RULES)
def test_real_world_rules_are_considered_safe(pat):
    assert cr.rule_risk(pat) is None


@pytest.mark.parametrize("pat", [r"^(a+)+$", r"^(a*)*$", r"^(a|aa)+$", r"^(?:a+)+$", r"(.+)*", r"^(\w+\s?)*$",
                                 r"^([a-z]+)+$", r"(?P<x>a+)+", r"^(a+){1,}$", r"^(a{1,100})+$", r".*.*.*x",
                                 "^" + "a" * 300])
def test_risky_rules_are_rejected(pat):
    assert cr.rule_risk(pat) is not None
    rejected = []
    assert cr.compile_rules({pat: True, "^ok$": True}, rejected) != [] and rejected == [pat]


def test_adversarial_rule_finishes_quickly_and_is_reported(builders, tmp_path):
    evil = "a" * 40
    files = {"Info.plist": b"plist-bytes", evil + "!": b"x"}
    s = builders.seal({"Info.plist": b"plist-bytes"}, extra_rules={"^(a+)+$": True})
    started = time.monotonic()
    res = _verify(_src(tmp_path, _pack(files, s)), s)
    assert time.monotonic() - started < 1.0
    det = res["details"]
    assert det["unevaluated_rules"] == 1 and det["rules_incomplete"] is True
    assert any("not evaluated" in w for w in res["warnings"])
    assert res["extra"] == 1                       # the safe ``^.*`` rule still flags the unsealed file


def test_rule_input_is_truncated():
    seen = []

    class Rx:
        def search(self, text):
            seen.append(len(text))
            return True

    assert cr.rule_expects([(Rx(), 1.0, False)], "x" * 5000) is True
    assert seen == [cr.MAX_RULE_INPUT]


def test_rule_time_budget_stops_evaluation(builders, tmp_path):
    files = {"Info.plist": b"p", "e1": b"1", "e2": b"2"}
    s = builders.seal({"Info.plist": b"p"})
    res = _verify(_src(tmp_path, _pack(files, s)), s, max_rule_seconds=-1.0)
    assert res["details"]["rules_timed_out"] is True and res["details"]["rules_incomplete"] is True
    assert res["extra"] == 0 and any("stopped" in w for w in res["warnings"])
