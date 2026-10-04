from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from ipa_analyzer.engines.api import ENGINE_KINDS, SIGNAL_TYPES
from ipa_analyzer.engines.signatures import (UNVERIFIED_WEIGHT_CAP, SignatureSet, load_dir, load_signatures,
                                             parse_pattern, split_count, validate_signature_dict)
from ipa_analyzer.util.paths import resource_dir

ENGINE_DIR = Path(resource_dir("data")) / "engines"
ENGINE_FILES = sorted(ENGINE_DIR.glob("*.json"))


def good(**over):
    d = {"id": "fake_engine", "name": "Fake", "kind": "game_engine", "confirm_threshold": 0.7,
         "signals": [{"type": "file", "pattern": "fake.dat", "weight": 0.9, "strong": True}], "sources": ["unit test"]}
    d.update(over)
    return d


# --- built-in data -----------------------------------------------------------------------------------------------
def test_all_builtin_files_are_valid_and_ids_match_file_names():
    assert len(ENGINE_FILES) >= 40
    seen = set()
    for path in ENGINE_FILES:
        d = json.loads(path.read_text(encoding="utf-8"))
        assert validate_signature_dict(d) == [], path.name
        assert d["id"] == path.stem and d["id"] not in seen
        seen.add(d["id"])
        assert d["sources"] and all(s.strip() for s in d["sources"])
        assert d["kind"] in ENGINE_KINDS
        for s in d["signals"]:
            assert s["type"] in SIGNAL_TYPES
            if s.get("unverified"):
                assert s["weight"] <= UNVERIFIED_WEIGHT_CAP and not s.get("strong"), (path.name, s)
    # every exclusive_with target exists
    for path in ENGINE_FILES:
        d = json.loads(path.read_text(encoding="utf-8"))
        assert set(d.get("exclusive_with", [])) <= seen, path.name


def test_builtin_loader_reports_no_warnings():
    s = load_signatures(user_dirs=[])
    assert s.warnings == [] and len(s.signatures) == len(ENGINE_FILES)
    assert {"unity", "unreal", "godot", "defold", "flutter", "react_native", "cocos2dx_cpp", "cocos2dx_lua",
            "cocos2dx_js", "cocos_creator_2x", "cocos_creator_3x", "cocos2d_iphone", "neox_family", "supercell_sc",
            "native_swiftui", "native_uikit", "native_objc"} <= set(s.signatures)


def test_unverified_signals_are_capped_and_never_strong(tmp_path):
    d = good(signals=[{"type": "file", "pattern": "a.bin", "weight": 1.0, "strong": True, "unverified": True}])
    (tmp_path / "x.json").write_text(json.dumps(d), encoding="utf-8")
    s = SignatureSet()
    assert load_dir(tmp_path, s) == 1
    spec = s.signatures["fake_engine"].signals[0]
    assert spec.weight == UNVERIFIED_WEIGHT_CAP and spec.strong is False


def test_strong_signal_weight_is_lifted(tmp_path):
    d = good(signals=[{"type": "file", "pattern": "a.bin", "weight": 0.2, "strong": True}])
    s = SignatureSet()
    assert s.add(d, "t.json")
    assert s.signatures["fake_engine"].signals[0].weight >= 0.9


# --- validation ----------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("mutate,fragment", [
    (lambda d: d.pop("sources"), "sources"),
    (lambda d: d.update(sources=[]), "sources"),
    (lambda d: d.update(id="Bad Id"), "id"),
    (lambda d: d.update(kind="spaceship"), "kind"),
    (lambda d: d.update(signals=[]), "signals"),
    (lambda d: d.update(signals=[{"type": "nope", "pattern": "x", "weight": 1}]), "unknown type"),
    (lambda d: d.update(signals=[{"type": "string", "pattern": "re:(unclosed", "weight": 0.5}]), "regex"),
    (lambda d: d.update(signals=[{"type": "file", "pattern": "x", "weight": 3}]), "weight"),
    (lambda d: d.update(confirm_threshold=0), "confirm_threshold"),
    (lambda d: d.update(exclusive_with="x"), "exclusive_with"),
    (lambda d: d.update(signals=[{"type": "binary_section", "pattern": "nocomma", "weight": 0.5}]), "binary_section"),
])
def test_validation_catches_problems(mutate, fragment):
    d = good()
    mutate(d)
    errs = validate_signature_dict(d)
    assert errs and any(fragment in e for e in errs), errs


def test_validation_rejects_non_objects():
    assert validate_signature_dict([1]) and validate_signature_dict("x")


# --- grammar -------------------------------------------------------------------------------------------------------
def test_pattern_grammar():
    assert split_count("magic:ccz#50") == ("magic:ccz", 50) and split_count("a#b") == ("a#b", 1)
    pp = parse_pattern("file", "magic:CCZ#5")
    assert (pp.kind, pp.value, pp.min_count) == ("magic", "ccz", 5)
    assert parse_pattern("file", "head:NXPK").kind == "head"
    assert parse_pattern("file", "/Data/Boot.config").value == "/data/boot.config"
    assert parse_pattern("dir", "/Frameworks/X.framework/").value == "/frameworks/x.framework"
    assert parse_pattern("symbol", "luaL_newstate").kind == "exact"
    assert parse_pattern("symbol", "_ZN7cocos2d*").kind == "prefix"
    assert parse_pattern("symbol", "*needle*").kind == "contains"
    assert parse_pattern("symbol", "re:^foo").regex.search(b"foo")
    assert parse_pattern("plist_key", "A=b").kind == "keyvalue"
    assert parse_pattern("dylib", "Metal.Framework").value == "metal.framework"
    with pytest.raises(ValueError):
        parse_pattern("file", "")
    with pytest.raises(ValueError):
        parse_pattern("file", "head:")
    with pytest.raises(ValueError):
        parse_pattern("string", "re:(")
    with pytest.raises(ValueError):
        parse_pattern("zzz", "x")


# --- user directories ------------------------------------------------------------------------------------------------
def test_user_dirs_register_override_and_warn(tmp_path):
    user = tmp_path / "engines.user.d"
    user.mkdir()
    (user / "fake.json").write_text(json.dumps(good()), encoding="utf-8")
    override = good(id="unity", name="My Unity", confirm_threshold=0.5)
    (user / "override.json").write_text(json.dumps([override]), encoding="utf-8")
    (user / "broken.json").write_text("{not json", encoding="utf-8")
    (user / "invalid.json").write_text(json.dumps({"id": "x"}), encoding="utf-8")
    (user / "notes.txt").write_text("ignored", encoding="utf-8")
    s = load_signatures(user_dirs=[user])
    assert "fake_engine" in s.signatures and s.signatures["unity"].name == "My Unity"
    assert sorted(s.user_ids) == ["fake_engine", "unity"]
    assert len(s.warnings) == 2 and any("broken.json" in w for w in s.warnings)
    assert "cocos2dx_lua" in s.signatures        # built-ins stay


def test_default_user_dir_follows_home_env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "engines.user.d").mkdir(parents=True)
    (home / "engines.user.d" / "fake.json").write_text(json.dumps(good()), encoding="utf-8")
    monkeypatch.setenv("IPA_ANALYZER_HOME", str(home))
    assert "fake_engine" in load_signatures().signatures
    extra = tmp_path / "extra"
    extra.mkdir()
    (extra / "o.json").write_text(json.dumps(good(id="other_engine")), encoding="utf-8")
    s = load_signatures(engines_user_dir=extra)
    assert {"fake_engine", "other_engine"} <= set(s.signatures)


def test_missing_directories_are_fine(tmp_path):
    s = load_signatures(data_dir=tmp_path / "nope", user_dirs=[tmp_path / "nope2"])
    assert s.signatures == {} and s.warnings == []
