"""Shipped knowledge base: schema, uniqueness, rule conflicts and evidence quality."""
from __future__ import annotations

import json
import re

import pytest

from ipa_analyzer.libs import load_kb, load_sysframeworks, validate_entry, validate_kb_doc
from ipa_analyzer.util.paths import resource_dir

DATA = resource_dir("data")


@pytest.fixture(scope="module")
def doc():
    return json.loads((DATA / "libs.json").read_text(encoding="utf-8"))


def test_seed_size_and_schema(doc):
    libs = doc["libs"]
    assert len(libs) >= 150
    assert validate_kb_doc(doc) == []
    assert len({e["id"] for e in libs}) == len(libs)


def test_categories_whitelist(doc):
    cats = set(doc["categories"])
    assert {"ads", "analytics", "crash", "payment", "social", "push", "media", "security", "hotfix", "storage", "engine"} <= cats
    assert all(e["category"] in cats for e in doc["libs"])


def test_every_entry_has_sources_and_real_rules(doc):
    for e in doc["libs"]:
        assert e["sources"], e["id"]
        assert all(s.startswith(("https://", "http://", "observed:")) for s in e["sources"]), e["id"]
        assert e["match"] or e.get("merge_only"), e["id"]
        assert e["purpose_zh"].strip() and e["purpose_en"].strip()


def test_all_regexes_compile_and_no_rule_conflicts(doc):
    for e in doc["libs"]:
        for rx in e["match"].get("symbol_regex", []):
            re.compile(rx)
    assert not [p for p in validate_kb_doc(doc) if "claimed by both" in p]


def test_known_rules_present(doc):
    by_id = {e["id"]: e for e in doc["libs"]}
    assert "GoogleMobileAds" in by_id["admob"]["match"]["framework"]
    assert "AppsFlyerLib" in by_id["appsflyer"]["match"]["framework"]
    assert "FirebaseCore" in by_id["firebase_core"]["match"]["framework"]
    assert "XLua" in by_id["xlua"]["match"]["namespace"]


def test_validate_entry_rejects_bad_input():
    good = {"id": "x1", "name": "X", "category": "other", "purpose_zh": "z", "purpose_en": "e", "match": {"framework": ["X"]}}
    assert validate_entry(good) == []
    assert validate_entry({**good, "id": "Bad Id"})
    assert validate_entry({**good, "category": "nonsense"})
    assert validate_entry({**good, "match": {"symbol_regex": ["(["]}})
    assert validate_entry({**good, "match": {"bogus": ["x"]}})
    assert validate_entry({**good, "match": {}})                       # no rules and not merge_only
    assert validate_entry({**good, "match": {}, "merge_only": True}) == []
    assert validate_entry("nope")


def test_validate_kb_doc_flags_duplicates_and_conflicts():
    a = {"id": "a", "name": "A", "category": "other", "purpose_zh": "z", "purpose_en": "e", "match": {"framework": ["Foo"]}}
    b = {**a, "id": "b"}
    errs = validate_kb_doc({"libs": [a, b, dict(a)]})
    assert any("duplicate id" in e for e in errs) and any("claimed by both" in e for e in errs)


def test_loads_cleanly_and_sysframeworks_table():
    kb = load_kb(user_path=None)
    assert len(kb.entries) >= 150 and kb.warnings == []
    sf = load_sysframeworks()
    rec = sf.lookup("/System/Library/Frameworks/CoreLocation.framework/CoreLocation")
    assert rec and rec.sensitive and rec.capability == "location"
    assert sf.frameworks["AdSupport"].capability == "advertising_id"
    assert sf.frameworks["AppTrackingTransparency"].sensitive and sf.frameworks["HealthKit"].sensitive
    assert not sf.frameworks["UIKit"].sensitive
