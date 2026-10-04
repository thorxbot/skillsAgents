"""Redaction: e-mail, UDID, home-directory user names, Apple-ID-like keys."""
from __future__ import annotations

import json

import pytest

from fixtures.sample_report import EMAIL, UDID_NEW, UDID_OLD, build_report
from ipa_analyzer.report.redact import RedactionStats, redact_obj, redact_report, redact_text


@pytest.mark.parametrize("raw,must_not_contain", [
    ("mail bob@example.com now", "bob@example.com"),
    ("dev.support+x@sub.example.co.uk", "dev.support"),
    ("udid " + UDID_OLD + " end", UDID_OLD),
    ("udid " + UDID_NEW, UDID_NEW),
    ("/Users/alice/Library/x", "alice"),
    ("/Users/alice", "alice"),
    ("C:\\Users\\carol\\Desktop\\x.ipa", "carol"),
    ("c:/users/Carol/Desktop", "Carol"),
    ("/home/dave/work", "dave"),
    ("C:\\Users\\John Smith\\Desktop", "Smith"),               # user names with spaces: up to the separator
    ("D:\\Users\\Mary Ann Lee", "Lee"),
    ("\\\\fileserver\\share\\Users\\bob\\x", "bob"),            # UNC
    ("//fileserver/share/Users/bob/x", "bob"),
    ("\\\\?\\UNC\\srv\\sh\\Users\\Bob Q\\x", "Bob"),
    ("\\\\?\\C:\\Users\\Bob\\x", "Bob"),
    ("file:///Users/erin/x.ipa", "erin"),
    ("opened (/Users/frank/a.ipa)", "frank"),
    ("device: " + UDID_OLD, UDID_OLD),                                  # device context
    ("UDID=" + UDID_OLD, UDID_OLD),
])
def test_redact_text_removes_personal_data(raw, must_not_contain):
    stats = RedactionStats()
    out = redact_text(raw, stats)
    assert must_not_contain not in out
    assert stats.total >= 1
    assert "<" not in out.replace("&lt;", "")           # placeholders are Markdown / HTML safe


@pytest.mark.parametrize("raw", [
    "Icon@2x.png", "icon@3x.png", "/Users/Shared/Library", "/Users/[user]/x", "no personal data here",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",     # a sha256 is not a UDID
    "123e4567-e89b-12d3-a456-426614174000",                                  # a UUID is not a UDID
    "/Applications/Cydia.app", "Payload/DemoGame.app/Info.plist",
    # App-internal paths and URLs that merely contain home/ or Users/ must not be rewritten
    "Payload/X.app/res/home/btn.png", "assets/home/index.json", "https://example.com/home/page",
    "Payload/X.app/Users/list.json", "see https://example.com/Users/profile now", "res/home/a/b/c.png",
    "ftp://host:21/home/pub", "C:/data/home/x", "x:/Users/Shared/y",
    # resource names that look like addresses
    "btn@ipad.png", "Payload/X.app/icon@iphone.jpg", "bg@tablet.webp",
    # digests are not UDIDs
    "cdhash 199082ca199082ca199082ca199082ca199082ca", "sha1: 0123456789abcdef0123456789abcdef01234567",
    "git 0123456789abcdef0123456789abcdef01234567 fixed it",
])
def test_redact_text_leaves_harmless_strings(raw):
    stats = RedactionStats()
    assert redact_text(raw, stats) == raw
    assert stats.total == 0


def test_user_name_is_replaced_but_path_kept():
    assert redact_text("/Users/alice/Downloads/a.ipa") == "/Users/[user]/Downloads/a.ipa"
    assert redact_text("C:\\Users\\carol\\x") == "C:\\Users\\[user]\\x"


def test_sensitive_keys_blank_values():
    stats = RedactionStats()
    out = redact_obj({"apple-id": "a@b.co", "userName": "Alice", "DSPersonID": 12345, "purchaseDate": "2020", "ok": "keep",
                      "nested": {"receipt": {"x": 1}}, "empty": {"apple-id": ""}, "done": {"apple-id": "<redacted>"}}, stats)
    assert out["apple-id"] == out["userName"] == out["DSPersonID"] == out["purchaseDate"] == "[REDACTED]"
    assert out["ok"] == "keep" and out["nested"]["receipt"] == "[REDACTED]"
    assert out["empty"]["apple-id"] == "" and out["done"]["apple-id"] == "<redacted>"
    assert {"key:appleid", "key:username", "key:dspersonid", "key:purchasedate", "key:receipt"} <= set(stats.fields)


def test_redact_report_default_removes_everything_and_records_stats():
    rd = build_report("full_success").to_dict()
    rd["warnings"].append("contact " + EMAIL)
    red, info = redact_report(rd, enabled=True, producer_fields=["itunes.apple-id"])
    text = json.dumps(red, ensure_ascii=False)
    assert "alice" not in text and EMAIL not in text
    assert info["applied"] is True and "home_path" in info["fields"] and "email" in info["fields"]
    assert "itunes.apple-id" in info["fields"] and info["counts"]["email"] >= 1
    assert red["redaction"] == info
    # the input is not mutated
    assert "alice" in json.dumps(rd)


def test_redact_report_cocos_udids():
    red, info = redact_report(build_report("cocos_lua").to_dict())
    text = json.dumps(red)
    assert UDID_OLD not in text and UDID_NEW not in text and "dave" not in text
    assert info["counts"]["udid"] >= 2


def test_redact_report_disabled_keeps_values():
    rd = build_report("full_success").to_dict()
    red, info = redact_report(rd, enabled=False, producer_fields=["x"])
    assert "alice" in json.dumps(red) and info == {"applied": False, "fields": ["x"], "counts": {}}


def test_extras_are_redacted_in_place_and_counted():
    extras = {"details/a.json": ["ok", "mail me@example.org"]}
    _, info = redact_report({"a": "b"}, extras=extras)
    assert extras["details/a.json"][1] == "mail [REDACTED-EMAIL]" and info["counts"]["email"] == 1


def test_digest_keys_are_never_udids_and_not_reported():
    h40 = "199082ca199082ca199082ca199082ca199082ca"
    rd = {"macho": {"binaries": [{"slices": [{"signature": {"cdhash": h40, "cdhashes": {"sha1": h40, "sha256": "ab" * 32},
                                                            "digest_list": [h40]}}]}]},
          "git": {"commit": h40}, "plain": "x"}
    red, info = redact_report(rd)
    assert red["macho"] == rd["macho"] and red["git"] == rd["git"]
    assert "udid" not in info["fields"] and info["counts"] == {}


def test_device_keys_redact_bare_legacy_udids():
    rd = {"provision": {"ProvisionedDevices": [UDID_OLD], "udid": UDID_OLD, "devices": [{"id": UDID_OLD}]},
          "note": "paired device " + UDID_OLD}
    red, info = redact_report(rd)
    text = json.dumps(red)
    assert UDID_OLD not in text and info["counts"]["udid"] == 4 and info["fields"] == ["udid"]


def test_device_key_beats_hash_word_in_device_hash_keys():
    red, _ = redact_report({"device_hash_prefixes": [UDID_OLD]})
    assert UDID_OLD not in json.dumps(red)


def test_hash_context_in_text_wins_over_earlier_device_word():
    raw = "device app cdhash " + UDID_OLD
    assert redact_text(raw) == raw


def test_resource_paths_survive_in_a_whole_report():
    rd = build_report("full_success").to_dict()
    rd["resources"]["top_files"] = [{"path": "Payload/DemoGame.app/res/home/btn.png", "size": 1, "category": "image"}]
    rd["warnings"].append("fetch https://example.com/home/page failed for /Users/alice/x.ipa")
    red, _ = redact_report(rd)
    assert red["resources"]["top_files"][0]["path"] == "Payload/DemoGame.app/res/home/btn.png"
    assert "https://example.com/home/page" in red["warnings"][-1] and "alice" not in red["warnings"][-1]
