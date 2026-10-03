from __future__ import annotations

import json
import plistlib

from ipa_analyzer.meta.itunes_meta import REDACTED, is_sensitive_key, parse_itunes_metadata


def _load(builders, **over):
    return plistlib.loads(builders.itunes_plist(**over))


def test_redacted_by_default(builders):
    out, keys = parse_itunes_metadata(_load(builders), True)
    text = json.dumps(out, ensure_ascii=False)
    for secret in (builders.EMAIL, builders.BUYER, "777000111", "2021-01-01"):
        assert secret not in text
    assert out["appleId"] == REDACTED and out["userName"] == REDACTED and out["purchaseDate"] == REDACTED
    assert out["com.apple.iTunesStore.downloadInfo"] == REDACTED
    assert out["item_id"] == 123456789 and out["item_name"] == "Foo Store Name" and out["artist_name"] == "Foo Studio"
    assert out["genre"] == "Games" and out["genre_id"] == 6014 and out["software_version_bundle_id"] == "com.example.foo"
    assert out["bundle_version_external_id"] == 999 and out["release_date"] == "2020-05-06T07:08:09Z"
    assert "unknownKey" in out["extra"]["other_keys"] and "keep-out-of-output" not in text
    assert "appleId" in keys and "com.apple.iTunesStore.downloadInfo.accountInfo.AppleID" in keys
    assert all(builders.EMAIL not in k for k in keys)      # names only, no values


def test_no_redact_keeps_purchaser_fields(builders):
    out, keys = parse_itunes_metadata(_load(builders), False)
    assert out["appleId"] == builders.EMAIL and out["userName"] == builders.BUYER
    assert out["com.apple.iTunesStore.downloadInfo"]["accountInfo"]["DSPersonID"] == 777000111
    assert keys == []
    assert "keep-out-of-output" not in json.dumps(out)       # unknown keys are never copied


def test_sensitive_key_variants():
    for k in ("apple-id", "AppleID", "appleId", "Apple_ID", "userName", "DSPersonID", "purchaseDate",
              "com.apple.iTunesStore.downloadInfo", "accountInfo", "storeCohort"):
        assert is_sensitive_key(k), k
    for k in ("itemId", "artistName", "genre", "vendorId"):
        assert not is_sensitive_key(k), k


def test_nested_sensitive_keys_in_allowlisted_values_are_dropped(builders):
    out, _ = parse_itunes_metadata({"genres": [{"genre": "Games", "AppleID": builders.EMAIL}], "itemId": 1}, True)
    assert out["genres"] == [{"genre": "Games"}] and builders.EMAIL not in json.dumps(out)


def test_empty_and_odd_inputs():
    out, keys = parse_itunes_metadata({}, True)
    assert out == {"extra": {"other_keys": []}} and keys == []
    out, _ = parse_itunes_metadata({"itemId": True, "itemName": ["x"], "releaseDate": 5, "gameCenterEnabled": "yes"}, True)
    assert "item_id" not in out and "item_name" not in out and "game_center_enabled" not in out
