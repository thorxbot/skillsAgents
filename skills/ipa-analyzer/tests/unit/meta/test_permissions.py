from __future__ import annotations

import json

from ipa_analyzer.meta import permissions as pm
from ipa_analyzer.util.paths import resource_dir


def test_database_file_is_well_formed():
    raw = json.loads((resource_dir("data") / "permissions.json").read_text(encoding="utf-8"))
    entries = raw["permissions"]
    assert len(entries) >= 25
    for key, v in entries.items():
        assert key.endswith("UsageDescription"), key
        assert v["level"] in pm.LEVELS and v["meaning_zh"] and v["meaning_en"], key
    assert entries["NSUserTrackingUsageDescription"]["level"] == "high"
    assert entries["NSCameraUsageDescription"]["level"] == "high"
    assert entries["NSPhotoLibraryAddUsageDescription"]["level"] == "low"


def test_collect_known_unknown_localized_and_order():
    info = {"NSCameraUsageDescription": "Scan codes", "NSPhotoLibraryAddUsageDescription": "Save",
            "NSUserTrackingUsageDescription": "ATT", "FancyNewUsageDescription": "x", "NSLocationWhenInUseUsageDescription": 5,
            "CFBundleName": "ignored", "NSCalendarsUsageDescription": {"weird": 1}}
    loc = {"zh-Hans": {"NSCameraUsageDescription": " 扫码 "}, "en": {"NSCameraUsageDescription": "Scan"}}
    perms = pm.collect_permissions(info, loc)
    keys = [p["key"] for p in perms]
    assert keys == ["NSCameraUsageDescription", "NSUserTrackingUsageDescription", "FancyNewUsageDescription",
                    "NSCalendarsUsageDescription", "NSLocationWhenInUseUsageDescription", "NSPhotoLibraryAddUsageDescription"]
    cam = perms[0]
    assert cam["level"] == "high" and cam["localized"] == {"en": "Scan", "zh-Hans": "扫码"} and cam["known"] is True
    assert cam["meaning_zh"] and cam["meaning_en"] and cam["description"] == "Scan codes"
    fancy = perms[2]
    assert fancy["known"] is False and fancy["level"] == "medium" and fancy["meaning_zh"] == ""
    assert next(p for p in perms if p["key"] == "NSCalendarsUsageDescription")["description"] == ""
    s = pm.summarize_permissions(perms)
    assert s["count"] == 6 and s["by_level"]["high"] == 2 and s["unknown_keys"] == ["FancyNewUsageDescription"]


def test_missing_database_is_tolerated(tmp_path):
    assert pm.load_permission_db(tmp_path / "nope.json") == {}
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert pm.load_permission_db(bad) == {}
    perms = pm.collect_permissions({"NSCameraUsageDescription": "x"}, {}, db={})
    assert perms[0]["known"] is False


def test_long_text_is_clipped():
    perms = pm.collect_permissions({"NSCameraUsageDescription": "x" * 5000}, {})
    assert len(perms[0]["description"]) < 1100
