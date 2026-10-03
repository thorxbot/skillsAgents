from __future__ import annotations

import json

from ipa_analyzer.util.paths import resource_dir

FINDING_IDS = ["meta.identity", "meta.distribution", "meta.permissions", "meta.fairplay_container", "meta.signature_integrity"]


def _load(lang):
    return json.loads((resource_dir("data") / "i18n" / lang / "meta.json").read_text(encoding="utf-8"))


def test_zh_and_en_have_identical_keys_and_prefixes():
    zh, en = _load("zh"), _load("en")
    assert set(zh) == set(en)
    for key, val in zh.items():
        if key in FINDING_IDS:
            assert set(val) == {"title", "summary", "remediation"} and all(val.values()), key
            assert set(en[key]) == set(val) and all(en[key].values())
        else:
            assert key.startswith("meta."), key
            assert isinstance(val, str) and val
    assert all(fid in zh for fid in FINDING_IDS)


def test_every_distribution_type_and_level_has_a_label():
    zh = _load("zh")
    for t in ("appstore", "adhoc", "enterprise", "development", "unsigned_or_repackaged", "unknown"):
        assert "meta.distribution.type." + t in zh
    for lv in ("high", "medium", "low"):
        assert "meta.permission.level." + lv in zh
    for src in ("InfoPlist.strings:CFBundleDisplayName", "Info.plist:CFBundleDisplayName", "Info.plist:CFBundleName",
                "iTunesMetadata.plist:itemName", "CFBundleExecutable", "input_filename"):
        assert "meta.name.source." + src in zh
