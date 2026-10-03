from __future__ import annotations

import pytest

from ipa_analyzer.meta import infoplist as ip


@pytest.mark.parametrize("binary", [True, False])
def test_parse_and_identity(builders, binary):
    info = ip.parse_info_plist(builders.info_plist(binary=binary, MinimumOSVersion="13.0"))
    ident = ip.extract_identity(info)
    assert ident["bundle_id"] == "com.example.foo" and ident["version"] == "1.2.3" and ident["build"] == "45"
    assert ident["executable"] == "Foo" and ident["min_os"] == "13.0" and ident["devices"] == ["iphone", "ipad"]
    assert ident["extra"]["display_name"] == "Foo Display" and ident["extra"]["device_family_ids"] == [1, 2]


def test_missing_keys_do_not_raise():
    ident = ip.extract_identity({})
    assert ident["bundle_id"] is None and ident["devices"] == [] and ident["min_os"] is None
    assert ip.extract_ats({})["allows_arbitrary_loads"] is False
    assert ip.extract_url_schemes({}) == [] and ip.extract_capabilities({}) == [] and ip.extract_sdk({})["name"] is None


def test_wrong_types_are_tolerated():
    info = {"CFBundleIdentifier": ["x"], "CFBundleVersion": 7, "CFBundleShortVersionString": 1.5, "UIDeviceFamily": "bad",
            "CFBundleURLTypes": "nope", "UIBackgroundModes": 3, "NSAppTransportSecurity": [], "UIApplicationSceneManifest": 1}
    ident = ip.extract_identity(info)
    assert ident["bundle_id"] is None and ident["build"] == "7" and ident["version"] == "1.5" and ident["devices"] == []
    assert ip.extract_url_schemes(info) == [] and ip.extract_background_modes(info) == []
    assert ip.extract_ats(info)["extra"]["present"] is False
    assert ip.extract_scene_manifest(info) == {"present": False}


def test_corrupt_plist_returns_none(builders):
    assert ip.parse_info_plist(b"\x00\x01garbage\xff") is None
    assert ip.parse_info_plist(b"bplist00\x00\x01truncated") is None
    import plistlib
    assert ip.parse_info_plist(plistlib.dumps([1, 2])) is None     # root is not a dict


def test_unknown_device_family_and_dict_capabilities():
    assert ip.extract_devices({"UIDeviceFamily": [2, 99, 2]}) == {"devices": ["ipad", "family_99"], "ids": [2, 99]}
    caps = ip.extract_capabilities({"UIRequiredDeviceCapabilities": {"metal": True, "telephony": False}})
    assert caps == ["metal", "!telephony"]
    assert ip.extract_capabilities({"UIRequiredDeviceCapabilities": ["armv7", "metal", "armv7"]}) == ["armv7", "metal"]


def test_url_and_query_schemes_dedup():
    info = {"CFBundleURLTypes": [{"CFBundleURLSchemes": ["foo", "bar"]}, {"CFBundleURLSchemes": ["foo", "wx123"]}, {}],
            "LSApplicationQueriesSchemes": ["weixin", "alipay", "weixin"]}
    assert ip.extract_url_schemes(info) == ["foo", "bar", "wx123"]
    assert ip.extract_query_schemes(info) == ["weixin", "alipay"]


def test_ats_details():
    info = {"NSAppTransportSecurity": {
        "NSAllowsArbitraryLoads": True, "NSAllowsLocalNetworking": True,
        "NSExceptionDomains": {"b.example.com": {"NSExceptionAllowsInsecureHTTPLoads": True},
                               "a.example.com": {"NSIncludesSubdomains": True}}}}
    ats = ip.extract_ats(info)
    assert ats["allows_arbitrary_loads"] is True and ats["exception_domains"] == ["a.example.com", "b.example.com"]
    assert ats["extra"]["insecure_http_domains"] == ["b.example.com"] and ats["extra"]["allows_local_networking"] is True


def test_sdk_and_scene_manifest_and_ns_extension():
    info = {"DTSDKName": "iphoneos17.0", "DTPlatformVersion": "17.0", "DTXcode": "1500", "DTCompiler": "clang", "DTSDKBuild": "21A",
            "UIApplicationSceneManifest": {"UIApplicationSupportsMultipleScenes": True, "UISceneConfigurations": {
                "UIWindowSceneSessionRoleApplication": [{"UISceneDelegateClassName": "App.SceneDelegate"}]}},
            "NSExtension": {"NSExtensionPointIdentifier": "com.apple.widget-extension", "NSExtensionPrincipalClass": "W"}}
    sdk = ip.extract_sdk(info)
    assert sdk["name"] == "iphoneos17.0" and sdk["xcode"] == "1500" and sdk["extra"] == {"sdk_build": "21A"}
    sc = ip.extract_scene_manifest(info)
    assert sc["supports_multiple_scenes"] is True and sc["delegate_classes"] == ["App.SceneDelegate"]
    assert ip.extract_identity(info)["extra"]["ns_extension"]["point"] == "com.apple.widget-extension"


def test_iso_utc():
    import datetime as dt
    assert ip.iso_utc(dt.datetime(2024, 1, 2, 3, 4, 5, 999)) == "2024-01-02T03:04:05Z"
    assert ip.iso_utc(dt.datetime(2024, 1, 2, 5, 0, tzinfo=dt.timezone(dt.timedelta(hours=2)))) == "2024-01-02T03:00:00Z"
    assert ip.iso_utc("2020-01-01") == "2020-01-01" and ip.iso_utc(5) == "5" and ip.iso_utc(None) is None


# --- project name priority ---------------------------------------------------------------------
def _names(**kw):
    base = dict(info={"CFBundleDisplayName": "Disp", "CFBundleName": "Name"}, localized={},
                itunes_name="Item", itunes_display_name="ItemDisp", executable="Exec", input_name="file")
    base.update(kw)
    return ip.build_name_candidates(base["info"], base["localized"], base["itunes_name"], base["itunes_display_name"],
                                    base["executable"], base["input_name"])


def test_name_order_without_localization():
    c = _names()
    assert [x["value"] for x in c] == ["Disp", "Name", "Item", "ItemDisp", "Exec", "file"]
    assert [x["source"] for x in c] == ["Info.plist:CFBundleDisplayName", "Info.plist:CFBundleName",
                                         "iTunesMetadata.plist:itemName", "iTunesMetadata.plist:bundleDisplayName",
                                         "CFBundleExecutable", "input_filename"]
    assert ip.select_name(c) == "Disp"


def test_localized_zh_hans_beats_zh_hant_beats_en_beats_plain():
    loc = {"en": {"CFBundleDisplayName": "EN"}, "zh-Hant": {"CFBundleDisplayName": "繁"},
           "zh-Hans": {"CFBundleDisplayName": "简"}, "ja": {"CFBundleDisplayName": "日"}}
    c = _names(localized=loc)
    assert [x["value"] for x in c][:5] == ["简", "繁", "EN", "Disp", "Name"]
    assert c[0]["lang"] == "zh-Hans" and c[1]["lang"] == "zh-Hant" and c[2]["lang"] == "en"
    # other languages never outrank the plain Info.plist value
    assert [x["value"] for x in c].index("日") > [x["value"] for x in c].index("ItemDisp")


def test_fallback_chain_each_level():
    assert ip.select_name(_names(info={"CFBundleName": "Name"})) == "Name"
    assert ip.select_name(_names(info={})) == "Item"
    assert ip.select_name(_names(info={}, itunes_name=None, itunes_display_name=None)) == "Exec"
    assert ip.select_name(_names(info=None, itunes_name=None, itunes_display_name=None, executable=None)) == "file"
    assert ip.select_name(_names(info=None, itunes_name=None, itunes_display_name=None, executable=None, input_name=None)) is None


def test_unresolved_build_variable_and_blank_are_skipped():
    c = _names(info={"CFBundleDisplayName": "$(PRODUCT_NAME)", "CFBundleName": "  "})
    assert [x["value"] for x in c][:1] == ["Item"]


def test_localized_bundle_name_is_low_priority():
    c = _names(info={}, itunes_name=None, itunes_display_name=None, localized={"zh-Hans": {"CFBundleName": "本地名"}})
    assert [x["value"] for x in c] == ["本地名", "Exec", "file"]
