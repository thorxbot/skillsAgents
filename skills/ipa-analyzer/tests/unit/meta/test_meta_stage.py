from __future__ import annotations

import json
import plistlib

import pytest

from ipa_analyzer.analyzers import meta as meta_mod
from ipa_analyzer.models import Status, dumps_json


def _dump(res):
    """Everything the stage emits, as one JSON string."""
    return dumps_json({"data": res.data, "findings": [f.to_dict() for f in res.findings],
                       "warnings": res.warnings})


def _finding(res, fid):
    (f,) = [f for f in res.findings if f.id == fid]
    return f


def _store_app(b, **over):
    exe = b"\xcf\xfa\xed\xfe-main"
    files = {
        "Info.plist": b.info_plist(
            binary=True,
            NSCameraUsageDescription="Scan codes", NSUserTrackingUsageDescription="Ads",
            NSPhotoLibraryAddUsageDescription="Save", CFBundleURLTypes=[{"CFBundleURLSchemes": ["foo", "wx123"]}],
            LSApplicationQueriesSchemes=["weixin"], UIBackgroundModes=["audio", "fetch"],
            UIRequiredDeviceCapabilities=["arm64", "metal"], DTSDKName="iphoneos17.0", DTXcode="1500",
            NSAppTransportSecurity={"NSAllowsArbitraryLoads": True,
                                    "NSExceptionDomains": {"example.com": {"NSExceptionAllowsInsecureHTTPLoads": True}}}),
        "zh-Hans.lproj/InfoPlist.strings": ('"CFBundleDisplayName" = "富大";\n"NSCameraUsageDescription" = "扫码用";\n').encode("utf-16"),
        "zh_TW.lproj/InfoPlist.strings": '"CFBundleDisplayName" = "富大繁";'.encode("utf-8"),
        "en.lproj/InfoPlist.strings": b'"CFBundleDisplayName" = "Foo EN";',
        "Foo": exe,
        "assets/a.bin": b"A" * 3000,
        "SC_Info/Foo.sinf": b"sinf", "SC_Info/Foo.supp": b"supp", "SC_Info/Manifest.plist": b"m",
    }
    sealed = {k: v for k, v in files.items() if k not in ("Foo", "SC_Info/Foo.sinf", "SC_Info/Foo.supp", "SC_Info/Manifest.plist")}
    files["_CodeSignature/CodeResources"] = b.seal(sealed)
    arch = b.app(files)
    arch["iTunesMetadata.plist"] = b.itunes_plist()
    arch.update(over)
    return arch


def test_stage_is_registered_with_contract_args():
    from ipa_analyzer.registry import get_registry
    from ipa_analyzer.pipeline import ensure_analyzers_loaded
    ensure_analyzers_loaded()
    spec = get_registry().get("meta")
    assert spec.requires == ("ingest",) and spec.after == () and not spec.always_run


def test_skipped_without_source(tmp_path):
    from ipa_analyzer.config import Config
    from ipa_analyzer.context import AnalysisContext
    res = meta_mod.MetaStage().run(AnalysisContext(Config(), tmp_path / "x.ipa"))
    assert res.status is Status.SKIPPED and res.reason


def test_app_store_package_end_to_end(run_meta, builders):
    res, ctx = run_meta(_store_app(builders))
    assert res.status is Status.OK, res.warnings
    d = res.data
    ident = d["identity"]
    assert ident["bundle_id"] == "com.example.foo" and ident["version"] == "1.2.3" and ident["build"] == "45"
    assert ident["selected_name"] == "富大"
    assert [(n["value"], n["lang"]) for n in ident["names"]][:5] == [
        ("富大", "zh-Hans"), ("富大繁", "zh-Hant"), ("Foo EN", "en"), ("Foo Display", ""), ("FooName", "")]
    assert ident["names"][-1] == {"value": "sample", "source": "input_filename", "lang": ""}
    assert ident["extra"]["localizations"] == ["en", "zh-Hans", "zh-Hant"]
    assert d["distribution"]["type"] == "appstore" and d["distribution"]["verdict"] == "yes"
    assert d["provision"] == {"present": False}
    assert d["itunes"]["item_name"] == "Foo Store Name" and d["itunes"]["genre_id"] == 6014
    assert d["fairplay_container"]["sc_info_present"] is True
    assert d["fairplay_container"]["files"] == ["SC_Info/Foo.sinf", "SC_Info/Foo.supp", "SC_Info/Manifest.plist"]
    assert d["url_schemes"] == ["foo", "wx123"] and d["query_schemes"] == ["weixin"]
    assert d["background_modes"] == ["audio", "fetch"] and d["capabilities"] == ["arm64", "metal"]
    assert d["ats"]["allows_arbitrary_loads"] is True and d["ats"]["exception_domains"] == ["example.com"]
    assert d["sdk"]["name"] == "iphoneos17.0" and d["sdk"]["xcode"] == "1500"
    keys = [p["key"] for p in d["permissions"]]
    assert keys == ["NSCameraUsageDescription", "NSUserTrackingUsageDescription", "NSPhotoLibraryAddUsageDescription"]
    assert d["permissions"][0]["localized"] == {"zh-Hans": "扫码用"} and d["permissions"][0]["level"] == "high"
    si = d["signature_integrity"]
    assert (si["checked"], si["missing"], si["modified"], si["extra"]) == (5, 0, 0, 0)
    ids = [f.id for f in res.findings]
    assert ids == ["meta.identity", "meta.distribution", "meta.permissions", "meta.fairplay_container", "meta.signature_integrity"]
    assert _finding(res, "meta.fairplay_container").verdict.value == "yes"
    assert _finding(res, "meta.signature_integrity").verdict.value == "no"
    assert _finding(res, "meta.permissions").params["count"] == 3
    json.loads(_dump(res))        # fully JSON-serialisable


def test_redaction_default_hides_purchaser(run_meta, builders):
    res, _ = run_meta(_store_app(builders))
    text = _dump(res)
    for secret in (builders.EMAIL, builders.BUYER, "777000111"):
        assert secret not in text
    assert res.data["itunes"]["appleId"] == "<redacted>"
    red = res.data["redaction"]
    assert red["applied"] is True and "appleId" in red["keys"] and "userName" in red["keys"]
    assert "com.apple.iTunesStore.downloadInfo.accountInfo.AppleID" in red["keys"]
    assert "unknownKey" in res.data["itunes"]["extra"]["other_keys"] and "keep-out-of-output" not in text


def test_no_redact_keeps_purchaser_but_never_udid(run_meta, builders):
    files = _store_app(builders)
    files[builders.APP + "embedded.mobileprovision"] = builders.fake_cms(builders.provision_plist("adhoc"))
    res, _ = run_meta(files, redact=False)
    text = _dump(res)
    assert builders.EMAIL in text and builders.BUYER in text
    assert res.data["redaction"] == {"applied": False, "keys": []}
    assert builders.UDID_A not in text and builders.UDID_B not in text and builders.UDID_A.lower() not in text.lower()
    assert res.data["provision"]["device_count"] == 2


@pytest.mark.parametrize("kind,dist", [("development", "development"), ("adhoc", "adhoc"), ("enterprise", "enterprise"),
                                       ("appstore", "appstore")])
def test_profile_driven_distribution(run_meta, builders, kind, dist):
    files = builders.app({"Info.plist": builders.info_plist(), "Foo": b"x",
                          "embedded.mobileprovision": builders.fake_cms(builders.provision_plist(kind)),
                          "_CodeSignature/CodeResources": builders.seal({"Info.plist": builders.info_plist()})})
    res, _ = run_meta(files)
    d = res.data
    assert d["distribution"]["type"] == dist and d["provision"]["present"] is True
    assert d["provision"]["team_id"] == "TEAM123456" and d["provision"]["expiration_date"] == "2025-01-02T03:04:05Z"
    refs = [e["ref"] for e in d["distribution"]["evidence"]]
    assert "embedded.mobileprovision" in refs
    text = _dump(res)
    assert builders.UDID_A not in text and builders.UDID_B not in text
    if kind in ("development", "adhoc"):
        assert d["provision"]["device_count"] == 2 and len(d["provision"]["device_hash_prefixes"]) == 2
    if kind == "enterprise":
        assert d["provision"]["provisions_all_devices"] is True
    assert _finding(res, "meta.distribution").params["type"] == dist


def test_unsigned_package(run_meta, builders):
    res, _ = run_meta(builders.app({"Info.plist": builders.info_plist(), "Foo": b"x"}))
    assert res.status is Status.OK
    assert res.data["distribution"]["type"] == "unsigned_or_repackaged" and res.data["distribution"]["verdict"] == "suspected"
    assert _finding(res, "meta.fairplay_container").verdict.value == "no"
    assert _finding(res, "meta.signature_integrity").verdict.value == "n/a"
    assert "signature_integrity" not in res.data
    assert _finding(res, "meta.permissions").verdict.value == "no"


def test_restored_ipa_with_store_artefacts_and_dev_profile_is_flagged_resigned(run_meta, builders):
    files = _store_app(builders)
    files[builders.APP + "embedded.mobileprovision"] = builders.fake_cms(builders.provision_plist("development"))
    res, _ = run_meta(files)
    dist = res.data["distribution"]
    assert dist["type"] == "development" and dist["verdict"] == "suspected" and dist["extra"]["repackaged_hint"] is True
    assert "repackaged_hint" in _finding(res, "meta.distribution").tags


def test_tampered_seal_is_reported(run_meta, builders):
    files = _store_app(builders)
    files[builders.APP + "assets/a.bin"] = b"X" * 3000
    files[builders.APP + "evil.dylib"] = b"inject"
    res, _ = run_meta(files)
    si = res.data["signature_integrity"]
    assert si["modified"] == 1 and si["extra"] == 1
    f = _finding(res, "meta.signature_integrity")
    assert f.verdict.value == "yes" and "tampered" in f.tags


def test_signature_integrity_can_be_disabled(run_meta, builders):
    res, _ = run_meta(_store_app(builders), signature_integrity=False)
    assert "signature_integrity" not in res.data
    f = _finding(res, "meta.signature_integrity")
    assert f.verdict.value == "n/a" and f.params["reason"] == "disabled"


def test_corrupt_info_plist_is_partial_not_fatal(run_meta, builders):
    files = builders.app({"Info.plist": b"\x00garbage\xff\xfe not a plist", "Foo": b"x"})
    res, _ = run_meta(files)
    assert res.status is Status.PARTIAL and res.reason
    assert any("Info.plist" in w for w in res.warnings)
    assert _finding(res, "meta.identity").verdict.value == "unknown"
    assert res.data["identity"]["bundle_id"] is None
    assert res.data["identity"]["selected_name"] == "sample"          # input file name is the last resort
    assert _finding(res, "meta.permissions").verdict.value == "unknown"


def test_missing_info_plist(run_meta, builders):
    res, _ = run_meta(builders.app({"Foo": b"x"}))
    assert res.status is Status.PARTIAL and any("not found" in w for w in res.warnings)
    json.loads(_dump(res))


def test_each_broken_subfile_only_warns(run_meta, builders):
    files = _store_app(builders)
    files["iTunesMetadata.plist"] = b"nope"
    files[builders.APP + "embedded.mobileprovision"] = b"\x30\x82 no plist inside"
    files[builders.APP + "_CodeSignature/CodeResources"] = b"nope"
    files[builders.APP + "fr.lproj/InfoPlist.strings"] = b"\x00\xff\x01\x02"
    files[builders.APP + "PlugIns/Bad.appex/Info.plist"] = b"nope"
    res, _ = run_meta(files)
    assert res.status is Status.PARTIAL
    joined = "\n".join(res.warnings)
    for needle in ("iTunesMetadata", "mobileprovision", "CodeResources", "PlugIns/Bad.appex/Info.plist"):
        assert needle in joined, needle
    assert res.data["identity"]["bundle_id"] == "com.example.foo"         # the good parts survive
    assert res.data["distribution"]["type"] == "unknown"                    # unreadable profile => cannot decide
    assert res.data["extensions"][0]["bundle_id"] is None
    assert _finding(res, "meta.signature_integrity").verdict.value == "unknown"


def test_substep_exception_is_isolated(run_meta, builders, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("kaboom")
    monkeypatch.setattr(meta_mod, "collect_permissions", boom)
    res, _ = run_meta(_store_app(builders))
    assert res.status is Status.PARTIAL and any("permissions failed" in w and "kaboom" in w for w in res.warnings)
    assert res.data["permissions"] == [] and res.data["identity"]["bundle_id"] == "com.example.foo"


def test_extensions_watch_and_app_clip(run_meta, builders):
    b = builders
    ext = plistlib.dumps({"CFBundleIdentifier": "com.example.foo.share", "CFBundleDisplayName": "Share",
                          "CFBundleShortVersionString": "1.0", "NSExtension": {"NSExtensionPointIdentifier": "com.apple.share-services",
                                                                              "NSExtensionPrincipalClass": "ShareVC"}})
    watch = plistlib.dumps({"CFBundleIdentifier": "com.example.foo.watchkitapp", "WKCompanionAppBundleIdentifier": "com.example.foo",
                            "WKApplication": True})
    clip = plistlib.dumps({"CFBundleIdentifier": "com.example.foo.Clip", "NSAppClip": {"NSAppClipRequestEphemeralUserNotification": False}})
    files = b.app({"Info.plist": b.info_plist(), "PlugIns/Share.appex/Info.plist": ext, "PlugIns/Share.appex/Share": b"x",
                   "Watch/W.app/Info.plist": watch, "Watch/W.app/PlugIns/Ext.appex/Info.plist": ext,
                   "AppClips/Clip.app/Info.plist": clip})
    res, _ = run_meta(files)
    exts = {e["path"].replace(b.APP, ""): e for e in res.data["extensions"]}
    assert set(exts) == {"PlugIns/Share.appex", "Watch/W.app", "Watch/W.app/PlugIns/Ext.appex", "AppClips/Clip.app"}
    assert exts["PlugIns/Share.appex"]["kind"] == "appex" and exts["PlugIns/Share.appex"]["point"] == "com.apple.share-services"
    assert exts["PlugIns/Share.appex"]["bundle_id"] == "com.example.foo.share"
    assert exts["Watch/W.app"]["kind"] == "watch" and exts["Watch/W.app"]["extra"]["companion_bundle_id"] == "com.example.foo"
    assert exts["AppClips/Clip.app"]["kind"] == "app_clip"
    assert exts["Watch/W.app/PlugIns/Ext.appex"]["extra"]["parent"] == b.APP + "Watch/W.app"
    assert [e["path"] for e in res.data["extensions"]] == sorted(e["path"] for e in res.data["extensions"])


def test_directory_style_app_root_and_no_payload_prefix(run_meta, builders):
    files = {"Info.plist": builders.info_plist(), "zh-Hans.lproj/InfoPlist.strings": "\"CFBundleDisplayName\"=\"名\";".encode("utf-8"),
             "iTunesMetadata.plist": builders.itunes_plist()}
    res, _ = run_meta(files, app_root="")
    assert res.data["identity"]["selected_name"] == "名" and res.data["distribution"]["type"] == "appstore"
    assert res.data["redaction"]["applied"] is True


def test_output_is_deterministic(run_meta, builders):
    a, _ = run_meta(_store_app(builders), input_name="one.ipa")
    b, _ = run_meta(_store_app(builders), input_name="one.ipa")
    assert _dump(a) == _dump(b)


def test_sc_info_directory_without_fairplay_files(run_meta, builders):
    res, _ = run_meta(builders.app({"Info.plist": builders.info_plist(), "SC_Info/readme.txt": b"x"}))
    f = _finding(res, "meta.fairplay_container")
    assert f.verdict.value == "suspected" and res.data["fairplay_container"]["sc_info_present"] is True


def test_i18n_templates_format_with_every_finding_params(run_meta, builders):
    import string
    from ipa_analyzer.util.paths import resource_dir
    tamper = _store_app(builders)
    tamper[builders.APP + "assets/a.bin"] = b"X" * 3000
    scenarios = [
        _store_app(builders),
        builders.app({"Info.plist": builders.info_plist(), "Foo": b"x"}),
        builders.app({"Info.plist": b"garbage"}),
        tamper,
        builders.app({"Info.plist": builders.info_plist(), "SC_Info/readme.txt": b"x"}),
    ]
    for lang in ("zh", "en"):
        tables = json.loads((resource_dir("data") / "i18n" / lang / "meta.json").read_text(encoding="utf-8"))
        for i, files in enumerate(scenarios):
            res, _ = run_meta(files, signature_integrity=(i != 1), input_name="s%d.ipa" % i)
            for f in res.findings:
                entry = tables[f.id]
                for field in ("title", "summary", "remediation"):
                    fields = {n for _, n, _, _ in string.Formatter().parse(entry[field]) if n}
                    assert fields <= set(f.params), (lang, f.id, field, fields - set(f.params))
                    entry[field].format_map(f.params)
