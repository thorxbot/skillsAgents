from __future__ import annotations

import json
import plistlib

import pytest

from fixtures.macho_builder import build_macho
from ipa_analyzer.analyzers.libs import LibsStage
from ipa_analyzer.models import Status, Verdict

SYS = ["/usr/lib/libSystem.B.dylib", "/System/Library/Frameworks/CoreLocation.framework/CoreLocation",
       "/System/Library/Frameworks/UIKit.framework/UIKit", "/System/Library/Frameworks/AdSupport.framework/AdSupport"]


def fw(name, **kw):
    return {"Frameworks/%s.framework/%s" % (name, name): build_macho(filetype="dylib", **kw),
            "Frameworks/%s.framework/Info.plist" % name: plistlib.dumps({"CFBundleShortVersionString": "9.8.7"})}


def app_files(*, encrypted=False, **kw):
    files = {"T": build_macho(encrypted=encrypted, dylibs=SYS + [
        "@rpath/FirebaseCore.framework/FirebaseCore", "@rpath/AppsFlyerLib.framework/AppsFlyerLib",
        "@rpath/GoogleMobileAds.framework/GoogleMobileAds", "@rpath/MyOwnKit.framework/MyOwnKit"], **kw)}
    for n in ("FirebaseCore", "AppsFlyerLib", "GoogleMobileAds", "MyOwnKit"):
        files.update(fw(n))
    files["Frameworks/GoogleMobileAds.framework/GoogleMobileAdsResources.bundle/Info.plist"] = b"x"
    files["GoogleService-Info.plist"] = plistlib.dumps({"GOOGLE_APP_ID": "x"})
    return files


def items_by_id(ctx):
    return {i["id"]: i for i in ctx.results["libs"]["items"]}


def test_firebase_appsflyer_admob_identified_with_merged_evidence(run_stages):
    ctx = run_stages(app_files(objc_classes=["GADMobileAds"], imports=["_OBJC_CLASS_$_GADMobileAds"]))
    items = items_by_id(ctx)
    assert {"firebase_core", "appsflyer", "admob"} <= set(items)
    admob = items["admob"]
    assert admob["kind"] == "framework" and admob["category"] == "ads" and admob["vendor"] == "Google"
    kinds = {e["kind"] for e in admob["evidence"]}
    assert {"file", "macho", "symbol"} <= kinds and admob["confidence"] >= 0.95 and admob["version"] == "9.8.7"
    assert "ads" in admob["tags"] and "admob" in ctx.results["libs"]["privacy_tags"]["ads"]
    assert "appsflyer" in ctx.results["libs"]["privacy_tags"]["tracking"]
    assert items["firebase_core"]["confidence"] >= 0.8
    assert ctx.results["libs"]["by_category"]["ads"] >= 1
    sys_items = {i["name"]: i for i in ctx.results["libs"]["items"] if i["kind"] == "system"}
    assert sys_items["CoreLocation"]["sensitive"] and sys_items["CoreLocation"]["capability"] == "location"
    assert sys_items["AdSupport"]["capability"] == "advertising_id" and "UIKit" in sys_items
    assert {f.id for f in ctx.stage_results["libs"].findings} == {"libs.summary", "libs.unknown"}


def test_unknown_library_has_no_purpose(run_stages):
    ctx = run_stages(app_files())
    unk = {u["name"]: u for u in ctx.results["libs"]["unknown"]}
    assert "MyOwnKit" in unk and unk["MyOwnKit"]["kind"] == "framework"
    assert not any(k in unk["MyOwnKit"] for k in ("purpose", "purpose_zh", "purpose_en", "vendor"))
    assert unk["MyOwnKit"]["evidence"]
    assert "myownkit" not in items_by_id(ctx)
    f = {f.id: f for f in ctx.stage_results["libs"].findings}["libs.unknown"]
    assert f.verdict == Verdict.UNKNOWN and "MyOwnKit" in f.summary


def test_name_hint_is_marked_as_guess(run_stages):
    files = {"T": build_macho(dylibs=["@rpath/FirebaseNIMessInstallation.framework/FirebaseNIMessInstallation"])}
    files.update(fw("FirebaseNIMessInstallation"))
    unk = {u["name"]: u for u in run_stages(files).results["libs"]["unknown"]}
    assert "unverified" in unk["FirebaseNIMessInstallation"]["hint"]


def test_encrypted_binary_gives_no_noise_but_keeps_load_commands_and_import_symbols(run_stages):
    # ObjC class names live in the encrypted range: they must be skipped, never reported
    ctx = run_stages(app_files(encrypted=True, objc_classes=["GADMobileAds", "AppsFlyerLib"], strings=["googleads.g.doubleclick.net"]))
    libs = ctx.results["libs"]
    assert libs["limitations"]["binary_encrypted"] and libs["limitations"]["encrypted_binaries"] >= 1
    admob_ev = items_by_id(ctx)["admob"]["evidence"]
    assert not any("ObjC class" in e["detail"] for e in admob_ev)
    f = ctx.stage_results["libs"].findings[0]
    assert "encrypted" in f.summary and "decrypted IPA" in f.remediation
    # an imported ObjC class symbol is readable even in an encrypted binary
    ctx2 = run_stages({"T": build_macho(encrypted=True, imports=["_OBJC_CLASS_$_GADMobileAds"])})
    assert "admob" in items_by_id(ctx2)


def test_plain_binary_without_features_yields_nothing_spurious(run_stages):
    ctx = run_stages({"T": build_macho(objc_classes=["AppDelegate", "MyViewController"], dylibs=SYS)})
    libs = ctx.results["libs"]
    assert [i for i in libs["items"] if i["kind"] != "system"] == [] and libs["unknown"] == []
    f = ctx.stage_results["libs"].findings[0]
    assert f.verdict == Verdict.NO


def test_user_override_and_new_entry(run_stages, tmp_path):
    user = tmp_path / "libs.user.json"
    user.write_text(json.dumps({"libs": [
        {"id": "admob", "name": "AdMob (custom)", "category": "ads", "purpose_zh": "自定义", "purpose_en": "custom purpose",
         "match": {"framework": ["GoogleMobileAds"]}},
        {"id": "my_own_kit", "name": "My Own Kit", "vendor": "Me", "category": "other", "purpose_zh": "自研", "purpose_en": "in-house",
         "match": {"framework": ["MyOwnKit"]}},
        {"id": "broken", "name": "Broken", "category": "nope", "purpose_zh": "x", "purpose_en": "x", "match": {"framework": ["B"]}}]}),
        encoding="utf-8")
    ctx = run_stages(app_files(), libs_user=user)
    items = items_by_id(ctx)
    assert items["admob"]["name"] == "AdMob (custom)" and items["admob"]["purpose_en"] == "custom purpose"
    assert items["my_own_kit"]["vendor"] == "Me"
    assert "MyOwnKit" not in {u["name"] for u in ctx.results["libs"]["unknown"]}
    assert any("broken" in w or "entry 2" in w for w in ctx.stage_results["libs"].warnings)


@pytest.mark.parametrize("content", ["{not json", "[1, 2, 3]", json.dumps({"libs": "nope"}), ""])
def test_corrupt_user_file_only_warns(run_stages, tmp_path, content):
    user = tmp_path / "libs.user.json"
    user.write_text(content, encoding="utf-8")
    ctx = run_stages(app_files(), libs_user=user)
    assert ctx.stage_status("libs") in (Status.OK, Status.PARTIAL) and "admob" in items_by_id(ctx)


def test_hotfix_fingerprint_and_unity_signals(run_stages):
    inject = {
        "engine.unity.hotfix": {"frameworks": [{"id": "hybridclr", "name": "HybridCLR", "kind": "csharp", "confidence": 0.9,
                                                  "version_hint": "8.0", "evidence": [{"kind": "string", "ref": "x", "detail": "HybridCLR"}]}],
                                "lua": {"runtime_versions": [{"flavor": "luajit", "version": "2.1", "source": "native strings", "confidence": 0.8}]}},
        "engine.fingerprint": {"physics": [{"id": "box2d", "name": "Box2D", "confidence": 0.7, "evidence": []}],
                               "script_vms": [{"id": "wren", "name": "Wren", "confidence": 0.6, "evidence": []}],
                               "audio": [{"id": "not_in_kb", "name": "NoKb", "confidence": 0.5, "evidence": []}]},
        "engine.unity": {"dump": {"namespaces": ["XLua", "Cysharp.Threading.Tasks", "Company.Game"]}}}
    ctx = run_stages({"T": build_macho()}, inject=inject)
    st = LibsStage().run(ctx)
    items = {i["id"]: i for i in st.data["items"]}
    assert items["hybridclr"]["version"] == "8.0" and items["hybridclr"]["category"] == "hotfix"
    assert items["luajit"]["version"] == "2.1" and items["luajit"]["kind"] == "static_sdk" and items["luajit"]["purpose_en"]
    assert items["box2d"]["purpose_en"] and items["wren"]["category"] == "hotfix"
    assert items["not_in_kb"]["category"] == "media" and items["not_in_kb"]["purpose_en"]
    assert items["xlua"]["kind"] == "unity_namespace" and "unitask" in items and "company.game" not in items


def test_without_macho_stage_is_partial_but_file_evidence_works(run_stages):
    files = {k: v for k, v in app_files().items() if not k.endswith("/FirebaseCore") and k != "T"}
    ctx = run_stages(files, stages=("ingest", "inventory", "libs"))
    st = ctx.stage_results["libs"]
    assert st.status == Status.PARTIAL and "macho" in (st.reason or "")
    assert "firebase_core" in items_by_id(ctx) or "admob" in items_by_id(ctx)


def test_resource_bundle_and_privacy_bundle_not_unknown(run_stages):
    files = {"T": build_macho(), "FirebaseCore_Privacy.bundle/PrivacyInfo.xcprivacy": b"x",
             "Zzz_Privacy.bundle/PrivacyInfo.xcprivacy": b"x", "Zzz.bundle/a.txt": b"x"}
    ctx = run_stages(files)
    assert "firebase_core" in items_by_id(ctx)
    names = {u["name"] for u in ctx.results["libs"]["unknown"]}
    assert "FirebaseCore_Privacy" not in names and "Zzz" in names
