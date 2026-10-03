"""Hand-written, contract-shaped stage results and ``Report`` fixtures for rendering tests (WP8).

Usage (``tests`` is on ``pythonpath``)::

    from fixtures.sample_report import FIXTURES, full_success_report, build_ctx

Four scenarios, together covering every stage status (ok / partial / skipped / failed) of all 13 stages:

* ``full_success``      Unity IL2CPP game, every stage ran (``macho`` is ``partial``).
* ``custom_engine``     in-house engine suspected; ``meta`` / ``macho`` / ``protect`` failed, ``libs`` partial,
                        ``engine.other`` skipped by ``--skip``, Unity stages skipped (not a Unity app).
* ``ingest_only``       only ``ingest`` succeeded; ``inventory`` failed, everything downstream skipped
                        ("dependency X failed / skipped" chains).
* ``cocos_lua``         FairPlay-encrypted Cocos2d-x Lua game, xxtea suspected, Unity stages skipped.

The data is shaped exactly like ``ctx.results[...]`` in docs/CONTRACT-FREEZE.md section 4; the personal data in
it (home path, e-mail, UDIDs) is deliberate: it exercises the redaction pass.
"""
from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List

from ipa_analyzer.config import Config
from ipa_analyzer.context import AnalysisContext
from ipa_analyzer.models import Evidence, Finding, Report, StageResult

GENERATED_AT = "2026-01-01T00:00:00Z"
STAGE_NAMES = ("ingest", "inventory", "meta", "macho", "engine.fingerprint", "engine.detect", "engine.other",
               "engine.unity", "engine.unity.hotfix", "libs", "protect", "classify", "report")

# Deliberate personal data (must never survive default redaction).
HOME_PATH = "/Users/alice/Downloads/DemoGame.ipa"
EMAIL = "dev.support@example.com"
UDID_OLD = "0123456789abcdef0123456789abcdef01234567"
UDID_NEW = "00008110-001A2B3C4D5E6F70"


def _sha(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def E(kind: str, ref: str, detail: str = "") -> Evidence:
    return Evidence(kind, ref, detail)


def ev(kind: str, ref: str, detail: str = "") -> Dict[str, str]:
    return {"kind": kind, "ref": ref, "detail": detail}


def F(fid: str, verdict: str, conf: float, title: str, summary: str = "", params: Dict[str, Any] = None,
      evidence: List[Evidence] = None, remediation: str = "", tags: List[str] = None) -> Finding:
    return Finding(fid, verdict, conf, title, summary, dict(params or {}), list(evidence or []), remediation, list(tags or []))


def _tree() -> Dict[str, Any]:
    def n(name, size, count, children=None):
        return {"name": name, "size": size, "count": count, "children": children or []}

    return n("DemoGame.app", 734003200, 3120, [
        n("Data", 612000000, 2900, [
            n("Managed", 120000000, 40, [n("Metadata", 60000000, 1, [n("global-metadata.dat", 60000000, 1)])]),
            n("Raw", 400000000, 2500), n("Resources", 80000000, 300)]),
        n("Frameworks", 98000000, 120, [n("UnityFramework.framework", 97000000, 100)]),
        n("DemoGame", 12000000, 1), n("Assets.car", 8000000, 1), n("zh-Hans.lproj", 40000, 3),
    ])


def _unity_inventory() -> Dict[str, Any]:
    files = [
        {"path": "Payload/DemoGame.app/DemoGame", "size": 12000000, "csize": 4800000, "ext": "", "magic": "macho", "category": "executable", "entropy": 6.1},
        {"path": "Payload/DemoGame.app/Data/Managed/Metadata/global-metadata.dat", "size": 60000000, "csize": 21000000, "ext": ".dat", "magic": "unknown", "category": "engine_data"},
        {"path": "Payload/DemoGame.app/Data/Raw/aa/ui.bundle", "size": 9000000, "csize": 8800000, "ext": ".bundle", "magic": "unityfs", "category": "assetbundle"},
    ]
    return {
        "files": files, "files_total": 3120, "files_truncated": True, "inventory_file": "inventory.json",
        "by_category": [
            {"category": "assetbundle", "count": 410, "size": 400000000, "percent": 54.5},
            {"category": "engine_data", "count": 120, "size": 150000000, "percent": 20.4},
            {"category": "framework", "count": 100, "size": 97000000, "percent": 13.2},
            {"category": "executable", "count": 1, "size": 12000000, "percent": 1.6},
            {"category": "image", "count": 900, "size": 60000000, "percent": 8.2},
            {"category": "other", "count": 1589, "size": 15003200, "percent": 2.1}],
        "by_ext": [{"ext": ".bundle", "count": 410, "size": 400000000}, {"ext": ".dat", "count": 3, "size": 61000000},
                   {"ext": ".png", "count": 800, "size": 40000000}, {"ext": "", "count": 5, "size": 120000}],
        "top_files": [{"path": "Payload/DemoGame.app/Data/Raw/aa/big|odd`name.bundle", "size": 90000000, "category": "assetbundle"},
                      {"path": "Payload/DemoGame.app/Data/Managed/Metadata/global-metadata.dat", "size": 60000000, "category": "engine_data"}],
        "localizations": ["zh-Hans", "en", "Base"], "archives": [],
        "nested_units": [
            {"path": "Payload/DemoGame.app/Frameworks/UnityFramework.framework", "rel": "Frameworks/UnityFramework.framework", "kind": "framework", "name": "UnityFramework", "size": 97000000, "file_count": 100},
            {"path": "Payload/DemoGame.app/PlugIns/Share.appex", "rel": "PlugIns/Share.appex", "kind": "appex", "name": "Share", "size": 300000, "file_count": 6}],
        "tree": _tree(),
        "structure_hints": {"top_level_dirs": ["Data", "Frameworks"], "has": {"Frameworks": True, "PlugIns": True, "Watch": False, "SC_Info": False, "_CodeSignature": True, "Data": True, "Assets_car": True, "embedded_mobileprovision": False, "iTunesMetadata_plist": True}},
    }


def _meta_unity() -> Dict[str, Any]:
    return {
        "identity": {"names": [{"value": "示例游戏", "source": "InfoPlist.strings", "lang": "zh-Hans"},
                               {"value": "DemoGame", "source": "CFBundleDisplayName", "lang": ""}],
                     "selected_name": "示例游戏", "bundle_id": "com.example.demogame", "version": "1.2.3", "build": "456",
                     "executable": "DemoGame", "min_os": "12.0", "devices": ["iPhone", "iPad"]},
        "distribution": {"type": "appstore", "verdict": "yes", "confidence": 0.9,
                         "evidence": [ev("file", "iTunesMetadata.plist", "present"), ev("file", "SC_Info", "absent: decrypted dump")]},
        "provision": {"present": False}, "itunes": {"item_id": 123456, "item_name": "DemoGame", "apple-id": "<redacted>"},
        "fairplay_container": {"sc_info_present": False, "files": []},
        "permissions": [
            {"key": "NSCameraUsageDescription", "description": "Scan codes", "localized": {"zh-Hans": "用于扫码", "en": "Scan codes"}, "level": "medium", "meaning_zh": "访问相机", "meaning_en": "Camera access"},
            {"key": "NSLocationAlwaysUsageDescription", "description": "Always location", "localized": {"en": "Always location"}, "level": "high", "meaning_zh": "始终访问位置", "meaning_en": "Always-on location"}],
        "url_schemes": ["demogame", "fb123456"], "query_schemes": ["weixin", "alipay"],
        "ats": {"allows_arbitrary_loads": True, "exception_domains": ["cdn.example.com"]},
        "extensions": [{"path": "Payload/DemoGame.app/PlugIns/Share.appex", "bundle_id": "com.example.demogame.share", "kind": "appex", "point": "com.apple.share-services"}],
        "background_modes": ["audio", "remote-notification"], "capabilities": ["arm64", "metal"],
        "sdk": {"name": "iphoneos", "platform_version": "17.0", "xcode": "1500", "compiler": "com.apple.compilers.llvm.clang.1_0"},
        "signature_integrity": {"checked": 812, "missing": 0, "modified": 0, "extra": 0, "examples": []},
        "redaction": {"applied": True, "keys": ["itunes.apple-id"]}, "warnings": [],
    }


def _macho_unity() -> Dict[str, Any]:
    def sl(**kw):
        base = {"arch": "arm64", "filetype": "execute", "platform": "ios", "min_os": "12.0", "sdk": "17.0", "uuid": "11111111-2222-3333-4444-555555555555",
                "encrypted": False, "cryptid": 0, "cryptsize": 0, "is_pie": True, "stripped": True, "has_swift": False, "has_objc": True,
                "has_cpp": True, "signed": True, "team_id": "ABCDE12345", "entitlements_keys": ["application-identifier"]}
        base.update(kw)
        return base

    return {"binaries": [
        {"path": "Payload/DemoGame.app/DemoGame", "rel": "DemoGame", "role": "main", "kind": "execute", "size": 12000000, "is_fat": False,
         "slices": [sl()], "dylibs": [{"path": "/usr/lib/libz.1.dylib", "kind": "system", "load_kind": "load", "weak": False}], "rpaths": ["@executable_path/Frameworks"], "parse_warnings": []},
        {"path": "Payload/DemoGame.app/Frameworks/UnityFramework.framework/UnityFramework", "rel": "Frameworks/UnityFramework.framework/UnityFramework",
         "role": "framework", "kind": "dylib", "size": 97000000, "is_fat": False, "slices": [sl(filetype="dylib", has_swift=True)], "dylibs": [], "rpaths": [],
         "parse_warnings": ["LC_DYLD_CHAINED_FIXUPS not parsed"]}],
        "summary": {"main_binary": "Payload/DemoGame.app/DemoGame", "any_encrypted": False, "all_encrypted": False, "archs": ["arm64"], "min_os": "12.0", "languages_hint": ["objc", "cpp", "csharp"]}}


def _fingerprint_unity() -> Dict[str, Any]:
    return {"render": {"metal": {"id": "metal", "name": "Metal", "confidence": 0.95, "evidence": [ev("symbol", "MTLCreateSystemDefaultDevice")], "extra": {}}},
            "shader_formats": [{"id": "metallib", "name": "metallib", "confidence": 0.6, "evidence": [ev("file", "default.metallib")], "extra": {}}],
            "script_vms": [{"id": "il2cpp", "name": "IL2CPP", "confidence": 0.9, "evidence": [ev("symbol", "il2cpp_init")], "extra": {}},
                           {"id": "luajit", "name": "LuaJIT", "confidence": 0.7, "evidence": [ev("string", "luaL_newstate")], "extra": {}}],
            "physics": [{"id": "physx", "name": "PhysX", "confidence": 0.5, "evidence": [], "extra": {}}], "audio": [{"id": "fmod", "name": "FMOD", "confidence": 0.8, "evidence": [ev("dylib", "libfmod.dylib")], "extra": {}}],
            "animation": [], "network": [{"id": "protobuf", "name": "protobuf", "confidence": 0.6, "evidence": [], "extra": {}}], "asset_formats": [{"id": "astc", "name": "ASTC", "confidence": 0.7, "evidence": [], "extra": {}}],
            "containers": [], "host": {"thin_uikit_shell": True, "cpp_ratio": 0.62, "objc_swift_ratio": 0.2, "main_loop_hints": ["CADisplayLink"]},
            "summary_text": "Metal renderer, IL2CPP and LuaJIT script VMs, FMOD audio."}


def _detect_unity() -> Dict[str, Any]:
    prim = {"id": "unity", "name": "Unity", "family": "unity", "kind": "game_engine", "confidence": 0.97, "confirmed": True,
            "signals_matched": ["file:UnityFramework", "string:il2cpp_"], "evidence": [ev("file", "Frameworks/UnityFramework.framework", "framework present"), ev("string", "il2cpp_init", "")], "extra": {}}
    return {"primary": prim, "candidates": [prim], "wrapper": None,
            "custom": {"verdict": "no", "confidence": 0.05, "evidence": [], "profile_ref": "engine.fingerprint", "conditions": {"known_engine_confirmed": True}, "next_steps": [], "deviations": [], "open_source_base": []},
            "languages": [{"lang": "csharp", "confidence": 0.9, "evidence": [ev("heuristic", "il2cpp")]}, {"lang": "objc", "confidence": 0.8, "evidence": []}, {"lang": "lua", "confidence": 0.6, "evidence": []}],
            "is_game_engine": True, "extra": {}}


def _unity_data(many_namespaces: bool = True) -> Dict[str, Any]:
    ns = ["System", "UnityEngine", "XLua", "LuaInterface", "HybridCLR"] + ["Game.Module%03d" % i for i in range(150 if many_namespaces else 3)]
    return {
        "version": {"value": "2021.3.21f1", "sources": [{"source": "globalgamemanagers", "value": "2021.3.21f1", "ref": "Data/globalgamemanagers"}, {"source": "unityfs_header", "value": "2021.3.21f1", "ref": "Data/Raw/aa/ui.bundle"}], "conflicts": []},
        "backend": "il2cpp", "binary": {"path": "Payload/DemoGame.app/Frameworks/UnityFramework.framework/UnityFramework", "slice": "arm64", "encrypted": False},
        "metadata": {"path": "Payload/DemoGame.app/Data/Managed/Metadata/global-metadata.dat", "present": True, "version": 29, "header_ok": True, "entropy": 5.1, "string_region_ok": True,
                     "string_region": {"offset": 1024, "size": 2048000}, "verdict": "no", "evidence": [ev("string", "mscorlib", "found in string region")]},
        "bundles": {"total": 410, "by_class": {"standard": 400, "offset_prefix": 0, "xor_simple": 0, "high_entropy_unknown": 8, "other": 2, "unknown": 0},
                    "compression": {"lz4": 380, "lzma": 20}, "unity_versions": {"2021.3.21f1": 410}, "samples": {"standard": ["Data/Raw/aa/ui.bundle"], "high_entropy_unknown": ["Data/Raw/x/a.bin", "Data/Raw/x/b.bin"]},
                    "paths_sample": ["Payload/DemoGame.app/Data/Raw/aa/b%03d.bundle" % i for i in range(120)], "sampled": 200, "addressables": {"catalog_found": True}},
        "mono": {"assemblies": [], "verdict": "n/a", "evidence": []}, "precheck": {"ready": True, "error_code": None, "reasons": []},
        "dump": {"ran": True, "ok": True, "backend": "Il2CppDumper", "backend_version": "6.7.40", "out_dir": "il2cpp", "artifacts": {"dump.cs": "il2cpp/dump.cs", "script.json": "il2cpp/script.json"},
                 "error_code": None, "remediation": "", "cached": False, "duration_s": 12.3, "namespaces": ns,
                 "summary": {"assemblies": 12, "classes": 4200, "interfaces": 130, "enums": 210, "methods": 38000, "fields": 21000, "string_literals": 9800,
                             "framework_namespaces": ["UnityEngine", "XLua"], "obfuscation": {"score": 0.12, "non_standard_ratio": 0.05, "short_ratio": 0.1, "non_ascii_ratio": 0.0}}},
    }


def _hotfix_unity() -> Dict[str, Any]:
    return {
        "frameworks": [
            {"id": "tolua", "name": "ToLua", "kind": "lua", "confidence": 0.85, "version_hint": None, "evidence": [ev("string", "LuaInterface.LuaState", "metadata string table")]},
            {"id": "hybridclr", "name": "HybridCLR", "kind": "csharp", "confidence": 0.9, "version_hint": "4.x", "evidence": [ev("string", "HybridCLR.RuntimeApi", "")]},
            {"id": "addressables", "name": "Addressables", "kind": "resource", "confidence": 0.8, "version_hint": None, "evidence": [ev("file", "aa/catalog.json", "")]}],
        "lua": {"runtime_versions": [{"flavor": "puc", "version": "5.1", "source": "native_string", "confidence": 0.6}],
                "bytecode": {"by_version": {"luajit_2.1": 98, "5.1": 0}, "invalid": 1, "stripped_count": 90, "arch_bits": {"32": 0, "64": 98}},
                "files": {"plain": 20, "bytecode": 98, "compressed": 0, "encrypted_suspected": 3, "total": 121}, "dialect_hints": ["5.1-style (setfenv)"],
                "consistency": {"ok": False, "notes": ["bytecode is LuaJIT 2.1 but the native runtime string says PUC-Lua 5.1"]}, "custom_lua_suspected": False},
        "js": {"backends": [], "files": {"plain": 0, "bytecode": 0, "encrypted_suspected": 0, "total": 0}, "formats": []},
        "csharp": {"assemblies": [
            {"name": "HotUpdate", "source": "bundle", "size": 1800000, "format": "pe_cli", "clr": "v4.0.30319", "asm_refs": ["mscorlib", "UnityEngine.CoreModule", "Assembly-CSharp", "netstandard", "System.Core", "X"], "kind": "hot", "path": "Data/Raw/hot/hot.bundle"},
            {"name": "mscorlib", "source": "loose", "size": 900000, "format": "pe_cli", "clr": "v4.0.30319", "asm_refs": [], "kind": "aot_meta", "path": "Data/Raw/aot/mscorlib.dll.bytes"},
            {"name": "Blob", "source": "bundle", "size": 40000, "format": "encrypted_suspected", "clr": None, "asm_refs": [], "kind": "unknown"}]},
        "resource_update": {"frameworks": [{"id": "addressables", "name": "Addressables"}], "catalogs": ["aa/catalog.json"], "manifests": [], "hosts": ["cdn.example.com"]},
        "storage": {"loose": 40, "in_bundles": 150, "in_serialized": 2, "scanned": {"bundles_sampled": 100, "total": 410}},
        "script_protection": {"lua": "no", "js": "n/a", "csharp": "suspected"},
        "summary_text": "ToLua + HybridCLR + Addressables; Lua is LuaJIT 2.1 bytecode.",
    }


def _libs_unity() -> Dict[str, Any]:
    def it(i, name, kind, vendor, cat, zh, en, tags, conf):
        return {"id": i, "name": name, "kind": kind, "vendor": vendor, "category": cat, "purpose_zh": zh, "purpose_en": en, "tags": tags, "confidence": conf,
                "evidence": [ev("file", "Frameworks/%s.framework" % name, "")]}

    items = [it("unityframework", "UnityFramework", "framework", "Unity", "engine", "Unity 运行时", "Unity runtime", [], 0.99),
             it("firebase", "FirebaseAnalytics", "framework", "Google", "analytics", "统计分析", "Analytics", ["analytics"], 0.9),
             it("applovin", "AppLovinSDK", "framework", "AppLovin", "ads", "广告聚合", "Ad mediation", ["ads", "tracking"], 0.9),
             it("storekit", "StoreKit", "system", "Apple", "payment", "应用内购买", "In-app purchase", [], 0.95),
             it("weird", "libX|Y", "bundled_dylib", None, "other", "", "", [], 0.4)]
    return {"items": items, "unknown": [{"name": "libmystery.dylib", "kind": "bundled_dylib", "evidence": [ev("file", "Frameworks/libmystery.dylib", "contact " + EMAIL)], "hint": "maybe an obfuscator"},
                                         {"name": "ZZCore", "kind": "framework", "evidence": [], "hint": None}],
            "by_category": {"engine": 1, "analytics": 1, "ads": 1, "payment": 1, "other": 1}, "privacy_tags": {"ads": ["applovin"], "analytics": ["firebase"], "tracking": ["applovin"], "social": []}}


def _protect_unity() -> Dict[str, Any]:
    return {"fairplay": {"verdict": "no", "scope": "none", "encrypted_binaries": [], "total_binaries": 2, "main_encrypted": False, "sc_info_present": False},
            "codesign": {"signed": True, "team_id": "ABCDE12345", "signature_type": "apple_distribution", "get_task_allow": False, "entitlements_keys": ["application-identifier", "aps-environment"]},
            "hardening": {"main": {"pie": True, "stack_canary": True, "arc": True, "stripped": True}, "all": {"pie": True, "stack_canary": False, "arc": True, "stripped": True}},
            "antidebug": {"hits": [{"kind": "symbol", "ref": "ptrace"}]}, "jailbreak_detect": {"hits": [{"kind": "string", "ref": "/Applications/Cydia.app"}]}, "obfuscation": {}, "packer": {}}


def _unity_stages() -> List[StageResult]:
    ing = {"kind": "ipa", "path": HOME_PATH, "size": 734003200, "sha256": _sha("DemoGame"), "app_root": "Payload/DemoGame.app/", "app_name_dir": "DemoGame.app", "entries": 3120, "warnings": []}
    st = [
        StageResult.ok("ingest", ing, [], []),
        StageResult.ok("inventory", _unity_inventory()),
        StageResult.ok("meta", _meta_unity(), [
            F("meta.identity", "yes", 0.95, "App identity resolved", "bundle com.example.demogame", {"bundle_id": "com.example.demogame", "version": "1.2.3"}),
            F("meta.distribution", "yes", 0.9, "Distribution: appstore", params={"type": "appstore"}),
            F("meta.permissions", "yes", 0.9, "2 permission declarations", params={"count": 2}),
            F("meta.signature_integrity", "no", 0.8, "Signature resources intact", "812 files checked")]),
        StageResult.partial("macho", _macho_unity(), [F("macho.summary", "yes", 0.9, "2 Mach-O binaries parsed", params={"count": 2})],
                            ["UnityFramework: LC_DYLD_CHAINED_FIXUPS not parsed"], reason="1 binary had parse warnings"),
        StageResult.ok("engine.fingerprint", _fingerprint_unity(), [F("engine.fingerprint", "yes", 0.8, "Engine capability profile built", params={"render": "metal"}),
                                                                      F("engine.container.unknown", "n/a", 0.5, "No unknown containers")]),
        StageResult.ok("engine.detect", _detect_unity(), [
            F("engine.primary", "yes", 0.97, "Primary engine: Unity", params={"engine": "Unity"}, evidence=[E("file", "Frameworks/UnityFramework.framework")]),
            F("engine.language", "yes", 0.9, "Languages: C#, ObjC, Lua"), F("engine.custom", "no", 0.9, "No in-house engine indicated")]),
        StageResult.ok("engine.other", {"generic_scripts": {"scripts": {"lua": 121}}, "_checkers": {
            "cocos": {"status": "skipped", "reason": "not applicable", "error": None, "duration_s": 0.0},
            "generic_scripts": {"status": "ok", "reason": None, "error": None, "duration_s": 0.12}}}),
        StageResult.ok("engine.unity", _unity_data(), [
            F("unity.detected", "yes", 0.97, "Unity detected"), F("unity.version", "yes", 0.9, "Unity 2021.3.21f1", params={"version": "2021.3.21f1", "sources": ["globalgamemanagers", "unityfs_header"]}),
            F("unity.backend", "yes", 0.95, "Scripting backend: il2cpp", params={"backend": "il2cpp"}),
            F("unity.metadata.present", "yes", 0.95, "global-metadata.dat present"),
            F("unity.metadata.encrypted", "no", 0.85, "metadata looks intact", "magic, header and string region are consistent",
              evidence=[E("string", "mscorlib", "in string region")], remediation=""),
            F("unity.binary.fairplay", "no", 0.9, "UnityFramework is not FairPlay-encrypted"),
            F("unity.il2cpp.precheck", "yes", 0.9, "Dump preconditions met"),
            F("unity.il2cpp.dump", "yes", 0.9, "IL2CPP dump succeeded", params={"backend": "Il2CppDumper"}),
            F("unity.il2cpp.names_obfuscated", "no", 0.6, "Identifiers are not obfuscated"),
            F("unity.assetbundle.encryption", "suspected", 0.55, "A few AssetBundles look encrypted",
              "8 of 410 bundles are high-entropy without a known header (compressed is not encrypted)",
              evidence=[E("file", "Data/Raw/x/a.bin", "entropy 7.99"), E("file", "Data/Raw/x/b.bin", "entropy 7.98")],
              remediation="Check the loader for a custom decrypt hook.")]),
        StageResult.ok("engine.unity.hotfix", _hotfix_unity(), [
            F("unity.hotfix.framework", "yes", 0.9, "Hot-update frameworks: ToLua, HybridCLR, Addressables", params={"names": ["ToLua", "HybridCLR", "Addressables"]}),
            F("unity.hotfix.lua", "yes", 0.9, "Lua scripts found", params={"total": 121}),
            F("unity.hotfix.lua_version", "yes", 0.85, "Lua bytecode: LuaJIT 2.1", params={"versions": ["luajit_2.1"]}),
            F("unity.hotfix.csharp_dll", "yes", 0.8, "C# hot assembly found"),
            F("unity.hotfix.resource_update", "yes", 0.7, "Resource updates via Addressables"),
            F("unity.hotfix.script_protection", "suspected", 0.5, "C# hot assembly may be encrypted", "one blob has no PE header",
              evidence=[E("heuristic", "Blob", "high entropy, no PE header")])]),
        StageResult.ok("libs", _libs_unity(), [F("libs.summary", "yes", 0.9, "5 libraries identified", params={"count": 5}),
                                                F("libs.unknown", "unknown", 0.5, "2 libraries unidentified", params={"count": 2})]),
        StageResult.ok("protect", _protect_unity(), [
            F("protect.fairplay", "no", 0.9, "No FairPlay encryption", "all 2 binaries have cryptid=0"),
            F("protect.codesign", "yes", 0.9, "Signed", params={"team_id": "ABCDE12345"}),
            F("protect.stripped", "yes", 0.8, "Symbols stripped"),
            F("protect.antidebug", "suspected", 0.45, "Anti-debug traits", evidence=[E("symbol", "ptrace", "")]),
            F("protect.jailbreak_detect", "suspected", 0.4, "Jailbreak-detection traits", evidence=[E("string", "/Applications/Cydia.app", "")])]),
        StageResult.ok("classify", {"category": "game", "subcategory": None, "confidence": 0.95, "scores": {"game": 1.4, "utility": 0.1},
                                    "evidence": [ev("plist_key", "LSApplicationCategoryType", "public.app-category.games"), ev("heuristic", "engine=unity", "")], "runner_up": {"category": "utility", "score": 0.1}},
                       [F("classify.category", "yes", 0.95, "Category: game", params={"category": "game"})]),
        StageResult.ok("report", {}),
    ]
    return st


# --- scenario 2: in-house engine, many skipped / failed ---------------------------------------------
def _custom_stages() -> List[StageResult]:
    inv = _unity_inventory()
    inv["archives"] = [{"path": "Payload/Rogue.app/res/data0.npk", "size": 400000000, "magic": "unknown", "category": "packed_archive"}]
    ing = {"kind": "ipa", "path": "/Users/bob/ipas/Rogue.ipa", "size": 650000000, "sha256": _sha("Rogue"), "app_root": "Payload/Rogue.app/", "app_name_dir": "Rogue.app", "entries": 900, "warnings": []}
    fp = {"render": {"metal": {"id": "metal", "name": "Metal", "confidence": 0.9, "evidence": [ev("string", "CAMetalLayer")], "extra": {}}}, "shader_formats": [],
          "script_vms": [{"id": "lua", "name": "Lua", "confidence": 0.8, "evidence": [ev("string", "luaL_newstate")], "extra": {}}],
          "physics": [{"id": "box2d", "name": "Box2D", "confidence": 0.7, "evidence": [ev("string", "b2World")], "extra": {}}], "audio": [], "animation": [], "network": [],
          "asset_formats": [], "containers": [{"id": "Payload/Rogue.app/res/data0.npk", "name": "data0.npk", "confidence": 0.7, "evidence": [ev("heuristic", "header offsets monotonic")],
                                                "extra": {"size": 400000000, "magic": "unknown", "verdict": "encrypted_suspected", "compression": "none found", "entropy": 7.9, "xor_hypothesis": None}}],
          "host": {"thin_uikit_shell": None, "cpp_ratio": None, "objc_swift_ratio": None, "main_loop_hints": []},
          "summary_text": "Metal + Lua VM + Box2D + one custom container."}
    detect = {"primary": None, "candidates": [], "wrapper": None,
              "custom": {"verdict": "suspected", "confidence": 0.62,
                         "evidence": [ev("heuristic", "Metal + Lua VM + custom .npk container", "no known engine reached the threshold"),
                                      ev("heuristic", "res/*.npk", "file naming resembles packed archives of some in-house engines (lead, low confidence)")],
                         "profile_ref": "engine.fingerprint", "conditions": {"known_engine": False, "render_api": True, "script_vm": True, "custom_container": True},
                         "next_steps": [{"key": "engine.next.container", "params": {}, "text": "Inspect res/data0.npk header and index first."},
                                        {"key": "engine.next.lua", "params": {}, "text": "Look at the Lua loader in the main binary."}],
                         "deviations": ["no engine directory layout matched"], "open_source_base": []},
              "languages": [{"lang": "cpp", "confidence": 0.8, "evidence": []}, {"lang": "lua", "confidence": 0.7, "evidence": []}], "is_game_engine": True, "extra": {}}
    return [
        StageResult.ok("ingest", ing),
        StageResult.ok("inventory", inv),
        StageResult.failed("meta", "ValueError: Info.plist is not a valid property list"),
        StageResult.failed("macho", "struct.error: unpack requires a buffer of 4 bytes"),
        StageResult.partial("engine.fingerprint", fp, [F("engine.fingerprint", "yes", 0.7, "Engine capability profile built"),
                                                        F("engine.container.unknown", "suspected", 0.6, "One container looks encrypted or custom",
                                                          "compressed is not encrypted; internal structure decides", evidence=[E("file", "res/data0.npk", "entropy 7.9")])],
                            ["macho unavailable: symbol-based signals skipped"], reason="macho unavailable"),
        StageResult.ok("engine.detect", detect, [F("engine.custom", "suspected", 0.62, "Possibly an in-house engine", "Metal + Lua VM + custom container; no known engine matched",
                                                    evidence=[E("heuristic", "res/*.npk", "lead, low confidence")], remediation="Follow the suggested next steps.")]),
        StageResult.skipped("engine.other", "disabled by --skip"),
        StageResult.skipped("engine.unity", "unity not detected"),
        StageResult.skipped("engine.unity.hotfix", "dependency engine.unity skipped"),
        StageResult.partial("libs", {"items": [], "unknown": [{"name": "libcore.dylib", "kind": "bundled_dylib", "evidence": [], "hint": None}], "by_category": {}, "privacy_tags": {}},
                            [F("libs.unknown", "unknown", 0.5, "1 library unidentified")], ["macho unavailable: only file-based evidence used"], reason="macho unavailable"),
        StageResult.failed("protect", "KeyError: 'binaries'"),
        StageResult.ok("classify", {"category": "game", "subcategory": None, "confidence": 0.55, "scores": {"game": 0.9}, "evidence": [ev("heuristic", "metal + lua + physics", "")], "runner_up": None},
                       [F("classify.category", "suspected", 0.55, "Category: game", params={"category": "game"})]),
        StageResult.ok("report", {}),
    ]


# --- scenario 3: ingest only ---------------------------------------------------------------------------
def _ingest_only_stages() -> List[StageResult]:
    ing = {"kind": "zip", "path": "C:\\Users\\carol\\Desktop\\broken.zip", "size": 1024, "sha256": _sha("broken"), "app_root": "", "app_name_dir": "", "entries": 1, "warnings": ["no Info.plist found"]}
    return [
        StageResult.ok("ingest", ing, [], ["no Info.plist found"]),
        StageResult.failed("inventory", "OSError: [Errno 5] Input/output error"),
        StageResult.failed("meta", "plistlib.InvalidFileException: Invalid file"),
        StageResult.skipped("macho", "dependency inventory failed"),
        StageResult.skipped("engine.fingerprint", "dependency inventory failed"),
        StageResult.skipped("engine.detect", "dependency inventory failed"),
        StageResult.skipped("engine.other", "dependency engine.detect skipped"),
        StageResult.skipped("engine.unity", "dependency engine.detect skipped"),
        StageResult.skipped("engine.unity.hotfix", "dependency engine.unity skipped"),
        StageResult.skipped("libs", "dependency inventory failed"),
        StageResult.skipped("protect", "dependency inventory failed"),
        StageResult.skipped("classify", "not selected by --stages"),
        StageResult.ok("report", {}),
    ]


# --- scenario 4: Cocos2d-x Lua, FairPlay encrypted ------------------------------------------------------
def _cocos_stages() -> List[StageResult]:
    ing = {"kind": "ipa", "path": "/home/dave/work/CocosLua.ipa", "size": 120000000, "sha256": _sha("CocosLua"), "app_root": "Payload/CocosLua.app/", "app_name_dir": "CocosLua.app", "entries": 800, "warnings": []}
    meta = _meta_unity()
    meta["identity"] = {"names": [{"value": "Cocos Lua", "source": "CFBundleName", "lang": ""}], "selected_name": "Cocos Lua", "bundle_id": "com.example.cocoslua", "version": "2.0", "build": "20",
                        "executable": "CocosLua", "min_os": "11.0", "devices": ["iPhone"]}
    meta["fairplay_container"] = {"sc_info_present": True, "files": ["SC_Info/CocosLua.sinf"]}
    meta["provision"] = {"present": True, "name": "Dev profile", "team_id": "ZZZZZ99999", "team_name": "Example Ltd", "app_id_prefix": "ZZZZZ99999", "creation_date": "2025-01-01", "expiration_date": "2026-01-01",
                         "provisions_all_devices": False, "device_count": 2, "device_hash_prefixes": ["0123abcd", UDID_OLD], "entitlements": {}}
    meta["distribution"] = {"type": "development", "verdict": "suspected", "confidence": 0.5, "evidence": [ev("file", "embedded.mobileprovision", "get-task-allow=true; device %s; %s" % (UDID_NEW, UDID_OLD))]}
    meta["extensions"], meta["background_modes"] = [], []
    macho = _macho_unity()
    for b in macho["binaries"]:
        for s in b["slices"]:
            s.update({"encrypted": True, "cryptid": 1, "cryptsize": 4096})
    macho["binaries"] = macho["binaries"][:1]
    macho["summary"].update({"any_encrypted": True, "all_encrypted": True, "main_binary": "Payload/CocosLua.app/CocosLua"})
    macho["binaries"][0]["path"], macho["binaries"][0]["rel"] = "Payload/CocosLua.app/CocosLua", "CocosLua"
    prim = {"id": "cocos", "name": "Cocos2d-x", "family": "cocos", "kind": "game_engine", "confidence": 0.8, "confirmed": True, "signals_matched": ["string:cocos2d::"], "evidence": [ev("string", "cocos2d::Director")], "extra": {}}
    detect = {"primary": prim, "candidates": [prim], "wrapper": {"host": {"id": "cocos", "name": "Cocos2d-x", "confidence": 0.8}, "embedded": [{"id": "lua", "name": "Lua", "confidence": 0.7}]},
              "custom": {"verdict": "no", "confidence": 0.1, "evidence": [], "profile_ref": "engine.fingerprint", "conditions": {}, "next_steps": [], "deviations": [], "open_source_base": []},
              "languages": [{"lang": "cpp", "confidence": 0.8, "evidence": []}, {"lang": "lua", "confidence": 0.8, "evidence": []}], "is_game_engine": True, "extra": {}}
    cocos = {"variant": "cocos2d-x-lua", "version_hint": "3.x", "scripts": {
        "plain": 4, "bytecode": 0, "suspected_encrypted": 180, "counts": {".lua": 4, ".luac": 180}, "samples": ["src/app/MyApp.luac", "src/main.lua"],
        "lua": {"runtime_versions": [{"flavor": "luajit", "version": "2.1", "source": "native_string", "confidence": 0.5}], "bytecode": {"by_version": {}, "invalid": 180, "stripped_count": 0, "arch_bits": {}},
                "files": {"plain": 4, "bytecode": 0, "compressed": 0, "encrypted_suspected": 180, "total": 184}, "dialect_hints": [], "consistency": {"ok": True, "notes": []}, "custom_lua_suspected": True}},
        "resources": {"plist_atlas": 12, "csb": 40, "encrypted_suspected": 0}, "xxtea_hint": {"symbol_found": True, "sign_prefix": "XXTEA", "key_extracted": False},
        "bundles": []}
    return [
        StageResult.ok("ingest", ing),
        StageResult.ok("inventory", _unity_inventory()),
        StageResult.ok("meta", meta, [F("meta.identity", "yes", 0.9, "App identity resolved"), F("meta.distribution", "suspected", 0.5, "Distribution: development", params={"type": "development"}),
                                       F("meta.fairplay_container", "yes", 0.9, "SC_Info present", evidence=[E("file", "SC_Info/CocosLua.sinf")])]),
        StageResult.ok("macho", macho, [F("macho.summary", "yes", 0.9, "1 Mach-O binary parsed")]),
        StageResult.ok("engine.fingerprint", {"render": {"gles": {"id": "gles", "name": "OpenGL ES", "confidence": 0.8, "evidence": [], "extra": {}}}, "shader_formats": [], "script_vms": [{"id": "luajit", "name": "LuaJIT", "confidence": 0.5, "evidence": [], "extra": {}}],
                                              "physics": [], "audio": [], "animation": [], "network": [], "asset_formats": [], "containers": [], "host": {}, "summary_text": ""}, [F("engine.fingerprint", "yes", 0.6, "Engine capability profile built")]),
        StageResult.ok("engine.detect", detect, [F("engine.primary", "yes", 0.8, "Primary engine: Cocos2d-x"), F("engine.wrapper", "suspected", 0.5, "Cocos2d-x host with embedded Lua")]),
        StageResult.ok("engine.other", {"cocos": cocos, "_checkers": {"cocos": {"status": "ok", "reason": None, "error": None, "duration_s": 0.3},
                                                                       "egret": {"status": "skipped", "reason": "not applicable", "error": None, "duration_s": 0.0}}},
                       [F("engine.script.encrypted", "suspected", 0.7, "Lua scripts look XXTEA-encrypted", "180 of 184 scripts lack a valid Lua header; bytecode is not encryption but these are not bytecode either",
                          evidence=[E("symbol", "xxtea_decrypt", "")], remediation="Look for the sign/key setup in the engine init code.", tags=["engine:cocos"]),
                        F("engine.cocos.variant", "yes", 0.8, "Cocos2d-x Lua", tags=["engine:cocos"])]),
        StageResult.skipped("engine.unity", "unity not detected"),
        StageResult.skipped("engine.unity.hotfix", "dependency engine.unity skipped"),
        StageResult.ok("libs", {"items": _libs_unity()["items"][2:4], "unknown": [], "by_category": {"ads": 1, "payment": 1}, "privacy_tags": {"ads": ["applovin"], "analytics": [], "tracking": ["applovin"], "social": []}},
                       [F("libs.summary", "yes", 0.9, "2 libraries identified")]),
        StageResult.ok("protect", {"fairplay": {"verdict": "yes", "scope": "all", "encrypted_binaries": ["Payload/CocosLua.app/CocosLua"], "total_binaries": 1, "main_encrypted": True, "sc_info_present": True},
                                   "codesign": {"signed": True, "team_id": "ZZZZZ99999", "signature_type": "development", "get_task_allow": True, "entitlements_keys": []}, "hardening": {}, "antidebug": {"hits": []}, "jailbreak_detect": {"hits": []}, "obfuscation": {}, "packer": {}},
                       [F("protect.fairplay", "yes", 0.98, "FairPlay-encrypted", "cryptid=1 in every binary", evidence=[E("macho", "Payload/CocosLua.app/CocosLua", "cryptid=1")],
                          remediation="Provide an already-decrypted IPA to analyse the binary.")]),
        StageResult.ok("classify", {"category": "game", "subcategory": "casual", "confidence": 0.9, "scores": {"game": 1.2}, "evidence": [ev("heuristic", "engine=cocos", "")], "runner_up": None},
                       [F("classify.category", "yes", 0.9, "Category: game")]),
        StageResult.ok("report", {}),
    ]


@dataclass
class Fixture:
    name: str
    stages: List[StageResult]
    cfg_overrides: Dict[str, Any] = field(default_factory=dict)

    def config(self, out_dir: Path = None, **kw: Any) -> Config:
        cfg = Config()
        if out_dir is not None:
            cfg.output_dir = Path(out_dir)
        for k, v in {**self.cfg_overrides, **kw}.items():
            setattr(cfg, k, v)
        return cfg


def _fixtures() -> Dict[str, Callable[[], Fixture]]:
    return {
        "full_success": lambda: Fixture("full_success", _unity_stages()),
        "custom_engine": lambda: Fixture("custom_engine", _custom_stages(), {"skip": ("engine.other",)}),
        "ingest_only": lambda: Fixture("ingest_only", _ingest_only_stages(), {"stages": ("ingest",)}),
        "cocos_lua": lambda: Fixture("cocos_lua", _cocos_stages()),
    }


FIXTURE_NAMES = tuple(_fixtures())
FIXTURES = {n: f() for n, f in _fixtures().items()}


def get_fixture(name: str) -> Fixture:
    return _fixtures()[name]()      # fresh copy (stage data is mutated by some tests)


def populate_ctx(ctx: AnalysisContext, stages: List[StageResult]) -> AnalysisContext:
    """Fill ``ctx`` the way ``pipeline.run`` would (all stages but ``report``), so ``ReportStage`` can run on it."""
    for sr in stages:
        if sr.name == "report":
            continue
        sr = copy.deepcopy(sr)
        ctx.stage_results[sr.name] = sr
        if sr.status.value in ("ok", "partial"):
            ctx.results[sr.name] = sr.data
        ctx.findings.extend(sr.findings)
        for w in sr.warnings:
            ctx.warnings.append("[%s] %s" % (sr.name, w))
        if sr.duration_s == 0:
            sr.duration_s = 0.25
    ing = ctx.results.get("ingest") or {}
    if ing.get("sha256"):
        ctx.input_sha256 = ing["sha256"]
    return ctx


def build_ctx(name: str, out_dir: Path, **cfg_kw: Any) -> AnalysisContext:
    """A bound ``AnalysisContext`` populated with fixture ``name`` (output goes below ``out_dir``)."""
    fx = get_fixture(name)
    cfg = fx.config(out_dir, **cfg_kw)
    ing = next((s.data for s in fx.stages if s.name == "ingest"), {})
    ctx = AnalysisContext(cfg, Path(ing.get("path", "input.ipa")))
    ctx.bind_input(ing.get("sha256") or _sha(name), Path(str(ing.get("path", name)).replace("\\", "/")).stem)
    return populate_ctx(ctx, fx.stages)


def build_report(name: str, **cfg_kw: Any) -> Report:
    """The base report for fixture ``name`` exactly as ``pipeline.build_report`` + ``enrich_report`` produce it
    (fixed ``generated_at``; no redaction yet)."""
    from ipa_analyzer import pipeline
    from ipa_analyzer.report.summary import enrich_report

    fx = get_fixture(name)
    cfg = fx.config(**cfg_kw)
    ing = next((s.data for s in fx.stages if s.name == "ingest"), {})
    ctx = populate_ctx(AnalysisContext(cfg, Path(ing.get("path", "input.ipa"))), fx.stages)
    report = pipeline.build_report(ctx, list(ctx.stage_results.values()) + [fx.stages[-1]])
    enrich_report(report, ctx.results)
    report.generated_at = GENERATED_AT
    return report


def full_success_report() -> Report:
    return build_report("full_success")


def custom_engine_report() -> Report:
    return build_report("custom_engine")


def ingest_only_report() -> Report:
    return build_report("ingest_only")


def cocos_lua_report() -> Report:
    return build_report("cocos_lua")


# Localised finding texts for the ids used above (zh / en). Real texts live in the WPs' own i18n files; tests
# build a catalog from this dict so rendering never depends on which WPs have shipped their files.
SAMPLE_I18N: Dict[str, Dict[str, Any]] = {
    "zh": {
        "unity.version": {"title": "Unity 版本", "summary": "识别为 Unity {version}(来源:{sources})"},
        "unity.assetbundle.encryption": {"title": "AssetBundle 加密", "summary": "部分 bundle 无已知头且高熵(压缩 ≠ 加密)", "remediation": "检查加载器中是否有自定义解密钩子。"},
        "unity.metadata.encrypted": {"title": "global-metadata 加密/魔改", "summary": "magic、头部与字符串区自洽"},
        "protect.fairplay": {"title": "FairPlay 加密", "summary": "二进制是否被 FairPlay 加密", "remediation": "请提供已解密的 IPA。"},
        "engine.custom": {"title": "自研引擎判定", "summary": "无已知引擎达到阈值,渲染+脚本 VM+自定义容器命中"},
        "engine.script.encrypted": {"title": "脚本加密", "summary": "Lua 脚本疑似 XXTEA 加密"},
        "libs.summary": {"title": "已识别 {count} 个库"},
        "classify.category": {"title": "项目类型:{category}"},
    },
    "en": {
        "unity.version": {"title": "Unity version", "summary": "Detected Unity {version} (sources: {sources})"},
        "protect.fairplay": {"title": "FairPlay encryption", "summary": "Whether binaries are FairPlay-encrypted", "remediation": "Provide a decrypted IPA."},
        "libs.summary": {"title": "{count} libraries identified"},
    },
}


# --- rendering test helpers ----------------------------------------------------------------------------
CHAPTERS = ["## 1.", "## 2.", "## 3.", "## 4.", "## 5.", "## 6.", "## 7.", "## 8.", "## 9.", "## 10."]
SUBSECTIONS = ["### 8.1", "### 8.2", "#### 8.2.1", "### 8.3"]
LEAK_PATTERN = r"\bNone\b|\{\}|\[\]|\{'|\['|\bnan\b|\bTrue\b|\bFalse\b"


def make_catalog(lang: str):
    """Catalog from ``data/i18n/<lang>/report.json`` plus ``SAMPLE_I18N`` (independent of other WPs' files)."""
    from ipa_analyzer.report import load_catalog

    cat = load_catalog(lang, modules=["report"])
    cat.tables.setdefault(lang, {}).update(SAMPLE_I18N.get(lang, {}))
    return cat


def report_dict(name: str) -> Dict[str, Any]:
    from ipa_analyzer.report import canonicalize

    return canonicalize(build_report(name).to_dict())


def render(name: str, lang: str) -> str:
    from ipa_analyzer.report import render_markdown

    rd = report_dict(name)
    return render_markdown(rd, make_catalog(lang), summary=rd.get("summary"))


def table_blocks(md: str) -> List[List[str]]:
    """Contiguous runs of table lines outside code fences."""
    blocks: List[List[str]] = []
    cur: List[str] = []
    fenced = False
    for ln in md.split("\n"):
        if ln.startswith("```"):
            fenced = not fenced
        if not fenced and ln.startswith("|"):
            cur.append(ln)
        elif cur:
            blocks.append(cur)
            cur = []
    if cur:
        blocks.append(cur)
    return blocks


def assert_tables_consistent(md: str) -> int:
    """Every table has the same cell count on every row; returns the number of tables."""
    from ipa_analyzer.report.render_md import split_row

    n = 0
    for block in table_blocks(md):
        widths = {len(split_row(ln)) for ln in block}
        assert len(widths) == 1, "inconsistent column counts %s in table starting %r" % (sorted(widths), block[0][:80])
        n += 1
    return n
