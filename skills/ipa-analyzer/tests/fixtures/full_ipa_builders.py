"""Whole-package synthetic IPAs for the end-to-end tests (WP9). Nothing here is, or is derived from, a real app.

Every fixture is composed from the per-WP builders (``ipa_builder``, ``macho_builder``, ``unity_builder``,
``unity_hotfix_builder``, ``engine_builder``, ``engine_checker_builder``)::

    FIXTURES                     {name: FixtureSpec}   (name == file stem, e.g. "unity_il2cpp_plain")
    build_fixture(name, dest_dir) -> Path               # ``<dest_dir>/<name>.ipa``
    build_all(dest_dir)          -> {name: Path}
    DUMPER_SCRIPT                path of the fake Il2CppDumper (pass it as ``--il2cpp-tool``)

Everything is deterministic: the same call writes byte-identical files.
"""
from __future__ import annotations

import json
import plistlib
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Union

from fixtures import engine_checker_builder as ecb
from fixtures import formats_builder as fb
from fixtures import unity_builder as ub
from fixtures import unity_hotfix_builder as uh
from fixtures.engine_builder import SynthApp, custom_engine_app, synth_for_engine, write_app
from fixtures.fake_dumper import __file__ as _FAKE_DUMPER_FILE
from fixtures.ipa_builder import build_ipa
from fixtures.macho_builder import build_macho

__all__ = ["FIXTURES", "FixtureSpec", "build_fixture", "build_all", "DUMPER_SCRIPT", "STR_LUA_53"]

DUMPER_SCRIPT = Path(_FAKE_DUMPER_FILE).resolve()
STR_LUA_53 = "Lua 5.3.6  Copyright (C) 1994-2020 Lua.org, PUC-Rio"
_ENGINE_DIR = Path(__file__).resolve().parents[2] / "data" / "engines"
_UIKIT = "/System/Library/Frameworks/UIKit.framework/UIKit"
_METAL = "/System/Library/Frameworks/Metal.framework/Metal"
Builder = Callable[[Path], Path]


@dataclass(frozen=True)
class FixtureSpec:
    name: str
    description: str
    build: Builder


def _urandom(n: int, seed: int = 1) -> bytes:
    return random.Random(seed).randbytes(n) if hasattr(random.Random, "randbytes") else bytes(
        random.Random(seed).getrandbits(8) for _ in range(n))


def _engine_json(engine_id: str) -> Dict[str, Any]:
    return json.loads((_ENGINE_DIR / (engine_id + ".json")).read_text(encoding="utf-8"))


# ------------------------------------------------------------------------------------------------ Unity
UNITY_APP = "Game"


def _unity_shell(*, encrypted: bool = False) -> Dict[str, Any]:
    """Info.plist + a thin main executable (Unity iOS keeps a tiny launcher and puts the runtime in UnityFramework)."""
    plist = {"CFBundleExecutable": UNITY_APP, "CFBundleIdentifier": "com.example.unitygame", "CFBundleName": UNITY_APP,
             "CFBundleShortVersionString": "1.2.3", "CFBundleVersion": "45"}
    main = build_macho(arch="arm64", encrypted=encrypted, cryptid=1 if encrypted else 0, strings=["main"],
                       objc_classes=["AppDelegate", "UnityAppController"], dylibs=[_UIKIT, _METAL],
                       code_signature=True)
    return {"Info.plist": plistlib.dumps(plist), UNITY_APP: main}


def _write_unity(dest: Path, name: str, files: Dict[str, Any], **kw: Any) -> Path:
    return build_ipa(dest / (name + ".ipa"), files, app_name=UNITY_APP, **kw)


def _unity_il2cpp(dest: Path, name: str, *, encrypted: bool = False, metadata_variant: str = "normal",
                  bundles: Union[Dict[str, bytes], None] = None, metadata_version: int = 24) -> Path:
    files = ub.build_unity_app(backend="il2cpp", metadata_version=metadata_version, metadata_variant=metadata_variant,
                               encrypted_binary=encrypted, bundles=bundles)
    files.update(_unity_shell(encrypted=encrypted))
    return _write_unity(dest, name, files)


def _standard_bundles() -> Dict[str, bytes]:
    return {"Data/Raw/scene_%d.bundle" % i: ub.build_standard_bundle("lz4", seed=i) for i in range(1, 6)}


def _unity_il2cpp_plain(dest: Path) -> Path:
    return _unity_il2cpp(dest, "unity_il2cpp_plain", bundles=_standard_bundles())


def _unity_il2cpp_encrypted_binary(dest: Path) -> Path:
    return _unity_il2cpp(dest, "unity_il2cpp_encrypted_binary", encrypted=True, bundles=_standard_bundles())


def _unity_il2cpp_meta_xor(dest: Path) -> Path:
    variants = ub.build_bundle_variants()
    bundles = {"Data/Raw/hi_%d.bundle" % i: _urandom(70_000, 100 + i) for i in range(1, 5)}
    bundles["Data/Raw/ok.bundle"] = variants["standard"]
    return _unity_il2cpp(dest, "unity_il2cpp_meta_xor", metadata_variant="xor_strings", bundles=bundles)


def _unity_mono(dest: Path) -> Path:
    samples = ub.mono_samples()
    files = ub.build_unity_app(backend="mono", dlls={"Encrypted.dll": samples["random"], "Plain.dll": samples["good"]})
    files.update(_unity_shell())
    return _write_unity(dest, "unity_mono", files)


# -------------------------------------------------------------------------------------- Unity hot update
def _hotfix(dest: Path, name: str, **opts: Any) -> Path:
    """``build_hotfix_app`` with a readable (decrypted) UnityFramework so the native-symbol evidence is available."""
    opts.setdefault("encrypted_binary", False)
    identifiers = list(opts.get("identifiers", ()))
    files = uh.build_hotfix_app(**opts)
    if uh.META_REL in files:
        # the hot-update builder's metadata is only a look-alike; use the header-accurate one so that engine.unity
        # accepts it (otherwise the metadata string-table evidence path is never exercised end to end)
        files[uh.META_REL] = ub.build_metadata(31, "normal", extra_identifiers=identifiers)
    files["Info.plist"] = plistlib.dumps({"CFBundleExecutable": uh.APP_NAME, "CFBundleIdentifier": "com.example.hotgame",
                                          "CFBundleName": uh.APP_NAME, "CFBundleShortVersionString": "2.0",
                                          "CFBundleVersion": "7"})
    return build_ipa(dest / (name + ".ipa"), files, app_name=uh.APP_NAME)


def _pe(name: str, refs: Any = ("UnityEngine.CoreModule", "mscorlib"), types: int = 5) -> bytes:
    return fb.build_pe_cli(name, list(refs), types=types)


def _unity_hybridclr(dest: Path) -> Path:
    hot = uh.build_bundle([uh.textasset("HotUpdate.dll", _pe("HotUpdate"))])
    return _hotfix(dest, "unity_hybridclr",
                   identifiers=["HybridCLR", "HomologousImageMode", "LoadMetadataForAOTAssembly", "RuntimeApi"],
                   binary_strings=["_ZN9hybridclr7interpreter11InterpreterE"],
                   loose={"Data/Raw/mscorlib.dll.bytes": _pe("mscorlib", ()), "Data/Raw/System.dll.bytes": _pe("System", ("mscorlib",))},
                   bundles={"Data/Raw/hotupdate.bundle": hot})


def _unity_ilruntime(dest: Path) -> Path:
    return _hotfix(dest, "unity_ilruntime", identifiers=["ILRuntime", "ILRuntime.Runtime.Enviorment", "CLRBindings"],
                   loose={"Data/Raw/Hotfix.dll.bytes": _pe("Hotfix", ("UnityEngine.CoreModule", "mscorlib", "ILRuntime"))})


def _unity_xlua_lua53(dest: Path) -> Path:
    scripts = uh.build_bundle([uh.textasset("Main.lua", uh.lua_chunk("5.3")), uh.textasset("Util.lua", uh.lua_chunk("5.3"))])
    return _hotfix(dest, "unity_xlua_lua53", identifiers=["XLua", "XLua.LuaDLL"],
                   binary_strings=["_xlua_pushcsobj", "_luaopen_xlua", STR_LUA_53],
                   bundles={"Data/Raw/lua_scripts.bundle": scripts})


def _unity_tolua_luajit(dest: Path) -> Path:
    scripts = uh.build_bundle([uh.textasset("Main.lua", uh.lua_chunk("luajit2.1", bits=64, strip=True))])
    return _hotfix(dest, "unity_tolua_luajit", identifiers=["LuaInterface", "LuaFileUtils", "LuaState", "LuaClient"],
                   binary_strings=["LuaJIT 2.1.0-beta3"], bundles={"Data/Raw/lua.bundle": scripts})


def _unity_lua_mixed_versions(dest: Path) -> Path:
    loose = {"Data/Raw/Lua/a.lua.bytes": uh.lua_chunk("5.1", bits=32), "Data/Raw/Lua/b.lua.bytes": uh.lua_chunk("5.4"),
             "Data/Raw/Lua/c.lua.bytes": uh.lua_chunk("5.4"), "Data/Raw/Lua/d.lua.bytes": uh.lua_chunk("5.1", bits=32)}
    return _hotfix(dest, "unity_lua_mixed_versions", identifiers=["XLua"], binary_strings=[STR_LUA_53], loose=loose)


def _unity_lua_tampered(dest: Path) -> Path:
    xor = bytes(b ^ 0x5A for b in uh.lua_chunk("5.3"))
    loose = {"Data/Raw/Lua/a.lua.bytes": uh.lua_chunk("5.3", tamper="luac_int"), "Data/Raw/Lua/b.lua.bytes": xor,
             "Data/Raw/Lua/c.lua.bytes": _urandom(5000, 9)}
    return _hotfix(dest, "unity_lua_tampered", identifiers=["XLua"], loose=loose)


def _unity_puerts_quickjs(dest: Path) -> Path:
    return _hotfix(dest, "unity_puerts_quickjs", identifiers=["Puerts", "BackendQuickJS", "JsEnv"],
                   binary_strings=["_JS_NewRuntime", "_JS_NewContext"],
                   loose={"Data/Raw/js/main.js.txt": "const a = 1;\nfunction f(x) { return x + a; }\nmodule.exports = f;\n"})


def _unity_addressables_remote(dest: Path) -> Path:
    settings = json.dumps({"m_AddressablesVersion": "1.21.2"})
    catalog = json.dumps({"m_InternalIds": ["https://cdn.example-game.net/assets/aa/iOS/a.bundle"]})
    return _hotfix(dest, "unity_addressables_remote",
                   identifiers=["UnityEngine.AddressableAssets", "UnityEngine.ResourceManagement.ResourceProviders"],
                   literals=["https://cdn.example-game.net/assets/aa/iOS/catalog_1.0.json"],
                   extra={"Data/Raw/aa/settings.json": settings, "Data/Raw/aa/catalog_1.0.json": catalog})


def _unity_hotdll_encrypted(dest: Path) -> Path:
    xor = bytes(b ^ 0x5A for b in _pe("XorHot"))
    return _hotfix(dest, "unity_hotdll_encrypted", identifiers=["HybridCLR", "HomologousImageMode"],
                   loose={"Data/Raw/HotUpdate.dll.bytes": _urandom(9000, 3), "Data/Raw/Hot2.dll.bytes": xor})


# ---------------------------------------------------------------------------------- native / media / flutter
def _native_swift_app(dest: Path) -> Path:
    fw = lambda n: build_macho(arch="arm64", filetype="dylib", strings=[n], code_signature=True)    # noqa: E731
    files: Dict[str, Any] = {
        "Frameworks/FirebaseCore.framework/FirebaseCore": fw("FirebaseCore"),
        "Frameworks/FirebaseAnalytics.framework/FirebaseAnalytics": fw("FirebaseAnalytics"),
        "Frameworks/AppsFlyerLib.framework/AppsFlyerLib": fw("AppsFlyerLib"),
        "GoogleService-Info.plist": plistlib.dumps({"GOOGLE_APP_ID": "1:123:ios:abc", "PROJECT_ID": "demo"}),
        "Assets.car": b"BOMStore" + b"\0" * 64, "Base.lproj/Main.storyboardc/Info.plist": b"bplist00",
        "icon.png": b"\x89PNG\r\n\x1a\n" + b"\0" * 64,
    }
    app = SynthApp(files=files, objc_classes=["AppDelegate", "SceneDelegate"],
                   dylibs=["/System/Library/Frameworks/SwiftUI.framework/SwiftUI", _UIKIT,
                           "@rpath/libswiftCore.dylib", "@rpath/FirebaseCore.framework/FirebaseCore",
                           "@rpath/AppsFlyerLib.framework/AppsFlyerLib"],
                   symbols=["_$s7SwiftUI4ViewP"], macho_extra={"swift": True, "code_signature": True},
                   plist={"NSLocationWhenInUseUsageDescription": "Show nearby stores", "UIRequiredDeviceCapabilities": ["arm64"],
                          "UIApplicationSceneManifest": {}, "LSApplicationCategoryType": "public.app-category.shopping"})
    return write_app(dest / "native_swift_app.ipa", app, app_name="Shop", plist_extra={"CFBundleName": "Shop"})


def _media_app(dest: Path) -> Path:
    app = SynthApp(files={"Base.lproj/Main.storyboardc/Info.plist": b"bplist00", "icon.png": b"\x89PNG\r\n\x1a\n" + b"\0" * 64,
                          "Resources/track1.mp3": b"ID3\x03\x00\x00\x00\x00\x00\x00" + _urandom(4000, 31),
                          "Resources/intro.mp4": b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 12 + _urandom(3000, 32)},
                   objc_classes=["AppDelegate", "PlayerViewController"],
                   dylibs=[_UIKIT, "/System/Library/Frameworks/AVFoundation.framework/AVFoundation",
                           "/System/Library/Frameworks/MediaPlayer.framework/MediaPlayer",
                           "/System/Library/Frameworks/AVKit.framework/AVKit"],
                   plist={"LSApplicationCategoryType": "public.app-category.music", "UIBackgroundModes": ["audio"]})
    itunes = plistlib.dumps({"itemName": "Tunes", "genre": "Music", "genreId": 6011, "artistName": "Example Studio",
                             "apple-id": "someone@private-mail.example", "userName": "Secret Person Name"})
    return _write_app(dest / "media_app.ipa", app, app_name="Tunes", plist_extra={"CFBundleName": "Tunes"},
                      raw_files={"iTunesMetadata.plist": itunes})


def _write_app(path: Path, app: SynthApp, *, app_name: str, plist_extra: Dict[str, Any],
               raw_files: Dict[str, bytes]) -> Path:
    """Like ``engine_builder.write_app`` but with extra archive-level files (e.g. ``iTunesMetadata.plist``)."""
    plist = {"CFBundleExecutable": app_name, "CFBundleIdentifier": "com.example.%s" % app_name.lower()}
    plist.update(app.plist)
    plist.update(plist_extra)
    kw: Dict[str, Any] = dict(arch="arm64", dylibs=app.dylibs, strings=app.strings, objc_classes=app.objc_classes,
                              symbols=app.symbols, imports=app.imports, stripped="local")
    kw.update(app.macho_extra)
    files: Dict[str, Any] = dict(app.files)
    files["Info.plist"] = plistlib.dumps(plist)
    files[app_name] = build_macho(**kw)
    return build_ipa(path, files, app_name=app_name, raw_files=raw_files)


def _flutter_app(dest: Path) -> Path:
    app = synth_for_engine(_engine_json("flutter"))
    app.files.update({k: v for k, v in ecb.flutter_files(aot=True).items() if k not in app.files})
    return write_app(dest / "flutter_app.ipa", app, app_name="FlutterApp")


# ------------------------------------------------------------------------------------------- engines
def _engine_app(engine_id: str, files: Dict[str, Any], *, app_name: str) -> SynthApp:
    app = synth_for_engine(_engine_json(engine_id))
    for k, v in files.items():
        app.files[k] = v if isinstance(v, bytes) else str(v).encode("utf-8")
    return app


def _cocos(dest: Path, name: str, engine_id: str, files: Dict[str, Any]) -> Path:
    return write_app(dest / (name + ".ipa"), _engine_app(engine_id, files, app_name="CocosGame"), app_name="CocosGame")


def _custom_engine(dest: Path) -> Path:
    return write_app(dest / "custom_engine.ipa", custom_engine_app(), app_name="Mystic")


def _cocos_cpp_lua_plain(dest: Path) -> Path:
    return _cocos(dest, "cocos_cpp_lua_plain", "cocos2dx_lua", ecb.cocos2dx_lua_files("plain"))


def _cocos_lua_xxtea(dest: Path) -> Path:
    return _cocos(dest, "cocos_lua_xxtea", "cocos2dx_lua", ecb.cocos2dx_lua_files("xxtea"))


def _cocos_js_jsc(dest: Path) -> Path:
    return _cocos(dest, "cocos_js_jsc", "cocos2dx_js", ecb.cocos2dx_js_files(jsc=True))


def _cocos_creator3(dest: Path) -> Path:
    return _cocos(dest, "cocos_creator3", "cocos_creator_3x", ecb.cocos_creator3x_files())


def _cocos_creator3_wrapped(dest: Path) -> Path:
    """Cocos Creator 3.x whose resources are re-packed with a custom 4-byte header (a *known* engine, not a custom one)."""
    return _cocos(dest, "cocos_creator3_wrapped", "cocos_creator_3x", ecb.cocos_creator3x_files(wrapped=True))


def _egret_app(dest: Path) -> Path:
    return _cocos(dest, "egret_app", "egret", ecb.egret_files())


def _laya_app(dest: Path) -> Path:
    return _cocos(dest, "laya_app", "layaair", ecb.laya_files())


# ------------------------------------------------------------------------------------------------ broken
def _good_small_ipa(dest: Path, name: str) -> Path:
    files = {"Info.plist": plistlib.dumps({"CFBundleExecutable": "Small", "CFBundleIdentifier": "com.example.small"}),
             "Small": build_macho(arch="arm64", strings=["x"]), "data.bin": _urandom(20_000, 5)}
    return build_ipa(dest / (name + ".ipa"), files, app_name="Small")


def _broken_truncated(dest: Path) -> Path:
    full = _good_small_ipa(dest, "_full_tmp")
    data = full.read_bytes()
    full.unlink()
    out = dest / "broken_truncated.ipa"
    out.write_bytes(data[: len(data) // 2])
    return out


def _broken_not_zip(dest: Path) -> Path:
    out = dest / "broken_not_zip.ipa"
    out.write_bytes(b"This is plain text, not a zip archive.\n" * 50)
    return out


def _broken_no_payload(dest: Path) -> Path:
    return build_ipa(dest / "broken_no_payload.ipa", {}, payload=False,
                     raw_files={"readme.txt": b"no app inside", "docs/a.bin": _urandom(500, 2)})


def _broken_zipslip(dest: Path) -> Path:
    files = {"Info.plist": plistlib.dumps({"CFBundleExecutable": "Slip", "CFBundleIdentifier": "com.example.slip"}),
             "Slip": build_macho(arch="arm64", strings=["x"])}
    raw = {"Payload/../../evil.txt": b"escape", "Payload/Slip.app/../../../evil2.txt": b"escape2",
           "/abs/evil3.txt": b"abs", "Payload/Slip.app/res\\..\\..\\evil4.txt": b"backslash"}
    return build_ipa(dest / "broken_zipslip.ipa", files, app_name="Slip", raw_files=raw)


_SPECS: List[FixtureSpec] = [
    FixtureSpec("unity_il2cpp_plain", "Unity IL2CPP, normal metadata v24, standard bundles, decrypted UnityFramework", _unity_il2cpp_plain),
    FixtureSpec("unity_il2cpp_encrypted_binary", "Unity IL2CPP with cryptid=1 binaries", _unity_il2cpp_encrypted_binary),
    FixtureSpec("unity_il2cpp_meta_xor", "Unity IL2CPP, XORed metadata strings, high-entropy bundles", _unity_il2cpp_meta_xor),
    FixtureSpec("unity_mono", "Unity Mono with one valid and one non-PE (encrypted) DLL", _unity_mono),
    FixtureSpec("native_swift_app", "SwiftUI app with Firebase + AppsFlyer frameworks", _native_swift_app),
    FixtureSpec("unity_hybridclr", "Unity + HybridCLR (hot DLL in a bundle, AOT metadata DLLs loose)", _unity_hybridclr),
    FixtureSpec("unity_ilruntime", "Unity + ILRuntime (loose Hotfix.dll.bytes)", _unity_ilruntime),
    FixtureSpec("unity_xlua_lua53", "Unity + xLua, Lua 5.3 bytecode in a bundle", _unity_xlua_lua53),
    FixtureSpec("unity_tolua_luajit", "Unity + ToLua, LuaJIT 2.1 bytecode in a bundle", _unity_tolua_luajit),
    FixtureSpec("unity_lua_mixed_versions", "Unity Lua bytecode 5.1 + 5.4 mixed, runtime string says 5.3", _unity_lua_mixed_versions),
    FixtureSpec("unity_lua_tampered", "Unity Lua chunks with a tampered header / XORed / random bytes", _unity_lua_tampered),
    FixtureSpec("unity_puerts_quickjs", "Unity + puerts (QuickJS backend), plain JS", _unity_puerts_quickjs),
    FixtureSpec("unity_addressables_remote", "Unity + Addressables with a remote catalog on a CDN", _unity_addressables_remote),
    FixtureSpec("unity_hotdll_encrypted", "Unity + HybridCLR whose hot DLLs are not PE (random / XOR)", _unity_hotdll_encrypted),
    FixtureSpec("custom_engine", "Self-made engine: thin UIKit shell, Metal, Lua, Box2D, custom .pak, random .dat", _custom_engine),
    FixtureSpec("cocos_cpp_lua_plain", "cocos2d-x Lua, plain .lua", _cocos_cpp_lua_plain),
    FixtureSpec("cocos_lua_xxtea", "cocos2d-x Lua with xxtea-looking scripts", _cocos_lua_xxtea),
    FixtureSpec("cocos_js_jsc", "cocos2d-x JS with .jsc", _cocos_js_jsc),
    FixtureSpec("cocos_creator3", "Cocos Creator 3.x, plain scripts", _cocos_creator3),
    FixtureSpec("cocos_creator3_wrapped", "Cocos Creator 3.x with custom-wrapped resource files (SeaWorld-like)", _cocos_creator3_wrapped),
    FixtureSpec("egret_app", "Egret native runtime", _egret_app),
    FixtureSpec("laya_app", "LayaAir native runtime", _laya_app),
    FixtureSpec("flutter_app", "Flutter AOT app", _flutter_app),
    FixtureSpec("media_app", "Music / video player with iTunesMetadata (purchaser fields to be redacted)", _media_app),
    FixtureSpec("broken_truncated", "Valid IPA cut in half", _broken_truncated),
    FixtureSpec("broken_not_zip", "Text file named .ipa", _broken_not_zip),
    FixtureSpec("broken_no_payload", "Zip without Payload/", _broken_no_payload),
    FixtureSpec("broken_zipslip", "Valid app plus zip-slip / absolute / backslash entry names", _broken_zipslip),
]
FIXTURES: Dict[str, FixtureSpec] = {s.name: s for s in _SPECS}


def build_fixture(name: str, dest_dir: Union[str, Path]) -> Path:
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    return FIXTURES[name].build(dest)


def build_all(dest_dir: Union[str, Path]) -> Dict[str, Path]:
    return {name: build_fixture(name, dest_dir) for name in FIXTURES}


def build_unity_variant(dest_dir: Union[str, Path], name: str, *, metadata_variant: str = "normal",
                        bundle_variant: str = "standard", n_bundles: int = 5) -> Path:
    """Unity IL2CPP app with the given metadata variant (``unity_builder.METADATA_VARIANTS``) and ``n_bundles`` copies of
    one bundle variant (``standard | standard_lzma | offset_prefix | xor_single | xor_repeating | high_entropy`` ...)."""
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    blob = ub.build_bundle_variants()[bundle_variant]
    bundles = {"Data/Raw/b%d.bundle" % i: blob + bytes([i]) * 0 for i in range(n_bundles)}
    if bundle_variant == "high_entropy":
        bundles = {"Data/Raw/b%d.bundle" % i: _urandom(len(blob) + 60_000, 40 + i) for i in range(n_bundles)}
    return _unity_il2cpp(dest, name, metadata_variant=metadata_variant, bundles=bundles)
