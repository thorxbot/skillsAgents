"""Synthetic app bundles for the engine checker tests (no real app content anywhere, all deterministic).

Entry points::

    make_ctx(tmp_path, files, *, detect=(), custom=None, app_name="Test", macho=True) -> AnalysisContext
        build an IPA from ``files`` (names relative to the .app), run ``ingest`` / ``inventory`` / ``macho`` and put a
        stub ``engine.detect`` result (candidates ``detect``) into ``ctx.results``.
    detect_stub(*ids, custom=None) -> DetectResult
    <engine>_files(...)  -> {name: bytes}   fixture file sets (cocos_*, egret_files, laya_files, unreal_files, ...)

Binary formats written here: CCZ headers, Unreal pak footers / IoStore headers, Godot pck, Hermes header, Defold
``.arci``, GameMaker FORM, zip with the encryption flag.  Payloads are random bytes (``rand``) -- the checkers
only ever look at headers, entropy and structure.
"""
from __future__ import annotations

import io
import random
import struct
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence, Tuple

from fixtures.formats_builder import build_lua_bytecode, build_pe_cli
from fixtures.ipa_builder import build_ipa
from fixtures.macho_builder import build_macho
from ipa_analyzer.analyzers.ingest_stage import IngestStage
from ipa_analyzer.analyzers.inventory import InventoryStage
from ipa_analyzer.analyzers.macho_stage import MachoStage
from ipa_analyzer.config import Config
from ipa_analyzer.context import AnalysisContext
from ipa_analyzer.engines.api import DetectResult, EngineMatch

INFO_PLIST = (b'<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleExecutable</key>'
              b"<string>%s</string></dict></plist>")


def rand(n: int, seed: int = 1) -> bytes:
    """Deterministic high-entropy bytes."""
    return random.Random(seed).randbytes(n)


def detect_stub(*ids: str, custom: Optional[Dict[str, Any]] = None, confidence: float = 0.9) -> DetectResult:
    cands = [EngineMatch(i, name=i, confidence=confidence, confirmed=True) for i in ids]
    return DetectResult(primary=cands[0] if cands else None, candidates=cands,
                        custom=custom or {"verdict": "unknown", "confidence": 0.0}, is_game_engine=bool(ids))


def make_ctx(tmp_path: Path, files: Dict[str, Any], *, detect: Iterable[str] = (), custom: Optional[Dict[str, Any]] = None,
             app_name: str = "Test", macho: bool = True, main_binary: Optional[bytes] = None) -> AnalysisContext:
    files = dict(files)
    files.setdefault("Info.plist", INFO_PLIST % app_name.encode())
    files.setdefault(app_name, main_binary if main_binary is not None else build_macho(strings=["hello"]))
    ipa = build_ipa(tmp_path / "t.ipa", files, app_name=app_name)
    ctx = AnalysisContext(Config(output_dir=tmp_path / "out"), ipa)
    ctx.results["ingest"] = IngestStage().run(ctx).data
    ctx.results["inventory"] = InventoryStage().run(ctx).data
    if macho:
        ctx.results["macho"] = MachoStage().run(ctx).data
    ctx.results["engine.detect"] = detect_stub(*detect, custom=custom).to_dict()
    return ctx


# --------------------------------------------------------------------------------------------- scripts
LUA_PLAIN = "local M = {}\nfunction M.run(x)\n  return x + 1\nend\nreturn M\n" * 20
LUA53_PLAIN = LUA_PLAIN + "local y = 7 // 2\nlocal z = 1 << 3\n"
JS_PLAIN = "System.register([], function (_export) {\n  'use strict';\n  return { execute: function () {} };\n});\n" * 10
JS_MINIFIED = "var a=function(){" + "return 1+2;" * 400 + "};"


def xxtea_like(plain_len: int, seed: int, sign: bytes = b"XXTEA") -> bytes:
    """Sign + random bytes with the xxtea-c ciphertext length ``(ceil(n/4)+1)*4`` (NOT real XXTEA)."""
    n = ((plain_len + 3) // 4 + 1) * 4
    return sign + rand(n, seed)


# ----------------------------------------------------------------------------------------------- cocos
def ccz_bytes(*, encrypted: bool, size: int = 400, seed: int = 3, version: int = 0, comp: int = 0) -> bytes:
    sig = b"CCZp" if encrypted else b"CCZ!"
    body = rand(size, seed) if encrypted else b"\x78\x9c" + rand(size, seed)
    return sig + struct.pack(">HHII", comp, version, 0, 4096) + body


def cocos_creator3x_files(*, encrypted_js: bool = False, jsc: bool = False, wrapped: bool = False) -> Dict[str, Any]:
    f: Dict[str, Any] = {
        "application.js": JS_PLAIN, "main.js": JS_PLAIN, "jsb-adapter/engine-adapter.js": JS_PLAIN,
        "src/settings.json": '{"CocosEngine":"3.8.2","engine":{}}', "src/import-map.json": '{"imports":{}}',
        "src/system.bundle.js": JS_PLAIN,
        "assets/main/config.abc12.json": '{"name":"main","deps":[],"uuids":["a","b"],"scenes":{},"packs":{}}',
        "assets/main/index.js": JS_PLAIN, "assets/main/import/07/073def.json": '{"__type__":"cc.Prefab"}',
        "assets/main/native/e0/e0f3.png": b"\x89PNG\r\n\x1a\n" + rand(300, 4),
        "assets/resources/import/aa/aa11.json": "{}", "assets/resources/native/aa/aa11.png": b"\x89PNG\r\n\x1a\n" + rand(200, 5),
    }
    if jsc:
        f.pop("src/system.bundle.js")
        f["src/system.bundle.jsc"] = rand(2048, 6)
        f["assets/main/index.jsc"] = rand(1024, 7)
        f.pop("assets/main/index.js")
    if encrypted_js:
        for i in range(10):
            f["assets/b%d/index.js" % i] = xxtea_like(900 + 4 * i, 20 + i)
            f["assets/b%d/import/aa/x%d.json" % (i, i)] = "{}"
    if wrapped:
        for i in range(12):
            body = rand(600 + i, 50 + i)
            size = 16 + len(body)
            f["assets/w%d/import/aa/f%d.json" % (i, i)] = b"NHPK" + struct.pack("<II", size, 7) + b"\x14\x89\x13\xc1" + body
            f["assets/w%d/index.js" % i] = b"NHPK" + struct.pack("<II", size, 9) + b"\x14\x89\x13\xc1" + body
    return f


def cocos_creator2x_files(*, jsc: bool = False) -> Dict[str, Any]:
    ext = ".jsc" if jsc else ".js"
    mk = (lambda seed: rand(1500, seed)) if jsc else (lambda seed: JS_PLAIN)
    return {"main" + ext: mk(1), "src/settings" + ext: mk(2), "src/project" + ext: mk(3), "jsb-adapter/jsb-engine.js": JS_PLAIN,
            "res/import/12/12ab.json": "{}", "res/raw-assets/34/34cd.png": b"\x89PNG\r\n\x1a\n" + rand(200, 8),
            "project.json": '{"engine":"cocos2d-js"}'}


def cocos2dx_lua_files(mode: str = "plain") -> Dict[str, Any]:
    """``mode``: plain | luac51 | luac53 | luajit | xxtea | mixed"""
    base: Dict[str, Any] = {"src/config.lua": "CC_USE_FRAMEWORK = true\n", "res/logo.png": b"\x89PNG\r\n\x1a\n" + rand(100, 9),
                            "src/cocos/init.lua": LUA_PLAIN}
    names = ["src/main", "src/app/MyApp", "src/app/views/MainScene", "src/app/views/Menu", "src/app/models/Player"]
    for i, n in enumerate(names):
        if mode == "plain":
            base[n + ".lua"] = LUA_PLAIN
        elif mode == "luac51":
            base[n + ".luac"] = build_lua_bytecode("5.1") + rand(200, i)
        elif mode == "luac53":
            base[n + ".luac"] = build_lua_bytecode("5.3") + rand(200, i)
        elif mode == "luajit":
            base[n + ".luac"] = build_lua_bytecode("luajit2.1") + rand(200, i)
        elif mode == "xxtea":
            base[n + ".lua"] = xxtea_like(1000 + 8 * i, 30 + i)
        elif mode == "mixed":
            base[n + (".lua" if i % 2 else ".luac")] = LUA_PLAIN if i % 2 else build_lua_bytecode("5.1") + rand(100, i)
    if mode == "xxtea":
        base.pop("src/cocos/init.lua", None)
    return base


def cocos2dx_js_files(*, jsc: bool = False) -> Dict[str, Any]:
    ext = ".jsc" if jsc else ".js"
    mk = (lambda s: rand(1200, s)) if jsc else (lambda s: JS_PLAIN)
    return {"main" + ext: mk(1), "project.json": '{"project_type":"javascript","jsList":["src/app.js"]}',
            "script/jsb_boot" + ext: mk(2), "src/app" + ext: mk(3), "src/resource" + ext: mk(4), "res/a.png": b"\x89PNG\r\n\x1a\n" + rand(80, 3)}


def cocos2d_iphone_files() -> Dict[str, Any]:
    return {"Published-iOS/MainScene.ccbi": b"ibcc" + rand(60, 11), "Published-iOS/a.png": b"\x89PNG\r\n\x1a\n" + rand(60, 12),
            "Published-iOS/b.ccbi": b"ibcc" + rand(60, 13)}


def cocos2dx_cpp_files(*, encrypted: bool = True, n: int = 6) -> Dict[str, Any]:
    f: Dict[str, Any] = {"HD/Sprites/s%d.ccz" % i: ccz_bytes(encrypted=encrypted, seed=i) for i in range(n)}
    f["effect.plist"] = ('<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>maxParticles</key><integer>10</integer>'
                         "<key>emitterType</key><integer>0</integer><key>particleLifespan</key><real>1.0</real></dict></plist>")
    return f


def native_plist_png_files() -> Dict[str, Any]:
    """Counter-example: a native app that just ships atlas plists and pngs."""
    plist = ('<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>frames</key><dict/>'
             "<key>metadata</key><dict><key>format</key><integer>2</integer></dict></dict></plist>")
    return {"sprites.plist": plist, "sprites.png": b"\x89PNG\r\n\x1a\n" + rand(100, 2), "Assets.car": b"BOMStore" + b"\0" * 40}


# ----------------------------------------------------------------------------------------- egret / laya
def egret_files(*, wrapped_res: bool = False) -> Dict[str, Any]:
    f: Dict[str, Any] = {
        "resource/default.res.json": '{"groups":[],"resources":[]}', "resource/default.thm.json": '{"skins":{}}',
        "resource/a.exml": "<e:Skin xmlns:e='http://ns.egret.com/eui'/>", "manifest.json": '{"initial":["egret.min.js"],"game":["main.min.js"]}',
        "egret.min.js": 'var egret={};egret.Capabilities={};egret.Capabilities.engineVersion="5.4.1";' + "x=1;" * 300,
        "main.min.js": JS_MINIFIED, "resource/bg.png": b"\x89PNG\r\n\x1a\n" + rand(100, 3),
    }
    if wrapped_res:
        for i in range(10):
            f["resource/assets/r%d.json" % i] = b"EGRX" + struct.pack("<II", 700 + i, 1) + rand(700, 70 + i)
    return f


def laya_files() -> Dict[str, Any]:
    return {"libs/laya.core.js": 'window.Laya={};Laya.version="2.13.0";' + "x=1;" * 300, "index.js": JS_PLAIN, "code.js": JS_MINIFIED,
            "fileconfig.json": "{}", "res/atlas/a.atlas": '{"frames":{}}', "res/scene.ls": '{"type":"Scene"}',
            "res/mat.lmat": '{"version":"LAYAMATERIAL:04"}', "res/a.png": b"\x89PNG\r\n\x1a\n" + rand(100, 4)}


# ------------------------------------------------------------------------------------------ unreal pak
def ue_pak(version: int = 8, *, encrypted_index: bool = False, body: int = 600, truncate_footer: bool = False,
           names: int = 5, bad_index: bool = False) -> bytes:
    data = rand(body, 90)
    off, size = (len(data) + 1000, 5000) if bad_index else (len(data) - 100, 50)
    foot = b""
    if version >= 7:
        foot += rand(16, 91)
    if version >= 4:
        foot += bytes([1 if encrypted_index else 0])
    foot += struct.pack("<II", 0x5A6F12E1, version) + struct.pack("<QQ", off, size) + rand(20, 92)
    if version == 9:
        foot += b"\x00"
    if version >= 8:
        n = 4 if (version == 8 and names == 4) else 5
        foot += b"".join(((b"Zlib", b"Oodle", b"", b"", b"")[k] if k < 2 else b"").ljust(32, b"\0") for k in range(n))
    out = data + foot
    return out[:-20] if truncate_footer else out


def ue_utoc(*, encrypted: bool) -> bytes:
    head = bytearray(0x90)
    head[:16] = b"-==--==--==--==-"
    head[16] = 5
    struct.pack_into("<I", head, 20, 0x90)
    head[80] = 0b0011 if encrypted else 0b1001     # Compressed|Encrypted vs Compressed|Indexed
    return bytes(head)


def unreal_files(**kw: Any) -> Dict[str, Any]:
    return {"cookeddata/Proj/Content/Paks/Proj-ios.pak": ue_pak(**kw)}


# ------------------------------------------------------------------------------------------------ godot
def godot_pck(*, fmt: int = 2, dir_encrypted: bool = False, entries: Sequence[Tuple[str, bool]] = (("res://main.gd", False),),
              truncate: bool = False) -> bytes:
    head = b"GDPC" + struct.pack("<IIII", fmt, 4 if fmt >= 2 else 3, 2, 0)
    flags = 1 if dir_encrypted else 0
    if fmt >= 2:
        head += struct.pack("<IQ", flags, 0)
    head += b"\0" * 64
    if dir_encrypted:
        body = struct.pack("<I", len(entries)) + rand(80, 5)
    else:
        body = struct.pack("<I", len(entries))
        for path, enc in entries:
            pb = path.encode()
            body += struct.pack("<I", len(pb)) + pb + struct.pack("<QQ", 0, 10) + b"\0" * 16
            if fmt >= 2:
                body += struct.pack("<I", 1 if enc else 0)
    out = head + body
    return out[: len(head) + 6] if truncate else out


def hermes_bundle(version: int = 96, size: int = 400) -> bytes:
    head = struct.pack("<QI", 0x1F1903C103BC1FC6, version) + b"\x11" * 20 + struct.pack("<I", size)
    head += struct.pack("<IIIIII", 0, 5, 1, 1, 9, 0)
    return head + rand(size - len(head), 33)


def flutter_files(*, aot: bool = True, kernel: bool = False) -> Dict[str, Any]:
    f: Dict[str, Any] = {
        "Frameworks/Flutter.framework/Flutter": build_macho(filetype="dylib"), "Frameworks/Flutter.framework/Info.plist": b"bplist00",
        "Frameworks/App.framework/flutter_assets/AssetManifest.json": "{}",
        "Frameworks/App.framework/flutter_assets/FontManifest.json": "[]",
    }
    if aot:
        f["Frameworks/App.framework/App"] = build_macho(filetype="dylib", symbols=["_kDartVmSnapshotData"])
    if kernel:
        f["Frameworks/App.framework/flutter_assets/kernel_blob.bin"] = rand(500, 6)
    return f


def rn_files(*, kind: str = "hermes") -> Dict[str, Any]:
    if kind == "hermes":
        return {"main.jsbundle": hermes_bundle()}
    if kind == "plain":
        return {"main.jsbundle": "var __BUNDLE_START_TIME__=this.nativePerformanceNow?nativePerformanceNow():Date.now();" + "__d(function(){},1,[]);" * 40}
    return {"main.jsbundle": rand(3000, 12)}


# ------------------------------------------------------------------------------------ small engines
def defold_arci(*, encrypted: Sequence[bool] = (False, False), version: int = 6) -> bytes:
    n = len(encrypted)
    head = struct.pack(">IIQIIII", version, 0, 0, n, 48, 48 + n * 16, 0) + b"\0" * 16
    entries = b""
    for i, enc in enumerate(encrypted):
        flags = (1 if enc else 0) | 2
        entries += struct.pack(">QII", (flags << 60) | (i * 100), 100, 80)
    return head + entries


def defold_files(**kw: Any) -> Dict[str, Any]:
    return {"game.arci": defold_arci(**kw), "game.arcd": rand(300, 14), "game.projectc": rand(100, 15)}


def form_file(chunks: Sequence[Tuple[bytes, int]], *, broken: bool = False) -> bytes:
    body = b"".join(cid + struct.pack("<I", n) + rand(n, 60 + i) for i, (cid, n) in enumerate(chunks))
    out = b"FORM" + struct.pack("<I", len(body)) + body
    return out[:-7] if broken else out


def gamemaker_files(**kw: Any) -> Dict[str, Any]:
    return {"game.ios": form_file([(b"GEN8", 40), (b"OPTN", 24), (b"SPRT", 100)], **kw)}


def solar2d_files(*, encrypted: bool = False) -> Dict[str, Any]:
    if encrypted:
        return {"resource.car": rand(4000, 21)}
    car = b"CAR\0" + struct.pack("<I", 3) + b"".join(build_lua_bytecode("5.1") + rand(60, i) for i in range(3))
    return {"resource.car": car}


def love_zip(*, encrypted: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("main.lua", LUA_PLAIN)
        zf.writestr("conf.lua", "function love.conf(t) end\n")
    data = buf.getvalue()
    if encrypted:
        data = _set_zip_encrypted_flag(data)
    return data


def _set_zip_encrypted_flag(data: bytes) -> bytes:
    """Set general-purpose bit 0 in every local and central header (so ``zipfile`` reports ``flag_bits & 1``)."""
    b = bytearray(data)
    i = 0
    while True:
        i = bytes(b).find(b"PK\x03\x04", i)
        if i < 0:
            break
        b[i + 6] |= 1
        i += 4
    i = 0
    while True:
        i = bytes(b).find(b"PK\x01\x02", i)
        if i < 0:
            break
        b[i + 8] |= 1
        i += 4
    return bytes(b)


def love_files(**kw: Any) -> Dict[str, Any]:
    return {"game.love": love_zip(**kw)}


def xamarin_files(*, broken: int = 0, native_dll: bool = False) -> Dict[str, Any]:
    f: Dict[str, Any] = {"Xamarin.iOS.dll": build_pe_cli("Xamarin.iOS", refs=["mscorlib"], types=3),
                         "MyApp.dll": build_pe_cli("MyApp", refs=["mscorlib", "Xamarin.iOS"], types=9),
                         "mscorlib.dll": build_pe_cli("mscorlib", types=20)}
    for i in range(broken):
        f["Enc%d.dll" % i] = rand(2000, 40 + i)
    if native_dll:
        f["native.dll"] = b"MZ" + b"\0" * 62 + b"\x40\0\0\0" + b"\0" * 200
    return f


def web_files(*, obfuscated: bool = False, encrypted: bool = False) -> Dict[str, Any]:
    js = "var _0x1a2b=['a','b'];function _0x3c4d(){return _0x1a2b[0];}" * 20 if obfuscated else JS_MINIFIED
    f: Dict[str, Any] = {"www/index.html": "<html><head></head><body>hi</body></html>", "www/js/app.js": js,
                         "www/css/a.css": "body{margin:0}"}
    if encrypted:
        for i in range(4):
            f["www/js/e%d.js" % i] = rand(2000, 80 + i)
    return f


def custom_wrapper_files(n: int = 20, tag: bytes = b"ZZPK") -> Dict[str, Any]:
    """Self-made engine: ``.json`` / ``.png`` / ``.js`` files that start with a custom 4 byte tag."""
    f: Dict[str, Any] = {}
    for i in range(n):
        body = rand(500 + i, 100 + i)
        size = 12 + len(body)
        ext = (".json", ".png", ".js")[i % 3]
        f["data/f%d%s" % (i, ext)] = tag + struct.pack("<II", size, 3) + body
    return f
