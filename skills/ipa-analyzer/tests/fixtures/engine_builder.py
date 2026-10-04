"""Programmatic fake apps for the engine layer (WP7). No real app content is stored.

Public API (``from fixtures.engine_builder import ...``)::

    SynthApp(files, strings, symbols, objc_classes, dylibs, plist)          # what an app is made of
    synth_for_engine(engine_json: dict, *, margin=0.05) -> SynthApp          # satisfy a data/engines/*.json entry
    custom_engine_app() -> SynthApp          # thin UIKit shell + Metal + Lua + Box2D + custom .pak + random .dat
    native_map_app() -> SynthApp             # UIKit + Metal + MapKit, nothing else
    write_app(path, app, *, encrypted=False, app_name="Test") -> Path        # IPA with a Mach-O main binary
    pak_with_zlib_blocks(...), random_blob(...), xor_png(...)                # container samples

The synthesiser reads the signal grammar documented in ``ipa_analyzer.engines.signatures`` but is kept
independent of the source package (it only needs the JSON), so a grammar bug cannot hide itself.
"""
from __future__ import annotations

import plistlib
import random
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from fixtures.ipa_builder import build_ipa
from fixtures.macho_builder import build_macho

# magic ids (util.magic) -> leading bytes that make the inventory assign that id
MAGIC_BYTES: Dict[str, bytes] = {
    "ccz": b"CCZp\x00\x01\x00\x00" + b"\x00" * 24, "il2cpp_metadata": b"\xaf\x1b\xb1\xfa\x1d\x00\x00\x00" + b"\x00" * 24,
    "unityfs": b"UnityFS\x00\x05\x00" + b"\x00" * 24, "gdpc": b"GDPC\x02\x00\x00\x00" + b"\x00" * 24,
    "hermes_bytecode": b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f" + b"\x00" * 24, "lua_bytecode": b"\x1bLuaS\x00\x19\x93\r\n\x1a\n" + b"\x00" * 16,
    "uasset": b"\xc1\x83\x2a\x9e" + b"\x00" * 28, "metallib": b"MTLB\x01\x80\x02\x00" + b"\x00" * 24,
    "fsb": b"FSB5\x01\x00\x00\x00" + b"\x00" * 24, "moc3": b"MOC3\x01\x00\x00\x00" + b"\x00" * 24,
    "wwise_bank": b"BKHD\x01\x00\x00\x00" + b"\x00" * 24, "wwise_pck": b"AKPK\x01\x00\x00\x00" + b"\x00" * 24,
    "astc": b"\x13\xab\xa1\x5c\x04\x04\x01" + b"\x00" * 24, "pvr": b"PVR\x03\x00\x00\x00\x00" + b"\x00" * 24,
    "ktx": b"\xabKTX 11\xbb\r\n\x1a\n" + b"\x00" * 24, "ktx2": b"\xabKTX 20\xbb\r\n\x1a\n" + b"\x00" * 24,
    "dds": b"DDS \x7c\x00\x00\x00" + b"\x00" * 24,
}
# sample strings for regex signals, keyed by a fragment of the pattern
REGEX_SAMPLES = (("Godot Engine", "Godot Engine v4.2.1.stable"), ("cocos2d-x", "cocos2d-x 3.17.2"),
                 ("20[12][0-9]", "2021.3.16f1"), ("$Lua", "$LuaVersion: Lua 5.3.6 $"))
_rng = random.Random(1234)


@dataclass
class SynthApp:
    files: Dict[str, bytes] = field(default_factory=dict)       # relative to the .app
    strings: List[str] = field(default_factory=list)
    symbols: List[str] = field(default_factory=list)            # defined external names (with Mach-O underscore)
    imports: List[str] = field(default_factory=list)
    objc_classes: List[str] = field(default_factory=list)
    dylibs: List[str] = field(default_factory=list)
    plist: Dict[str, Any] = field(default_factory=dict)
    macho_extra: Dict[str, Any] = field(default_factory=dict)
    sections: List[str] = field(default_factory=list)           # signalled sections that are not synthesised

    def merge(self, other: "SynthApp") -> "SynthApp":
        self.files.update(other.files)
        for name in ("strings", "symbols", "imports", "objc_classes", "dylibs"):
            getattr(self, name).extend(x for x in getattr(other, name) if x not in getattr(self, name))
        self.plist.update(other.plist)
        self.macho_extra.update(other.macho_extra)
        return self


# --- sample containers --------------------------------------------------------------------------------------
def random_blob(n: int, seed: int = 7) -> bytes:
    r = random.Random(seed)
    return bytes(r.getrandbits(8) for _ in range(n))


def text_corpus(n: int, seed: int = 3) -> bytes:
    r = random.Random(seed)
    words = ["sprite", "level", "monster", "hp", "attack", "texture", "sound", "quest", "item", "skill"]
    return (" ".join(r.choice(words) + str(r.randrange(1000)) for _ in range(n // 6))).encode()[:n]


def pak_with_zlib_blocks(blocks: int = 24, block_size: int = 6000, header_magic: bytes = b"") -> bytes:
    """Offset-table container: ``count`` + (offset, raw size, compressed size) records + zlib blocks."""
    payloads = [zlib.compress(text_corpus(block_size, seed=i)) for i in range(blocks)]
    table_size = 8 + blocks * 12
    off = len(header_magic) + table_size
    table = struct.pack("<II", blocks, table_size)
    entries = b""
    for p in payloads:
        entries += struct.pack("<III", off, block_size, len(p))
        off += len(p)
    return header_magic + table + entries + b"".join(payloads)


def xor_png(key: int = 0x5A, size: int = 6000) -> bytes:
    """A syntactically plausible PNG whose every byte is XORed with ``key``."""
    ihdr = b"\x00\x00\x00\r" + b"IHDR" + struct.pack(">IIBBBBB", 32, 32, 8, 6, 0, 0, 0) + b"\x00\x00\x00\x00"
    png = b"\x89PNG\r\n\x1a\n" + ihdr + b"\x00\x00\x10\x00IDAT" + random_blob(size, seed=11) + b"\x00" * 8
    return bytes(b ^ key for b in png)


# --- glob / pattern synthesis -------------------------------------------------------------------------------
def _split_count(p: str):
    if "#" in p:
        body, n = p.rsplit("#", 1)
        if n.isdigit():
            return body, int(n)
    return p, 1


def _paths_for_glob(pat: str, count: int = 1) -> List[str]:
    pat = pat.lstrip("/")
    out = []
    for i in range(count):
        s = pat.replace("**/", "x/").replace("**", "x").replace("*", "f%d" % i if count > 1 else "f").replace("?", "a")
        out.append(s)
    return out


def _regex_sample(pattern: str) -> Optional[str]:
    for frag, sample in REGEX_SAMPLES:
        if frag in pattern:
            return sample
    return None


def _apply_signal(app: SynthApp, sig: Dict[str, Any]) -> bool:
    t, pat = sig["type"], sig["pattern"]
    if t in ("file", "dir"):
        body, count = _split_count(pat)
        if t == "file" and body.startswith("magic:"):
            magic = body[6:]
            if magic not in MAGIC_BYTES:
                return False
            for i in range(count):
                app.files["m/%s_%d.bin" % (magic, i)] = MAGIC_BYTES[magic] + bytes([i % 251]) * 8
            return True
        if t == "file" and body.startswith("head:"):
            app.files.setdefault("pk/a%d.bin" % len(app.files), body[5:].encode() + random_blob(200, 5))
            return True
        if t == "dir":
            for p in _paths_for_glob(body, count):
                app.files[p.rstrip("/") + "/f.txt"] = b"x"
            return True
        for p in _paths_for_glob(body, count):
            app.files[p] = b"data" * 8
        return True
    if t == "string":
        if pat.startswith("re:"):
            s = _regex_sample(pat)
            if s is None:
                return False
            app.strings.append(s)
        else:
            app.strings.append(pat)
        return True
    if t == "symbol":
        if pat.startswith("re:"):
            return False
        name = pat.strip("*")
        if pat.startswith("*") and pat.endswith("*"):
            name = "x" + name + "x"
        elif pat.endswith("*"):
            name += "Impl"
        app.symbols.append("_" + name)
        return True
    if t == "objc_prefix":
        app.objc_classes.append(pat + "X")
        return True
    if t == "dylib":
        if ".framework/" in pat:
            app.dylibs.append("/System/Library/Frameworks/" + pat if not pat.startswith("@") else pat)
        else:
            app.dylibs.append("/usr/lib/%s.dylib" % pat)
        return True
    if t == "plist_key":
        k, _, v = pat.partition("=")
        app.plist[k] = v or "x"
        return True
    if t == "binary_section" and pat in ("__DATA,__objc_classlist", "__TEXT,__objc_classname"):
        if not app.objc_classes:
            app.objc_classes.append("AppDelegate")     # the Mach-O builder emits both ObjC sections for classes
        return True
    return False         # other sections cannot be emitted


def synth_for_engine(engine: Dict[str, Any], *, margin: float = 0.05) -> SynthApp:
    """Files / strings / symbols that make ``engine`` (a ``data/engines/*.json`` dict) reach its threshold.

    Strong verified signals first, then by weight; unverified signals are capped like the loader does.
    """
    app = SynthApp()
    sigs = sorted(engine["signals"], key=lambda s: (not s.get("strong", False), s.get("unverified", False), -s["weight"]))
    total = 0.0
    for s in sigs:
        w = min(s["weight"], 0.4) if s.get("unverified") else s["weight"]
        if _apply_signal(app, s):
            total += w
            if s.get("strong") and not s.get("unverified"):
                break
            if total >= engine["confirm_threshold"] + margin:
                break
    return app


# --- hand-made scenarios ----------------------------------------------------------------------------------------
def custom_engine_app() -> SynthApp:
    """Thin UIKit shell + Metal + Lua VM + Box2D + custom .pak (offset table + zlib) + high-entropy .dat."""
    app = SynthApp()
    app.objc_classes = ["AppDelegate", "ViewController"]
    app.dylibs = ["/System/Library/Frameworks/UIKit.framework/UIKit", "/System/Library/Frameworks/Metal.framework/Metal",
                  "/System/Library/Frameworks/QuartzCore.framework/QuartzCore", "/usr/lib/libc++.1.dylib"]
    app.imports = ["_MTLCreateSystemDefaultDevice", "_OBJC_CLASS_$_CAMetalLayer", "_OBJC_CLASS_$_CADisplayLink"]
    app.symbols = ["_luaL_newstate", "_luaL_openlibs", "_lua_pcallk", "__ZN7b2World4StepEfii", "__ZN6b2Body12SetTransformERK6b2Vec2f"]
    app.strings = ["bad argument #%d to '%s' (%s)", "main loop"]
    app.files = {"res/data.pak": pak_with_zlib_blocks(), "res/blob.dat": random_blob(70_000, seed=21),
                 "res/ui.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, "res/config.json": b'{"level": 1}'}
    app.macho_extra = {"cpp": True}
    return app


def native_map_app() -> SynthApp:
    app = SynthApp()
    app.objc_classes = ["AppDelegate", "MapViewController"]
    app.dylibs = ["/System/Library/Frameworks/UIKit.framework/UIKit", "/System/Library/Frameworks/Metal.framework/Metal",
                  "/System/Library/Frameworks/MapKit.framework/MapKit"]
    app.imports = ["_MTLCreateSystemDefaultDevice", "_OBJC_CLASS_$_MKMapView"]
    app.files = {"Base.lproj/Main.storyboardc/Info.plist": b"bplist00", "icon.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 64}
    app.plist = {"UIMainStoryboardFile": "Main"}
    return app


# --- writing -------------------------------------------------------------------------------------------------------
def write_app(path, app: SynthApp, *, encrypted: bool = False, app_name: str = "Test", plist_extra: Optional[dict] = None) -> Path:
    """Write ``app`` as an IPA; the main executable is a thin arm64 Mach-O named after ``app_name``."""
    plist = {"CFBundleExecutable": app_name, "CFBundleIdentifier": "com.example.%s" % app_name.lower()}
    plist.update(app.plist)
    plist.update(plist_extra or {})
    kw = dict(arch="arm64", dylibs=app.dylibs, strings=app.strings, objc_classes=app.objc_classes, symbols=app.symbols,
              imports=app.imports, encrypted=encrypted, stripped="local")
    kw.update(app.macho_extra)
    files: Dict[str, Any] = dict(app.files)
    files["Info.plist"] = plistlib.dumps(plist)
    files[app_name] = build_macho(**kw)
    return build_ipa(path, files, app_name=app_name)


# --- running the engine stages on a synthetic app -------------------------------------------------------------------
ENGINE_STAGES = ("macho", "engine.fingerprint", "engine.detect")


def run_stages(tmp_path, app: SynthApp, *, encrypted: bool = False, stages=ENGINE_STAGES, keep_open: bool = False, **cfg):
    """Write ``app`` as an IPA below ``tmp_path`` and run the given stages through the pipeline (returns the context)."""
    from ipa_analyzer import pipeline
    from ipa_analyzer.config import Config
    from ipa_analyzer.context import AnalysisContext
    ipa = write_app(Path(tmp_path) / "t.ipa", app, encrypted=encrypted)
    ctx = AnalysisContext(Config(output_dir=Path(tmp_path) / "out", stages=tuple(stages), formats=("json",), **cfg), ipa)
    try:
        pipeline.run(ctx)
    finally:
        if not keep_open:
            ctx.close()
    return ctx


def detect(ctx):
    return ctx.results["engine.detect"]
