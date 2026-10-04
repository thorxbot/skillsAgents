"""Synthetic Unity apps for the hot-update stage (WP5b); no real app data anywhere.

Built on ``formats_builder`` (UnityFS / Lua / PE-CLI) and ``macho_builder`` (Mach-O).  Public entry points::

    build_metadata(identifiers, *, layout="v31"|"v39", literals=(), encrypted=False, seed=1) -> BuiltMetadata
    textasset(name, data) -> bytes                     # Unity TextAsset record (len-prefixed name + payload)
    serialized_blob(records, *, container_paths=(), noise=0, seed=1) -> bytes
    build_bundle(records, *, container_paths=(), compression="lz4", noise=2048) -> bytes
    build_hotfix_app(**options) -> dict[str, bytes]    # files relative to the .app, ready for build_ipa
    make_context(tmp_path, files, *, unity=None, run_macho=True) -> AnalysisContext   # ingest + inventory (+ macho) done

Everything is deterministic.
"""
from __future__ import annotations

import plistlib
import random
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from fixtures import formats_builder as fb
from fixtures.ipa_builder import build_ipa
from fixtures.macho_builder import build_macho

APP_NAME = "Game"
APP = "Payload/%s.app/" % APP_NAME
META_REL = "Data/Managed/Metadata/global-metadata.dat"
UNITYFW_REL = "Frameworks/UnityFramework.framework/UnityFramework"

BASE_IDENTIFIERS = ["mscorlib", "System", "UnityEngine", "UnityEngine.CoreModule", "Assembly-CSharp",
                    "<Module>", "Object", "String", "Start", "Update", "Awake", "GameManager", "PlayerController"]
BASE_ASSEMBLIES = ["mscorlib.dll", "System.dll", "System.Core.dll", "UnityEngine.CoreModule.dll", "Assembly-CSharp.dll"]


@dataclass
class BuiltMetadata:
    data: bytes
    string_region: Optional[Dict[str, int]]


def build_metadata(identifiers: Iterable[str] = (), *, layout: str = "v31", literals: Iterable[str] = (),
                   encrypted: bool = False, seed: int = 1, assemblies: Iterable[str] = BASE_ASSEMBLIES,
                   magic_ok: bool = True) -> BuiltMetadata:
    """A global-metadata.dat look-alike: header with ``(offset, size)`` pairs, literal data, identifier pool.

    ``layout`` v31 puts the pool pair at header words 6/7, v39 at words 8/9 (the real files differ this way),
    so a reader that hard-codes one layout fails on the other -- the stage re-locates the pool.
    """
    rng = random.Random(seed)
    if encrypted:
        return BuiltMetadata(bytes(rng.randrange(256) for _ in range(40_000)), None)
    idents: List[str] = list(BASE_IDENTIFIERS) + list(assemblies) + list(identifiers)
    pool = b"".join(i.encode("utf-8") + b"\0" for i in idents)
    pool += b"".join(("Filler%04d" % n).encode() + b"\0" for n in range(400))      # make the pool plausibly large
    lit = "".join(literals).encode("utf-8") or b"placeholder-literal"
    lit_table = struct.pack("<II", len(lit), 0) * 8
    hdr_words = 48 if layout == "v31" else 96
    hdr = hdr_words * 4
    off_lit_tab = hdr
    off_lit = off_lit_tab + len(lit_table)
    off_pool = (off_lit + len(lit) + 15) & ~15
    words = [0] * hdr_words
    words[0] = 0xFAB11BAF if magic_ok else 0x12345678
    words[1] = 31 if layout == "v31" else 39
    words[2], words[3] = off_lit_tab, len(lit_table)
    words[4], words[5] = off_lit, len(lit)
    pool_idx = 6 if layout == "v31" else 8
    words[pool_idx], words[pool_idx + 1] = off_pool, len(pool)
    for i in range(pool_idx + 2, hdr_words):                  # keep the other pairs inside the file but unreadable
        words[i] = rng.randrange(1, off_pool)
    body = struct.pack("<%dI" % hdr_words, *words) + lit_table + lit
    body += b"\0" * (off_pool - len(body)) + pool
    return BuiltMetadata(body, {"offset": off_pool, "size": len(pool)})


# ------------------------------------------------------------------------------- containers


def _align4(n: int) -> int:
    return (n + 3) & ~3


def textasset(name: str, data: bytes) -> bytes:
    """Unity TextAsset body: ``int32 nlen, name, pad4, int32 len, data, pad4``."""
    nb = name.encode("ascii")
    return (struct.pack("<I", len(nb)) + nb + b"\0" * (_align4(len(nb)) - len(nb)) + struct.pack("<I", len(data)) +
            data + b"\0" * (_align4(len(data)) - len(data)))


def serialized_blob(records: Sequence[bytes], *, container_paths: Iterable[str] = (), noise: int = 2048,
                    seed: int = 1) -> bytes:
    """Fake SerializedFile payload: noise, the records back to back (each preceded by noise) and a path table."""
    rng = random.Random(seed)
    out = bytearray(b"\x00" * 64)
    for rec in records:
        out += bytes(rng.randrange(1, 200) for _ in range(noise)) + rec
    out += bytes(rng.randrange(1, 200) for _ in range(noise))
    for p in container_paths:
        out += struct.pack("<I", len(p)) + p.encode("ascii") + b"\0"
    return bytes(out)


def build_bundle(records: Sequence[bytes] = (), *, container_paths: Iterable[str] = (), compression: str = "lz4",
                 noise: int = 2048, seed: int = 1, block: int = 32 * 1024, engine_version: str = "2021.3.20f1") -> bytes:
    payload = serialized_blob(records, container_paths=container_paths, noise=noise, seed=seed)
    blocks = [payload[i:i + block] for i in range(0, len(payload), block)] or [b"\0" * 16]
    return fb.build_unityfs(blocks, compression=compression, engine_version=engine_version)


def build_filler_bundle(seed: int, *, compression: str = "lz4") -> bytes:
    return build_bundle([], noise=512, seed=seed, compression=compression)


# --------------------------------------------------------------------------------- the app


def lua_chunk(version: str = "5.3", **kw: Any) -> bytes:
    return fb.build_lua_bytecode(version, **kw) + b"return 1"


def _main_plist() -> bytes:
    return plistlib.dumps({"CFBundleExecutable": APP_NAME, "CFBundleIdentifier": "com.example.game"})


def build_hotfix_app(*, identifiers: Iterable[str] = (), metadata_layout: str = "v31", metadata_encrypted: bool = False,
                     literals: Iterable[str] = (), assemblies: Iterable[str] = BASE_ASSEMBLIES,
                     loose: Optional[Dict[str, Any]] = None, bundles: Optional[Dict[str, bytes]] = None,
                     encrypted_binary: bool = True, binary_strings: Iterable[str] = (),
                     serialized: Optional[Dict[str, bytes]] = None, extra: Optional[Dict[str, Any]] = None,
                     with_metadata: bool = True, seed: int = 1) -> Dict[str, bytes]:
    """Files of a small Unity IL2CPP app (names relative to the .app).

    ``loose``: relative path -> bytes/str; ``bundles``: relative path -> UnityFS bytes; ``serialized``: relative
    path -> raw serialized bytes; ``binary_strings`` land in ``__cstring`` of UnityFramework (visible only when
    ``encrypted_binary`` is False).
    """
    files: Dict[str, Any] = {
        "Info.plist": _main_plist(),
        APP_NAME: build_macho(encrypted=encrypted_binary, strings=["main"], objc_classes=["AppDelegate"]),
        UNITYFW_REL: build_macho(filetype="dylib", encrypted=encrypted_binary, strings=["il2cpp_init"] + list(binary_strings)),
        "Data/globalgamemanagers": b"\0" * 64 + b"2021.3.20f1\0" + b"\0" * 64,
        "Data/Resources/unity default resources": b"\0" * 128,
    }
    if with_metadata:
        meta = build_metadata(identifiers, layout=metadata_layout, literals=literals, encrypted=metadata_encrypted,
                              assemblies=assemblies, seed=seed)
        files[META_REL] = meta.data
    for rel, data in (loose or {}).items():
        files[rel] = data
    for rel, data in (bundles or {}).items():
        files[rel] = data
    for rel, data in (serialized or {}).items():
        files[rel] = data
    files.update(extra or {})
    return {k: (v if isinstance(v, bytes) else str(v).encode("utf-8")) for k, v in files.items()}


def metadata_result(files: Dict[str, bytes], *, verdict: str = "no", string_region: Optional[Dict[str, int]] = None,
                    present: bool = True) -> Dict[str, Any]:
    """``engine.unity``-shaped synthetic result (CONTRACT-FREEZE 4.8) for the given app files."""
    return {
        "version": {"value": "2021.3.20f1", "sources": [], "conflicts": []},
        "backend": "il2cpp",
        "binary": {"path": APP + UNITYFW_REL, "slice": "arm64", "encrypted": None},
        "metadata": {"path": APP + META_REL, "present": present, "version": 31, "header_ok": True, "entropy": None,
                     "string_region_ok": True, "string_region": string_region, "verdict": verdict, "evidence": []},
        "bundles": {"total": 0, "by_class": {}, "compression": {}, "unity_versions": {}, "samples": {}, "paths_sample": [],
                    "sampled": 0, "addressables": {"catalog_found": False}},
        "precheck": {"ready": False, "error_code": None, "reasons": []},
    }


def make_context(tmp_path: Path, files: Dict[str, bytes], *, unity: Optional[Dict[str, Any]] = None,
                 run_macho: bool = True, cfg_kwargs: Optional[Dict[str, Any]] = None,
                 unity_cfg: Optional[Dict[str, Any]] = None):
    """Build an IPA from ``files``, run ingest + inventory (+ macho) for real and attach a synthetic ``engine.unity``."""
    from ipa_analyzer.analyzers.ingest_stage import IngestStage
    from ipa_analyzer.analyzers.inventory import InventoryStage
    from ipa_analyzer.analyzers.macho_stage import MachoStage
    from ipa_analyzer.config import Config, UnityConfig
    from ipa_analyzer.context import AnalysisContext

    ipa = build_ipa(tmp_path / "Game.ipa", files, app_name=APP_NAME)
    cfg_args = dict(cfg_kwargs or {})
    if unity_cfg:
        cfg_args["unity"] = UnityConfig(**unity_cfg)
    ctx = AnalysisContext(Config(output_dir=tmp_path / "out", **cfg_args), ipa)
    ctx.results["ingest"] = IngestStage().run(ctx).data
    ctx.results["inventory"] = InventoryStage().run(ctx).data
    if run_macho:
        res = MachoStage().run(ctx)
        ctx.results["macho"] = res.data
    meta_region = None
    if META_REL in files:
        meta_region = None
    ctx.results["engine.unity"] = unity if unity is not None else metadata_result(files, string_region=meta_region)
    return ctx
