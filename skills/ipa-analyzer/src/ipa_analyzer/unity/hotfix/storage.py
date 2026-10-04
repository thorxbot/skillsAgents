"""Where do the scripts live?  Loose files, AssetBundles (sampled) and SerializedFiles.

* **Loose**: candidates are picked from the inventory by extension / directory / magic (``*.lua``,
  ``*.lua.bytes``, ``*.dll.bytes``, ``*.mjs`` ... and ``*.bytes`` in ``lua*`` directories) and only their
  first bytes (plus whole small DLLs) are read.
* **AssetBundles**: a deterministic sample (``Config.unity.hotfix_scan_bundles``) is decompressed through
  ``formats.unityfs.iter_decompressed`` (at most ``hotfix_scan_bytes_per_bundle`` bytes each) and the
  decompressed stream is signature-scanned (``formats.magic_scan``) -- the SerializedFile is *not* parsed.
  Lua/LuaJIT chunks, PE/CLI images and script-path strings are collected as :class:`Blob` objects.
* **SerializedFiles** (``resources.assets``, ``sharedassets*.assets``, ``level*`` ...): same scan on the raw
  file, limited in size and number.

Every limit is reported (``sampled/total``) because a sample is not the population.  Containers that cannot
be read (not UnityFS, high entropy, block decompression failure) are counted with a reason; that is
evidence of *protection or an unsupported variant*, never of "no scripts".

TextAsset layout used to size blobs found in a decompressed stream (Unity SerializedFile, UNVERIFIED for
exotic versions): ``int32 length`` immediately before the payload, preceded by the (4-aligned) asset name
and its own ``int32`` length.
"""
from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from ...formats import lua_bytecode, magic_scan, unityfs
from ...util.entropy import shannon
from .detect import HotfixRules

log = logging.getLogger(__name__)

__all__ = ["Blob", "ContainerScan", "Discovery", "discover", "pick_sample", "load_loose_blob", "scan_bundle",
           "scan_serialized", "HEAD_BYTES", "SAMPLE_BYTES"]

HEAD_BYTES = 4096
SAMPLE_BYTES = 64 * 1024
MAX_DLL_BYTES = 16 * 1024 * 1024
MAX_LOOSE_PER_KIND = 600
MAX_BYTES_SNIFF = 3000
MAX_SERIALIZED_FILES = 24
MAX_SERIALIZED_BYTES = 64 * 1024 * 1024
_LUA_TEXT_HITS = (b"local function ", b"require(\"", b"require('")
_PATTERNS: Sequence[magic_scan.SigPattern] = tuple(magic_scan.SCRIPT_SIGNATURES) + tuple(
    magic_scan.literal("lua_text_%d" % i, p) for i, p in enumerate(_LUA_TEXT_HITS))
_MAX_NAME_SAMPLES = 40
_MAX_DLL_PER_CONTAINER = 6
_MAX_DLL_BYTES_PER_CONTAINER = 24 * 1024 * 1024
_HIGH_ENTROPY = 7.2
_BUNDLE_HEAD = 64 * 1024


@dataclass
class Blob:
    """One script-like object (a file, or a chunk found inside a container)."""

    kind: str                 # lua | dll | js
    source: str               # loose | bundle | serialized
    container: str            # archive path of the containing file (loose files: the file itself)
    name: str                 # file name, or asset name inside a container when it could be recovered
    size: Optional[int] = None
    head: bytes = b""
    sample: bytes = b""
    data: Optional[bytes] = None
    note: str = ""


@dataclass
class ContainerScan:
    path: str
    kind: str                           # bundle | serialized
    status: str = "ok"                  # ok | partial | not_unityfs | encrypted_suspected | header_error |
    #                                     blocks_info_error | block_decompress_failed | limit | unsupported | io_error | budget
    detail: str = ""
    bytes_scanned: int = 0
    stopped: Optional[str] = None
    counts: Dict[str, int] = field(default_factory=dict)
    blobs: List[Blob] = field(default_factory=list)
    script_names: Dict[str, List[str]] = field(default_factory=dict)      # kind -> sample names
    script_name_counts: Dict[str, int] = field(default_factory=dict)
    lua_text_hits: int = 0
    rejected_hits: int = 0
    unity_version: str = ""


@dataclass
class Discovery:
    loose: Dict[str, List[Dict[str, Any]]] = field(default_factory=lambda: {"lua": [], "dll": [], "js": []})
    bundles: List[Dict[str, Any]] = field(default_factory=list)
    serialized: List[Dict[str, Any]] = field(default_factory=list)
    managed_dlls: List[str] = field(default_factory=list)
    excluded: Dict[str, int] = field(default_factory=dict)
    bytes_sniff: List[Dict[str, Any]] = field(default_factory=list)
    truncated: Dict[str, int] = field(default_factory=dict)
    file_names: List[str] = field(default_factory=list)       # relative paths (for file-signal matching)


def _longest_suffix(rl: str, exts: Iterable[str]) -> Optional[str]:
    best = None
    for e in exts:
        if rl.endswith(e) and (best is None or len(e) > len(best)):
            best = e
    return best


def discover(files: Iterable[Dict[str, Any]], rel_fn: Callable[[str], Optional[str]], rules: HotfixRules,
             extra_bundle_paths: Iterable[str] = ()) -> Discovery:
    """Classify inventory rows into script / bundle / serialized candidates (no file contents are read)."""
    st = rules.storage
    lua_ext, dll_ext, js_ext = st["lua_ext"], st["dll_ext"], st["js_ext"]
    bytes_ext = tuple(st["bytes_ext"])
    bundle_ext = tuple(st["bundle_ext"])
    lua_dir = re.compile(st["lua_dir_regex"], re.IGNORECASE)
    exclude = re.compile(st["exclude_path_regex"], re.IGNORECASE)
    game = re.compile(st["game_data_regex"])
    serialized = re.compile(st["serialized_regex"])
    managed = re.compile(st["managed_dir_regex"])
    d = Discovery()
    seen_bundles = set()
    for row in files:
        path = row.get("path")
        if not isinstance(path, str) or path.endswith("/"):
            continue
        rel = rel_fn(path)
        if rel is None:
            continue
        d.file_names.append(rel)
        rl = rel.lower()
        size = int(row.get("size") or 0)
        magic = str(row.get("magic") or "")
        in_game = bool(game.search(rel))
        excluded = bool(exclude.search(rel)) and not in_game
        info = {"path": path, "rel": rel, "size": size, "magic": magic}

        if magic in ("unityfs", "unityweb", "unityraw", "unityarchive") or (
                rl.endswith(bundle_ext) and in_game and magic not in ("png", "jpeg", "ogg")):
            if not excluded and path not in seen_bundles:
                seen_bundles.add(path)
                d.bundles.append(info)
            continue
        if serialized.search(rel):
            d.serialized.append(info)
            continue
        kind = None
        if _longest_suffix(rl, lua_ext):
            kind = "lua"
        elif _longest_suffix(rl, dll_ext):
            kind = "dll"
        elif _longest_suffix(rl, js_ext):
            kind = "js"
        elif magic == "lua_bytecode":
            kind = "lua"
        elif rl.endswith(bytes_ext) and in_game:
            if lua_dir.search(rel):
                kind = "lua"
                info["hint"] = "bytes_in_lua_dir"
            else:
                if len(d.bytes_sniff) < MAX_BYTES_SNIFF:
                    d.bytes_sniff.append(info)
                continue
        if kind is None:
            continue
        if kind == "dll" and managed.search(rel) and not rl.endswith((".bytes", ".txt")):
            d.managed_dlls.append(path)
            continue
        if excluded or (kind == "js" and not in_game):
            d.excluded[kind] = d.excluded.get(kind, 0) + 1
            continue
        if len(d.loose[kind]) >= MAX_LOOSE_PER_KIND:
            d.truncated[kind] = d.truncated.get(kind, 0) + 1
            continue
        d.loose[kind].append(info)
    for extra in extra_bundle_paths:
        if extra not in seen_bundles:
            rel = rel_fn(extra)
            if rel is not None:
                seen_bundles.add(extra)
                d.bundles.append({"path": extra, "rel": rel, "size": 0, "magic": ""})
    d.bundles.sort(key=lambda r: r["path"])
    return d


def pick_sample(items: Sequence[Dict[str, Any]], n: int) -> List[Dict[str, Any]]:
    """Deterministic, evenly spread sample of ``n`` items of a path-sorted sequence."""
    total = len(items)
    if n <= 0:
        return []
    if total <= n:
        return list(items)
    step = total / float(n)
    return [items[int(i * step)] for i in range(n)]


# --------------------------------------------------------------------------------- loose files


def _read_head(src: Any, name: str, n: int) -> bytes:
    try:
        return src.read_head(name, n)
    except (KeyError, OSError, ValueError):
        return b""


def load_loose_blob(src: Any, info: Dict[str, Any], kind: str) -> Optional[Blob]:
    """Read the head / sample (and small DLLs entirely) of one loose candidate."""
    name = info["path"]
    sample = _read_head(src, name, SAMPLE_BYTES)
    if not sample and info.get("size", 0) > 0:
        return None
    blob = Blob(kind=kind, source="loose", container=name, name=name.rsplit("/", 1)[-1], size=info.get("size"),
                head=sample[:HEAD_BYTES], sample=sample, note=info.get("hint", ""))
    if kind == "dll":
        size = info.get("size") or len(sample)
        if size <= MAX_DLL_BYTES:
            try:
                with src.open(name) as fh:
                    blob.data = fh.read(MAX_DLL_BYTES + 1)[:MAX_DLL_BYTES]
            except (KeyError, OSError, ValueError):
                blob.data = sample if size <= SAMPLE_BYTES else None
        else:
            blob.note = (blob.note + " too_large_for_parse").strip()
    return blob


# --------------------------------------------------------------------------- stream scanning


def _u32(buf: bytes, pos: int, big: bool = False) -> Optional[int]:
    if pos < 0 or pos + 4 > len(buf):
        return None
    return struct.unpack_from(">I" if big else "<I", buf, pos)[0]


def _asset_name_before(ctx_buf: bytes, data_pos: int) -> str:
    """Recover the TextAsset name stored before the payload at ``data_pos`` (best effort)."""
    end = data_pos - 4                       # payload length field sits at data_pos-4
    for nlen in range(1, 97):
        pad = (4 - nlen % 4) % 4
        start = end - pad - nlen
        if start - 4 < 0:
            break
        if _u32(ctx_buf, start - 4) == nlen:
            raw = ctx_buf[start:start + nlen]
            if all(0x20 <= b < 0x7F for b in raw):
                return raw.decode("ascii")
    return ""


def _classify_ext(name: str) -> Optional[str]:
    low = name.lower()
    if re.search(r"\.lua(?:\.bytes|\.txt)?$", low):
        return "lua"
    if re.search(r"\.dll(?:\.bytes|\.txt)?$", low):
        return "dll"
    if re.search(r"\.js(?:\.bytes|\.txt)?$", low):
        return "js"
    return None


def _guard(chunks: Iterator[bytes], holder: Dict[str, str]) -> Iterator[bytes]:
    """Yield ``chunks``; a decompression error ends the stream and is recorded instead of raised."""
    try:
        for c in chunks:
            yield c
    except unityfs.UnityFSError as exc:
        holder["kind"] = exc.kind
        holder["detail"] = str(exc)[:200]
    except OSError as exc:                 # a damaged archive entry (ingest.CorruptEntry) or an I/O error mid-stream
        holder["kind"] = "io_error"
        holder["detail"] = str(exc)[:200]


def _scan_stream(path: str, kind: str, chunks: Iterator[bytes], read_range: Callable[[int, int], bytes],
                 max_bytes: int, max_seconds: float) -> ContainerScan:
    cs = ContainerScan(path=path, kind=kind)
    source = "bundle" if kind == "bundle" else "serialized"
    err: Dict[str, str] = {}
    res = magic_scan.scan_stream(_guard(chunks, err), _PATTERNS, max_bytes=max_bytes, max_seconds=max_seconds,
                                 max_hits=9000, max_hits_per_pattern=3000, context_before=128,
                                 context_after=192)
    cs.bytes_scanned = res.bytes_scanned
    cs.stopped = res.stopped
    cs.counts = dict(res.counts)
    dll_cands: List[Tuple[int, int, str]] = []
    for hit in res.hits:
        pid = hit.pattern
        if pid.startswith("lua_text_"):
            cs.lua_text_hits += 1
        elif pid in ("lua_bytecode", "luajit_bytecode"):
            _accept_lua(cs, hit, source)
        elif pid == "pe_mz":
            cand = _dll_candidate(hit)
            if cand is None:
                continue
            dll_cands.append(cand)
        elif pid == "script_path":
            name = hit.match.decode("ascii", "replace")
            k = _classify_ext(name)
            if k:
                cs.script_name_counts[k] = cs.script_name_counts.get(k, 0) + 1
                lst = cs.script_names.setdefault(k, [])
                if len(lst) < _MAX_NAME_SAMPLES and name not in lst:
                    lst.append(name)
    used = 0
    for off, length, name in dll_cands[:_MAX_DLL_PER_CONTAINER]:
        if used + length > _MAX_DLL_BYTES_PER_CONTAINER:
            break
        try:
            data = read_range(off, length)
        except (unityfs.UnityFSError, OSError, ValueError):
            continue
        used += len(data)
        if data[:2] != b"MZ":
            continue
        cs.blobs.append(Blob("dll", source, path, name or "", size=len(data), head=data[:HEAD_BYTES],
                             sample=data[:SAMPLE_BYTES], data=data))
    cs.status = "ok" if res.stopped in (None, "max_hits") else "partial"
    if err:
        k = err.get("kind", "")
        cs.detail = err.get("detail", "")
        if k == "limit_exceeded":
            cs.status = "limit" if res.bytes_scanned == 0 else "partial"
        elif k == "block_decompress_failed":
            cs.status = "block_decompress_failed"
        elif k == "io_error":
            cs.status = "partial" if res.bytes_scanned else "io_error"
        else:
            cs.status = "blocks_info_error"
    return cs


def _accept_lua(cs: ContainerScan, hit: magic_scan.Hit, source: str) -> None:
    ctx = hit.context
    idx = min(128, hit.offset)
    head = ctx[idx:]
    info = lua_bytecode.parse_header(head)
    length_ok = False
    for big in (False, True):
        ln = _u32(ctx, idx - 4, big)
        if ln is not None and 16 <= ln <= (1 << 26):
            length_ok = True
    if not (info.valid or (info.signature_ok and length_ok and info.version is not None)):
        cs.rejected_hits += 1
        return
    cs.blobs.append(Blob("lua", source, cs.path, _asset_name_before(ctx, idx), size=None, head=head, sample=head,
                         note="" if info.valid else "length_prefix_only"))


def _dll_candidate(hit: magic_scan.Hit) -> Optional[Tuple[int, int, str]]:
    ctx = hit.context
    idx = min(128, hit.offset)
    blob = ctx[idx:]
    if len(blob) < 0x40:
        return None
    lfanew = struct.unpack_from("<I", blob, 0x3C)[0]
    if lfanew < 0x40 or lfanew + 4 > len(blob) or blob[lfanew:lfanew + 4] != b"PE\0\0":
        return None
    ln = _u32(ctx, idx - 4)
    if ln is None or not (1024 <= ln <= 64 * 1024 * 1024):
        return None
    return hit.offset, ln, _asset_name_before(ctx, idx)


def _bundle_read_range(fobj: BinaryIO, header: unityfs.UnityFSHeader, bi: unityfs.BlocksInfo, max_block: int
                       ) -> Callable[[int, int], bytes]:
    def read_range(start: int, length: int) -> bytes:
        out = bytearray()
        pos = 0
        for chunk in unityfs.iter_decompressed(fobj, header, bi, chunk=1 << 20, max_block=max_block):
            end = pos + len(chunk)
            if end > start:
                out += chunk[max(0, start - pos):max(0, start + length - pos)]
                if len(out) >= length:
                    break
            pos = end
        return bytes(out[:length])
    return read_range


def scan_bundle(src: Any, info: Dict[str, Any], *, max_bytes: int, max_seconds: float = 20.0) -> ContainerScan:
    """Header-check a bundle candidate and signature-scan up to ``max_bytes`` of its decompressed data."""
    name = info["path"]
    cs = ContainerScan(path=name, kind="bundle")
    head = _read_head(src, name, _BUNDLE_HEAD)
    if not head:
        cs.status = "io_error"
        cs.detail = "empty or unreadable"
        return cs
    try:
        fobj = src.open(name)
    except (KeyError, OSError, ValueError) as exc:
        cs.status, cs.detail = "io_error", str(exc)[:200]
        return cs
    try:
        try:
            header = unityfs.parse_header(fobj)
        except unityfs.UnityFSError as exc:
            high = shannon(head[:8192]) >= _HIGH_ENTROPY
            cs.status = "encrypted_suspected" if (exc.kind == "bad_magic" and high) else (
                "not_unityfs" if exc.kind == "bad_magic" else "header_error")
            cs.detail = str(exc)[:200]
            return cs
        cs.unity_version = header.unity_revision or header.unity_version
        if not header.is_unityfs:
            cs.status, cs.detail = "unsupported", "%s container not parsed" % header.signature
            return cs
        try:
            bi = unityfs.read_blocks_info(fobj, header)
        except unityfs.UnityFSError as exc:
            cs.status = "unsupported" if exc.kind in ("unsupported_version", "unsupported_compression") else "blocks_info_error"
            cs.detail = str(exc)[:200]
            return cs
        max_block = max(1 << 20, min(max_bytes, unityfs.DEFAULT_MAX_BLOCK))
        chunks = unityfs.iter_decompressed(fobj, header, bi, chunk=1 << 20, max_block=max_block)
        res = _scan_stream(name, "bundle", chunks, _bundle_read_range(fobj, header, bi, max_block), max_bytes,
                           max_seconds)
        res.unity_version = cs.unity_version
        return res
    finally:
        try:
            fobj.close()
        except Exception:   # noqa: BLE001
            pass


def scan_serialized(src: Any, info: Dict[str, Any], *, max_bytes: int = MAX_SERIALIZED_BYTES,
                    max_seconds: float = 20.0) -> ContainerScan:
    """Signature-scan the raw bytes of a SerializedFile (no decompression involved)."""
    name = info["path"]
    try:
        fobj = src.open(name)
    except (KeyError, OSError, ValueError) as exc:
        return ContainerScan(path=name, kind="serialized", status="io_error", detail=str(exc)[:200])

    def chunks() -> Iterator[bytes]:
        fobj.seek(0)
        while True:
            buf = fobj.read(1 << 20)
            if not buf:
                return
            yield buf

    def read_range(start: int, length: int) -> bytes:
        fobj.seek(start)
        return fobj.read(length)

    try:
        return _scan_stream(name, "serialized", chunks(), read_range, max_bytes, max_seconds)
    finally:
        try:
            fobj.close()
        except Exception:   # noqa: BLE001
            pass

