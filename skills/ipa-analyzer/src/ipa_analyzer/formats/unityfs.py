"""UnityFS AssetBundle container parser (header, BlocksInfo, streamed decompression, probes).

Parses and validates only; it never decrypts, repairs or rewrites a bundle.  Every failure
is an ``UnityFSError`` with a machine-readable ``kind`` so callers can classify a bundle as
standard / damaged / data-level-protected without string matching.

Layout (all integers big-endian) -- Unity does not publish this format; the layout below
is cross-checked between two independent community implementations:
  * AssetStudio  ``AssetStudio/BundleFile.cs``   (github.com/Perfare/AssetStudio)
  * UnityPy      ``UnityPy/files/BundleFile.py`` and ``enums/BundleFile.py`` (github.com/K0lb3/UnityPy)

  header     = signature\\0  u32 formatVersion  cstr unityVersion  cstr unityRevision
               i64 size  u32 compressedBlocksInfoSize  u32 uncompressedBlocksInfoSize  u32 flags
  (formatVersion >= 7: the stream is aligned to 16 bytes after the header; UnityPy also aligns
   for Unity 2019.4.15+ even when formatVersion is 6.)
  flags      = bits 0..5 compression of BlocksInfo (0 none, 1 LZMA, 2 LZ4, 3 LZ4HC, 4 LZHAM)
               0x40 BlocksAndDirectoryInfoCombined   0x80 BlocksInfoAtTheEnd
               0x100 OldWebPluginCompatibility
               0x200 BlockInfoNeedPaddingAtStart (Unity >= 2020.3.34 / 2021.3.2 / 2022.1.1) --
                     in older Unity versions the same bit marked UnityCN asset-bundle encryption
               0x400 / 0x1000 UsesAssetBundleEncryption in old / new flag sets (UnityPy)
  BlocksInfo = 16-byte hash, i32 blockCount, blockCount x (u32 uncompressedSize,
               u32 compressedSize, u16 flags [bits 0..5 compression, 0x40 streamed]),
               i32 nodeCount, nodeCount x (i64 offset, i64 size, u32 flags, cstr path)
  data       = the blocks back to back; node offsets index the concatenated *uncompressed* data.

Only ``UnityFS`` bundles can be opened.  ``UnityWeb`` / ``UnityRaw`` / ``UnityArchive`` are
recognised by ``parse_header`` and then rejected with ``unsupported_version``.

UNVERIFIED: flag bits >= 0x200 and the Unity-version cut-offs that choose between the old and
new flag meanings come from UnityPy; Unity itself is closed source.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import BinaryIO, Iterator, List, Optional, Tuple

from . import lz4

__all__ = [
    "SIGNATURE_FS",
    "KNOWN_SIGNATURES",
    "COMPRESSION_NONE",
    "COMPRESSION_LZMA",
    "COMPRESSION_LZ4",
    "COMPRESSION_LZ4HC",
    "COMPRESSION_LZHAM",
    "ERROR_KINDS",
    "UnityFSError",
    "UnityFSHeader",
    "StorageBlock",
    "Node",
    "BlocksInfo",
    "VariantHypothesis",
    "parse_header",
    "read_blocks_info",
    "iter_decompressed",
    "probe_variants",
]

SIGNATURE_FS = "UnityFS"
KNOWN_SIGNATURES = ("UnityFS", "UnityWeb", "UnityRaw", "UnityArchive")

COMPRESSION_NONE = 0
COMPRESSION_LZMA = 1
COMPRESSION_LZ4 = 2
COMPRESSION_LZ4HC = 3
COMPRESSION_LZHAM = 4

FLAG_COMPRESSION_MASK = 0x3F
FLAG_BLOCKS_INFO_COMBINED = 0x40
FLAG_BLOCKS_INFO_AT_END = 0x80
# UNVERIFIED: bits >= 0x100 and the Unity-version cut-offs in _uses_new_flag_set come from UnityPy only.
FLAG_OLD_WEB_PLUGIN = 0x100
FLAG_0x200 = 0x200  # padding-at-start (new flag set) or encryption (old flag set)
FLAG_ENCRYPTION_OLD = 0x400
FLAG_ENCRYPTION_NEW = 0x1000

BLOCK_FLAG_STREAMED = 0x40

#: Highest UnityFS format version this module has been written against.
# UNVERIFIED: format versions 5-8 are the ones seen in AssetStudio / UnityPy; newer ones are rejected.
MAX_KNOWN_FORMAT_VERSION = 8
#: Format versions above this are treated as garbage (corrupt / data-level protection).
MAX_PLAUSIBLE_FORMAT_VERSION = 255

#: A declared bundle size above this (1 TiB) is treated as a corrupt field rather than a truncation.
MAX_PLAUSIBLE_BUNDLE_SIZE = 1 << 40

MAX_HEADER_STRING = 256
MAX_BLOCKS_INFO_UNCOMPRESSED = 64 * 1024 * 1024
DEFAULT_MAX_BLOCK = 256 * 1024 * 1024
DEFAULT_MAX_TOTAL = 4 * 1024 * 1024 * 1024
DEFAULT_CHUNK = 1024 * 1024
_HEAD_READ = 2 * MAX_HEADER_STRING + 64

ERROR_KINDS = (
    "bad_magic",
    "truncated",
    "bad_sizes",
    "unsupported_version",
    "unsupported_compression",
    "blocks_info_decompress_failed",
    "bad_blocks_info",
    "block_decompress_failed",
    "limit_exceeded",
)


class UnityFSError(Exception):
    """A UnityFS bundle could not be parsed; ``kind`` is one of ``ERROR_KINDS``."""

    def __init__(self, kind: str, message: str = "", *, offset: Optional[int] = None) -> None:
        text = f"{kind}: {message}" if message else kind
        super().__init__(text)
        self.kind = kind
        self.message = message
        self.offset = offset


_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")


def _parse_unity_version(text: str) -> Optional[Tuple[int, int, int]]:
    m = _VERSION_RE.match(text or "")
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _uses_new_flag_set(ver: Optional[Tuple[int, int, int]]) -> bool:
    """True when bit 0x200 means padding-at-start (UnityPy ``BundleFile.read_fs`` cut-offs)."""
    if ver is None:
        return False
    major = ver[0]
    if major < 2020:
        return False
    if major == 2020:
        return ver >= (2020, 3, 34)
    if major == 2021:
        return ver >= (2021, 3, 2)
    if major == 2022:
        return ver >= (2022, 1, 1)
    return True


@dataclass
class UnityFSHeader:
    """Fixed-size part of a bundle header.  For non-UnityFS signatures the size fields are 0."""

    signature: str
    format_version: int
    unity_version: str
    unity_revision: str
    size: int
    compressed_blocks_info_size: int
    uncompressed_blocks_info_size: int
    flags: int
    header_end: int
    file_size: int

    @property
    def is_unityfs(self) -> bool:
        return self.signature == SIGNATURE_FS

    @property
    def engine_version(self) -> Optional[Tuple[int, int, int]]:
        """Unity editor version, e.g. (2019, 4, 40); taken from the revision string if it parses."""
        return _parse_unity_version(self.unity_revision) or _parse_unity_version(self.unity_version)

    @property
    def compression(self) -> int:
        return self.flags & FLAG_COMPRESSION_MASK

    @property
    def blocks_info_at_end(self) -> bool:
        return bool(self.flags & FLAG_BLOCKS_INFO_AT_END)

    @property
    def blocks_info_combined(self) -> bool:
        return bool(self.flags & FLAG_BLOCKS_INFO_COMBINED)

    @property
    def new_flag_set(self) -> bool:
        return _uses_new_flag_set(self.engine_version)

    @property
    def padding_at_start(self) -> bool:
        return self.new_flag_set and bool(self.flags & FLAG_0x200)

    @property
    def encryption_flag(self) -> bool:
        """True when the flag bits claim asset-bundle encryption (a hint only; see module notes)."""
        if self.new_flag_set:
            return bool(self.flags & (FLAG_ENCRYPTION_NEW | FLAG_ENCRYPTION_OLD))
        return bool(self.flags & (FLAG_0x200 | FLAG_ENCRYPTION_OLD))

    @property
    def aligned_after_header(self) -> bool:
        if self.format_version >= 7:
            return True
        ver = self.engine_version
        return ver is not None and ver[0] == 2019 and ver >= (2019, 4, 15)

    def to_dict(self) -> dict:
        return {
            "signature": self.signature,
            "format_version": self.format_version,
            "unity_version": self.unity_version,
            "unity_revision": self.unity_revision,
            "size": self.size,
            "compressed_blocks_info_size": self.compressed_blocks_info_size,
            "uncompressed_blocks_info_size": self.uncompressed_blocks_info_size,
            "flags": self.flags,
            "compression": self.compression,
            "blocks_info_at_end": self.blocks_info_at_end,
            "padding_at_start": self.padding_at_start,
            "encryption_flag": self.encryption_flag,
            "header_end": self.header_end,
            "file_size": self.file_size,
        }


@dataclass
class StorageBlock:
    uncompressed_size: int
    compressed_size: int
    flags: int

    @property
    def compression(self) -> int:
        return self.flags & FLAG_COMPRESSION_MASK

    @property
    def streamed(self) -> bool:
        return bool(self.flags & BLOCK_FLAG_STREAMED)


@dataclass
class Node:
    offset: int
    size: int
    flags: int
    path: str


@dataclass
class BlocksInfo:
    uncompressed_data_hash: bytes
    blocks: List[StorageBlock] = field(default_factory=list)
    nodes: List[Node] = field(default_factory=list)
    blocks_info_offset: int = 0
    data_offset: int = 0

    @property
    def total_compressed(self) -> int:
        return sum(b.compressed_size for b in self.blocks)

    @property
    def total_uncompressed(self) -> int:
        return sum(b.uncompressed_size for b in self.blocks)

    @property
    def compression_types(self) -> List[int]:
        return sorted({b.compression for b in self.blocks})


# --------------------------------------------------------------------------- header


def _file_size(fileobj: BinaryIO) -> int:
    pos = fileobj.tell()
    try:
        return fileobj.seek(0, 2)
    finally:
        fileobj.seek(pos)


def _cstr(buf: bytes, pos: int) -> Tuple[str, int]:
    end = buf.find(b"\x00", pos, pos + MAX_HEADER_STRING + 1)
    if end < 0:
        if len(buf) - pos <= MAX_HEADER_STRING:
            raise UnityFSError("truncated", "unterminated header string", offset=pos)
        raise UnityFSError("bad_magic", "header string longer than 256 bytes", offset=pos)
    return buf[pos:end].decode("utf-8", "replace"), end + 1


def parse_header(fileobj: BinaryIO) -> UnityFSHeader:
    """Parse the bundle header at offset 0.  Raises ``UnityFSError``; never reads more than ~600 bytes."""
    fileobj.seek(0)
    head = fileobj.read(_HEAD_READ)
    file_size = _file_size(fileobj)

    sig_end = head.find(b"\x00", 0, 16)
    if sig_end < 0:
        raise UnityFSError("bad_magic", "no NUL-terminated signature in the first 16 bytes")
    signature = head[:sig_end].decode("latin-1")
    if signature not in KNOWN_SIGNATURES:
        raise UnityFSError("bad_magic", f"unknown signature {signature!r}")
    pos = sig_end + 1

    if pos + 4 > len(head):
        raise UnityFSError("truncated", "missing format version", offset=pos)
    (format_version,) = struct.unpack_from(">I", head, pos)
    pos += 4
    if format_version > MAX_PLAUSIBLE_FORMAT_VERSION:
        raise UnityFSError("unsupported_version", f"implausible format version {format_version}", offset=pos - 4)

    unity_version, pos = _cstr(head, pos)
    unity_revision, pos = _cstr(head, pos)

    if signature != SIGNATURE_FS:
        return UnityFSHeader(signature, format_version, unity_version, unity_revision, 0, 0, 0, 0, pos, file_size)

    if pos + 20 > len(head):
        raise UnityFSError("truncated", "header ends before the size/flags fields", offset=pos)
    size, csize, usize, flags = struct.unpack_from(">qIII", head, pos)
    pos += 20
    return UnityFSHeader(
        signature, format_version, unity_version, unity_revision, size, csize, usize, flags, pos, file_size
    )


# ------------------------------------------------------------------------ blocks info


def _align16(value: int) -> int:
    return (value + 15) & ~15


def _decompress(
    kind: int, data: bytes, expected: int, *, error_kind: str, what: str
) -> bytes:
    try:
        if kind == COMPRESSION_NONE:
            if len(data) != expected:
                raise UnityFSError("bad_sizes", f"{what}: stored size {len(data)} != declared {expected}")
            return data
        if kind == COMPRESSION_LZMA:
            return lz4.decompress_lzma_unity(data, expected_size=expected, max_output=max(expected, 0))
        if kind in (COMPRESSION_LZ4, COMPRESSION_LZ4HC):
            return lz4.decompress_block(data, max_output=max(expected, 0), expected_size=expected)
    except lz4.CompressionError as exc:
        raise UnityFSError(error_kind, f"{what}: {exc}") from exc
    if kind == COMPRESSION_LZHAM:
        raise UnityFSError("unsupported_compression", f"{what}: LZHAM is not supported")
    raise UnityFSError("unsupported_compression", f"{what}: unknown compression type {kind}")


def read_blocks_info(
    fileobj: BinaryIO,
    header: UnityFSHeader,
    *,
    max_blocks_info: int = MAX_BLOCKS_INFO_UNCOMPRESSED,
) -> BlocksInfo:
    """Locate, decompress and parse the BlocksInfo + node table of a ``UnityFS`` bundle."""
    if not header.is_unityfs:
        raise UnityFSError("unsupported_version", f"{header.signature} bundles are not supported")
    if header.format_version > MAX_KNOWN_FORMAT_VERSION:
        raise UnityFSError("unsupported_version", f"UnityFS format version {header.format_version}")

    file_size = header.file_size
    csize = header.compressed_blocks_info_size
    usize = header.uncompressed_blocks_info_size

    if header.size < header.header_end:
        raise UnityFSError("bad_sizes", f"declared bundle size {header.size} smaller than its header")
    if header.size > file_size:
        kind = "bad_sizes" if header.size > MAX_PLAUSIBLE_BUNDLE_SIZE else "truncated"
        raise UnityFSError(kind, f"declared bundle size {header.size} > file size {file_size}")
    if usize > max_blocks_info:
        raise UnityFSError("bad_sizes", f"uncompressed BlocksInfo size {usize} exceeds {max_blocks_info}")

    start = header.header_end
    if header.aligned_after_header:
        start = _align16(start)

    if header.blocks_info_at_end:
        bi_offset = file_size - csize
        data_offset = start
    else:
        bi_offset = start
        data_offset = start + csize
    if csize > file_size:
        raise UnityFSError("bad_sizes", f"compressed BlocksInfo size {csize} exceeds the file size")
    if bi_offset < start or bi_offset + csize > file_size:
        raise UnityFSError("truncated", "compressed BlocksInfo does not fit inside the file", offset=bi_offset)
    if header.padding_at_start:
        data_offset = _align16(data_offset)

    fileobj.seek(bi_offset)
    raw = fileobj.read(csize)
    if len(raw) != csize:
        raise UnityFSError("truncated", "short read of BlocksInfo", offset=bi_offset)
    raw = _decompress(
        header.compression, raw, usize, error_kind="blocks_info_decompress_failed", what="BlocksInfo"
    )

    info = _parse_blocks_info_table(raw)
    info.blocks_info_offset = bi_offset
    info.data_offset = data_offset

    # Cross-check the table against the file.
    limit = bi_offset if header.blocks_info_at_end else file_size
    if data_offset + info.total_compressed > limit:
        raise UnityFSError("truncated", "block data extends past the end of the bundle", offset=data_offset)
    if data_offset + info.total_compressed > header.size:
        raise UnityFSError("bad_sizes", "block data larger than the declared bundle size")
    total_u = info.total_uncompressed
    for node in info.nodes:
        if node.offset < 0 or node.size < 0 or node.offset + node.size > total_u:
            raise UnityFSError("bad_sizes", f"node {node.path!r} lies outside the decompressed data")
    return info


def _parse_blocks_info_table(raw: bytes) -> BlocksInfo:
    n = len(raw)
    if n < 20:
        raise UnityFSError("bad_blocks_info", "BlocksInfo shorter than its fixed part")
    digest = raw[:16]
    (count,) = struct.unpack_from(">i", raw, 16)
    pos = 20
    if count < 0 or count * 10 > n - pos:
        raise UnityFSError("bad_blocks_info", f"block count {count} does not fit in BlocksInfo")
    blocks: List[StorageBlock] = []
    for _ in range(count):
        usz, csz, fl = struct.unpack_from(">IIH", raw, pos)
        pos += 10
        if StorageBlock(usz, csz, fl).compression == COMPRESSION_NONE and usz != csz:
            raise UnityFSError("bad_sizes", "stored block declares different compressed and raw sizes")
        blocks.append(StorageBlock(usz, csz, fl))
    if pos + 4 > n:
        raise UnityFSError("bad_blocks_info", "BlocksInfo ends before the node count")
    (ncount,) = struct.unpack_from(">i", raw, pos)
    pos += 4
    if ncount < 0 or ncount * 21 > n - pos:
        raise UnityFSError("bad_blocks_info", f"node count {ncount} does not fit in BlocksInfo")
    nodes: List[Node] = []
    for _ in range(ncount):
        if pos + 20 > n:
            raise UnityFSError("bad_blocks_info", "node table truncated")
        off, size, fl = struct.unpack_from(">qqI", raw, pos)
        pos += 20
        end = raw.find(b"\x00", pos)
        if end < 0:
            raise UnityFSError("bad_blocks_info", "unterminated node path")
        nodes.append(Node(off, size, fl, raw[pos:end].decode("utf-8", "replace")))
        pos = end + 1
    return BlocksInfo(uncompressed_data_hash=digest, blocks=blocks, nodes=nodes)


def iter_decompressed(
    fileobj: BinaryIO,
    header: UnityFSHeader,
    blocks_info: BlocksInfo,
    *,
    max_total: int = DEFAULT_MAX_TOTAL,
    chunk: int = DEFAULT_CHUNK,
    max_block: int = DEFAULT_MAX_BLOCK,
) -> Iterator[bytes]:
    """Yield the decompressed block data in pieces of at most ``chunk`` bytes.

    Memory is bounded by the largest single block (<= ``max_block``).  Total output is capped
    at ``max_total``; exceeding either cap raises ``UnityFSError('limit_exceeded')``.  The first
    corrupt block raises ``block_decompress_failed`` (earlier chunks were already yielded).
    """
    if chunk <= 0:
        raise ValueError("chunk must be positive")
    produced = 0
    pos = blocks_info.data_offset
    for index, block in enumerate(blocks_info.blocks):
        if block.uncompressed_size > max_block:
            raise UnityFSError("limit_exceeded", f"block {index} declares {block.uncompressed_size} bytes")
        if produced + block.uncompressed_size > max_total:
            raise UnityFSError("limit_exceeded", f"decompressed data would exceed {max_total} bytes")
        fileobj.seek(pos)
        raw = fileobj.read(block.compressed_size)
        if len(raw) != block.compressed_size:
            raise UnityFSError("truncated", f"block {index} is cut short", offset=pos)
        pos += block.compressed_size
        data = _decompress(
            block.compression,
            raw,
            block.uncompressed_size,
            error_kind="block_decompress_failed",
            what=f"block {index}",
        )
        produced += len(data)
        view = memoryview(data)
        for i in range(0, len(data), chunk):
            yield bytes(view[i : i + chunk])


# ------------------------------------------------------------------------ probing


@dataclass
class VariantHypothesis:
    """Evidence-only guess about a non-standard header; the file is never rewritten."""

    kind: str  # "standard" | "offset_prefix" | "xor_single" | "xor_repeating"
    confidence: float
    offset: int = 0
    key: bytes = b""
    signature: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "confidence": self.confidence,
            "offset": self.offset,
            "key_hex": self.key.hex(),
            "signature": self.signature,
            "detail": self.detail,
        }


_SIG_BYTES = tuple(s.encode("ascii") + b"\x00" for s in KNOWN_SIGNATURES)
_PROBE_MAX_OFFSET = 4096


def _plausible_header_after_signature(buf: bytes, sig_len: int) -> bool:
    """version u32 BE small, then a printable NUL-terminated version string."""
    if len(buf) < sig_len + 4 + 2:
        return False
    (ver,) = struct.unpack_from(">I", buf, sig_len)
    if ver > 32:
        return False
    end = buf.find(b"\x00", sig_len + 4, sig_len + 4 + 64)
    if end <= sig_len + 4:
        return False
    return all(32 <= c < 127 for c in buf[sig_len + 4 : end])


def probe_variants(head: bytes) -> List[VariantHypothesis]:
    """Detect UnityFS-shaped headers that are not at offset 0 in plain form.

    * ``standard``: a known signature at offset 0.
    * ``offset_prefix``: a signature at offset 1..4095 (bundle wrapped in extra bytes).
    * ``xor_single`` / ``xor_repeating``: the first 8 bytes XOR ``UnityFS\\0`` give a constant
      byte or a period of 2..4 bytes; the hypothesis is then verified on the following header
      fields.  Only a *hypothesis* is returned -- nothing is decoded or extracted.
    """
    head = bytes(head)
    out: List[VariantHypothesis] = []

    for sig in _SIG_BYTES:
        if head.startswith(sig):
            out.append(VariantHypothesis("standard", 1.0, 0, b"", sig[:-1].decode("ascii")))
            return out

    best: Optional[Tuple[int, bytes]] = None
    for sig in _SIG_BYTES:
        idx = head.find(sig, 1, _PROBE_MAX_OFFSET + len(sig))
        if idx > 0 and (best is None or idx < best[0]):
            best = (idx, sig)
    if best is not None:
        idx, sig = best
        ok = _plausible_header_after_signature(head[idx:], len(sig))
        out.append(
            VariantHypothesis(
                "offset_prefix",
                0.9 if ok else 0.5,
                idx,
                b"",
                sig[:-1].decode("ascii"),
                "signature found after a prefix; following header fields "
                + ("look valid" if ok else "do not look valid"),
            )
        )

    plain = _SIG_BYTES[0]
    if len(head) >= len(plain):
        key8 = bytes(a ^ b for a, b in zip(head[: len(plain)], plain))
        if any(key8):
            period = 0
            for p in (1, 2, 3, 4):
                if all(key8[i] == key8[i % p] for i in range(len(key8))):
                    period = p
                    break
            if period:
                key = key8[:period]
                decoded = bytes(c ^ key[i % period] for i, c in enumerate(head[:128]))
                ok = _plausible_header_after_signature(decoded, len(plain))
                kind = "xor_single" if period == 1 else "xor_repeating"
                base = 0.9 if period == 1 else 0.75
                out.append(
                    VariantHypothesis(
                        kind,
                        base if ok else 0.35,
                        0,
                        key,
                        SIGNATURE_FS,
                        "first 8 bytes XOR 'UnityFS\\0' give a "
                        + ("constant" if period == 1 else f"period-{period}")
                        + " key; header continuation "
                        + ("decodes plausibly" if ok else "could not be confirmed"),
                    )
                )
    return out
