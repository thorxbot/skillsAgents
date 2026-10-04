"""Programmatic Unity samples (no real app data anywhere): metadata files, SerializedFile headers, bundle
variants and whole synthetic app trees.  UnityFS / PE-CLI / LZ4 primitives come from ``formats_builder``.

Stable entry points::

    build_metadata(version=31, variant="normal", ...)   -> bytes     (see METADATA_VARIANTS)
    build_serialized_file(unity_version, ...)           -> bytes     (SerializedFile prefix, formats >= 9)
    build_standard_bundle(compression="lz4", ...)       -> bytes
    build_block_encrypted_bundle(...)                   -> bytes     (standard header + BlocksInfo, bad LZ4 blocks)
    build_unity_app(...)                                -> dict[name, bytes]  for ``ipa_builder.build_ipa``

Header sizes are written down independently of the module under test: legacy v31 = 8 + 31*8 = 256 and
v39 = 8 + 31*12 = 380 (both measured on real samples), v24 (sub-version 24.5) = 8 + 32*8 = 264 and v27
(27.2) = 8 + 31*8 = 256 (derived by hand from Il2CppDumper's ``Il2CppGlobalMetadataHeader``).
"""
from __future__ import annotations

import random
import struct
from typing import Dict, List, Optional, Sequence

from fixtures.formats_builder import build_pe_cli, build_unityfs, build_unityfs_ex
from fixtures.macho_builder import build_macho

MAGIC = 0xFAB11BAF
#: version -> (entry size, number of section descriptors, index of the string section)
LAYOUT = {24: (8, 32, 2), 27: (8, 31, 2), 29: (8, 31, 2), 31: (8, 31, 2), 39: (12, 31, 2)}
METADATA_VARIANTS = ("normal", "wrong_magic", "wrong_magic_garbage", "random", "xor_strings", "xor_header",
                     "offset_prefix", "bad_header", "truncated", "empty")

_FRAMEWORK_NAMES = (
    b"mscorlib", b"System", b"System.Collections.Generic", b"UnityEngine", b"UnityEngine.CoreModule",
    b"Assembly-CSharp", b"<Module>", b"MonoBehaviour", b"GameObject", b"Transform", b"Vector3", b"List`1",
    b"Dictionary`2", b"String", b"Object", b"Int32", b"Update", b"Start", b"Awake", b"get_transform",
)


def _identifier_table(count: int, rng: random.Random, obfuscated: bool = False,
                      extra: Sequence[str] = ()) -> bytes:
    parts: List[bytes] = list(_FRAMEWORK_NAMES) + [e.encode("utf-8") for e in extra]
    for i in range(count):
        if obfuscated:
            parts.append(bytes(rng.choice(b"abcdefghij") for _ in range(rng.choice((1, 2)))))
        else:
            parts.append(b"Game%sManager%d" % (rng.choice((b"Core", b"Net", b"Ui", b"Audio")), i))
    return b"\x00".join(parts) + b"\x00"


def _filler(n: int, rng: random.Random) -> bytes:
    """Structured-looking low-entropy binary data (small little-endian integers)."""
    out = bytearray()
    while len(out) < n:
        out += struct.pack("<I", rng.randrange(0, 4000))
    return bytes(out[:n])


def build_metadata(version: int = 31, variant: str = "normal", *, names: int = 600, seed: int = 11,
                   obfuscated: bool = False, xor_key: int = 0x5A, extra_identifiers: Sequence[str] = ()) -> bytes:
    """A synthetic ``global-metadata.dat`` with a real section table, readable string table and filler data.

    ``extra_identifiers`` are appended to the identifier pool (e.g. ``["HybridCLR", "XLua"]``) without disturbing
    the random generator, so the default output is byte-identical to before.
    """
    if variant not in METADATA_VARIANTS:
        raise ValueError(variant)
    if variant == "empty":
        return b""
    rng = random.Random(seed)
    entry, nsec, str_idx = LAYOUT[version]
    header_size = 8 + entry * nsec
    strings = _identifier_table(names, rng, obfuscated, extra_identifiers)
    body = bytearray()
    sections = []
    pos = header_size
    for i in range(nsec):
        if i == str_idx:
            data = strings
        elif i % 7 == 3:
            data = b""                        # a few empty sections, as in real files
        else:
            data = _filler(rng.choice((256, 512, 1024, 2048)), rng)
        data += b"\x00" * (-len(data) % 4)
        sections.append((pos if data else pos, len(data), len(data) // 4))
        body += data
        pos += len(data)
    head = bytearray(struct.pack("<Ii", MAGIC, version))
    for off, size, count in sections:
        head += struct.pack("<ii", off, size)
        if entry == 12:
            head += struct.pack("<i", count)
    assert len(head) == header_size
    blob = bytes(head) + bytes(body)
    str_off, str_size = sections[str_idx][0], sections[str_idx][1]

    if variant == "normal":
        return blob
    if variant == "wrong_magic":                       # magic changed, everything else intact (low entropy)
        return b"\xde\xad\xbe\xef" + blob[4:]
    if variant == "wrong_magic_garbage":               # magic and version both garbage, low entropy body
        return b"\x13\x37\x13\x37\xff\xff\xff\x7f" + blob[8:]
    if variant == "random":
        return random.Random(seed + 1).randbytes(len(blob))
    if variant == "xor_strings":                       # magic, version and header intact; identifiers XORed
        buf = bytearray(blob)
        for i in range(str_off, str_off + str_size):
            buf[i] ^= xor_key
        return bytes(buf)
    if variant == "xor_header":                        # whole file XORed with a single byte
        return bytes(b ^ xor_key for b in blob)
    if variant == "offset_prefix":
        return b"\x01\x02\x03\x04" * 8 + blob
    if variant == "bad_header":                        # section table points far outside the file
        buf = bytearray(blob)
        struct.pack_into("<ii", buf, 8 + 3 * entry, len(blob) * 4, 4096)
        return bytes(buf)
    if variant == "truncated":
        return blob[: header_size - 20]
    raise AssertionError(variant)


# ---------------------------------------------------------------------------------- SerializedFile
def build_serialized_file(unity_version: str = "2021.3.16f1", *, format_version: int = 22, platform: int = 9,
                          tail: int = 256) -> bytes:
    """Prefix of a SerializedFile (big-endian header fields, little-endian target platform) plus filler."""
    ver = unity_version.encode("ascii") + b"\x00"
    if format_version >= 22:
        head = struct.pack(">IIII", 0, 0, format_version, 0) + b"\x00\x00\x00\x00"
        head += struct.pack(">IqqQ", 100, 4096, 128, 0)
    else:
        head = struct.pack(">IIII", 100, 4096, format_version, 128) + b"\x00\x00\x00\x00"
    return head + ver + struct.pack("<i", platform) + b"\x01" + b"\x00" * tail


# ---------------------------------------------------------------------------------------- bundles
def _bundle_blocks(n_blocks: int, block_size: int, seed: int) -> List[bytes]:
    rng = random.Random(seed)
    return [bytes(rng.choice(b"abcdefgh01") for _ in range(block_size)) for _ in range(n_blocks)]


def build_standard_bundle(compression: str = "lz4", *, n_blocks: int = 3, block_size: int = 4096, seed: int = 3,
                          engine_version: str = "2021.3.16f1") -> bytes:
    return build_unityfs(_bundle_blocks(n_blocks, block_size, seed), compression=compression,
                         engine_version=engine_version, format_version=6)


def build_block_encrypted_bundle(*, n_blocks: int = 6, block_size: int = 8192, seed: int = 5,
                                 marker: bytes = b"\xd8\xd3\x33\xcd\x3b\xd8\xec\xa4", compression: str = "lz4",
                                 engine_version: str = "2021.3.16f1") -> bytes:
    """Standard header + readable BlocksInfo, but every LZ4 data block is ``noise + marker + noise`` (the marker
    sits at a different offset in each block, inside the first 256 bytes)."""
    rng = random.Random(seed)
    built = build_unityfs_ex(_bundle_blocks(n_blocks, block_size, seed), compression=compression,
                             engine_version=engine_version, format_version=6)
    data = bytearray(built.data)
    # locate compressed block boundaries by re-reading the BlocksInfo through the builder's own layout
    import io
    from ipa_analyzer.formats import unityfs
    fh = io.BytesIO(bytes(data))
    info = unityfs.read_blocks_info(fh, unityfs.parse_header(fh))
    pos = info.data_offset
    for i, blk in enumerate(info.blocks):
        junk = bytearray(rng.randbytes(blk.compressed_size))
        at = 16 + (i * 13) % 100
        junk[at: at + len(marker)] = marker
        junk[0] = 0xF0                       # a literal run longer than the block: never a valid LZ4 block
        for j in range(1, min(4, len(junk))):
            junk[j] = 0xFF
        data[pos: pos + blk.compressed_size] = junk
        pos += blk.compressed_size
    return bytes(data)


def build_bundle_variants(seed: int = 7) -> Dict[str, bytes]:
    """standard (lz4 / lz4hc / lzma / none), offset_prefix, xor_single, xor_repeating, high_entropy."""
    from fixtures.formats_builder import build_unityfs_variants
    out = dict(build_unityfs_variants(_bundle_blocks(3, 4096, seed), seed=seed, compression="lz4"))
    for comp in ("none", "lzma", "lz4hc"):
        out["standard_" + comp] = build_standard_bundle(comp)
    out["standard_lz4"] = out["standard"]
    return out


# ------------------------------------------------------------------------------------------ app tree
def il2cpp_binary(*, encrypted: bool = False, with_markers: bool = True, unity_string: Optional[str] = None) -> bytes:
    strings: List[str] = []
    if with_markers:
        strings += ["il2cpp_init", "il2cpp_runtime_invoke", "il2cpp_string_new", "UnityMain"]
    if unity_string:
        strings.append(unity_string)
    return build_macho(arch="arm64", filetype="dylib", encrypted=encrypted, cryptid=1 if encrypted else 0,
                       strings=strings)


def build_unity_app(*, backend: str = "il2cpp", metadata_version: int = 24, metadata_variant: str = "normal",
                    encrypted_binary: bool = False, unity_version: str = "2021.3.16f1",
                    bundles: Optional[Dict[str, bytes]] = None, with_binary_markers: bool = True,
                    binary_unity_string: Optional[str] = None, extra: Optional[Dict[str, bytes]] = None,
                    dlls: Optional[Dict[str, bytes]] = None) -> Dict[str, bytes]:
    """Files (relative to the .app) of a synthetic Unity app; ``backend`` is ``il2cpp`` | ``mono`` | ``none``."""
    files: Dict[str, bytes] = {"Data/globalgamemanagers": build_serialized_file(unity_version),
                               "Data/level0": build_serialized_file(unity_version)}
    if backend == "il2cpp":
        files["Data/Managed/Metadata/global-metadata.dat"] = build_metadata(metadata_version, metadata_variant)
        files["Frameworks/UnityFramework.framework/UnityFramework"] = il2cpp_binary(
            encrypted=encrypted_binary, with_markers=with_binary_markers, unity_string=binary_unity_string)
    elif backend == "mono":
        files["Data/Managed/Assembly-CSharp.dll"] = build_pe_cli("Assembly-CSharp", ["mscorlib", "UnityEngine"], 5)
        files["Data/Managed/UnityEngine.dll"] = build_pe_cli("UnityEngine", ["mscorlib"], 5)
    for name, data in (dlls or {}).items():
        files["Data/Managed/" + name] = data
    for name, data in (bundles or {}).items():
        files[name] = data
    files.update(extra or {})
    return files


def mono_samples() -> Dict[str, bytes]:
    """Three Mono cases: a genuine assembly, random non-PE data, and a PE image without CLI metadata."""
    good = build_pe_cli("Assembly-CSharp", ["mscorlib", "UnityEngine"], 5)
    pe_no_cli = good.replace(b"BSJB", b"XXXX")
    return {"good": good, "random": random.Random(9).randbytes(len(good)), "pe_no_cli": pe_no_cli}
