from __future__ import annotations

import io
import random
import struct
import time
import tracemalloc

import pytest

from fixtures.formats_builder import (
    build_unityfs,
    build_unityfs_ex,
    build_unityfs_variants,
    lz4_compress_block,
)
from ipa_analyzer.formats import unityfs
from ipa_analyzer.formats.unityfs import UnityFSError


def _blocks(count=3):
    rng = random.Random(3)
    out = []
    for i in range(count):
        out.append(b"block%d " % i * 400 + rng.randbytes(300))
    return out


def _open(data: bytes):
    f = io.BytesIO(data)
    header = unityfs.parse_header(f)
    info = unityfs.read_blocks_info(f, header)
    return f, header, info


@pytest.mark.parametrize("compression", ["none", "lz4", "lz4hc", "lzma"])
@pytest.mark.parametrize("at_end", [False, True])
@pytest.mark.parametrize("nblocks", [1, 5])
def test_roundtrip_matrix(compression, at_end, nblocks):
    blocks = _blocks(nblocks)
    data = build_unityfs(blocks, compression=compression, blocks_info_at_end=at_end)
    f, header, info = _open(data)
    assert header.signature == "UnityFS"
    assert header.blocks_info_at_end is at_end
    assert header.size == len(data)
    assert len(info.blocks) == nblocks
    assert info.total_uncompressed == sum(len(b) for b in blocks)
    assert info.nodes[0].path.startswith("CAB-")
    assert b"".join(unityfs.iter_decompressed(f, header, info, chunk=777)) == b"".join(blocks)


@pytest.mark.parametrize("compression", ["none", "lz4", "lzma"])
@pytest.mark.parametrize("at_end", [False, True])
def test_format_version_7_alignment_and_padding(compression, at_end):
    blocks = _blocks(2)
    data = build_unityfs(
        blocks,
        compression=compression,
        blocks_info_at_end=at_end,
        format_version=7,
        engine_version="2021.3.20f1",
        padding_at_start=True,
    )
    f, header, info = _open(data)
    assert header.format_version == 7 and header.padding_at_start
    assert info.data_offset % 16 == 0
    assert b"".join(unityfs.iter_decompressed(f, header, info)) == b"".join(blocks)


def test_mixed_block_compression_and_custom_nodes():
    blocks = [b"a" * 1000, b"b" * 1000, b"c" * 1000]
    nodes = [("one.assets", 0, 1500, 4), ("one.assets.resS", 1500, 1500, 0)]
    data = build_unityfs(blocks, compression=["none", "lz4", "lzma"], blocks_info_compression="lz4", nodes=nodes)
    f, header, info = _open(data)
    assert [b.compression for b in info.blocks] == [0, 2, 1]
    assert [n.path for n in info.nodes] == ["one.assets", "one.assets.resS"]
    assert b"".join(unityfs.iter_decompressed(f, header, info)) == b"".join(blocks)
    assert info.compression_types == [0, 1, 2]


def test_header_fields_and_flag_semantics():
    data = build_unityfs(_blocks(1), engine_version="2019.4.40f1", format_version=6)
    header = unityfs.parse_header(io.BytesIO(data))
    assert header.unity_version == "5.x.x"
    assert header.unity_revision == "2019.4.40f1"
    assert header.engine_version == (2019, 4, 40)
    assert header.aligned_after_header  # UnityPy quirk: 2019.4.15+ aligns even for format 6
    old = unityfs.parse_header(io.BytesIO(build_unityfs(_blocks(1), engine_version="2018.4.1f1")))
    assert not old.aligned_after_header
    # flag 0x200 means "encrypted" for old Unity, "padding at start" for new Unity
    flagged_old = build_unityfs_ex(_blocks(1), engine_version="2019.4.1f1", flags_extra=0x200)
    h = unityfs.parse_header(io.BytesIO(flagged_old.data))
    assert h.encryption_flag and not h.padding_at_start
    flagged_new = build_unityfs_ex(_blocks(1), engine_version="2022.3.5f1", flags_extra=0x200)
    h = unityfs.parse_header(io.BytesIO(flagged_new.data))
    assert h.padding_at_start and not h.encryption_flag


@pytest.mark.parametrize("sig", ["UnityWeb", "UnityRaw", "UnityArchive"])
def test_other_signatures_recognised_but_unsupported(sig):
    data = build_unityfs(_blocks(1), signature=sig)
    f = io.BytesIO(data)
    header = unityfs.parse_header(f)
    assert header.signature == sig and not header.is_unityfs
    with pytest.raises(UnityFSError) as exc:
        unityfs.read_blocks_info(f, header)
    assert exc.value.kind == "unsupported_version"


# ----------------------------------------------------------------------------- errors


def test_bad_magic_and_tiny_inputs():
    for blob in (b"", b"Un", b"PK\x03\x04" + b"\x00" * 100, b"UnityXX\x00" + b"\x00" * 50, b"\xff" * 300):
        with pytest.raises(UnityFSError) as exc:
            unityfs.parse_header(io.BytesIO(blob))
        assert exc.value.kind in ("bad_magic", "truncated")
    with pytest.raises(UnityFSError) as exc:
        unityfs.parse_header(io.BytesIO(b"PK\x03\x04" + b"\x00" * 100))
    assert exc.value.kind == "bad_magic"


def test_truncated_at_every_layer():
    good = build_unityfs_ex(_blocks(3), compression="lz4")
    kinds = set()
    for cut in (4, 9, 12, 20, good.header_end - 6, good.header_end + 3, good.blocks_info_offset + good.blocks_info_length // 2,
                good.data_offset + 10, len(good.data) - 1):
        blob = good.data[:cut]
        try:
            f = io.BytesIO(blob)
            h = unityfs.parse_header(f)
            info = unityfs.read_blocks_info(f, h)
            b"".join(unityfs.iter_decompressed(f, h, info))
        except UnityFSError as exc:
            kinds.add(exc.kind)
        else:
            pytest.fail(f"cut at {cut} was accepted")
    assert kinds <= {"bad_magic", "truncated", "bad_sizes"}
    assert "truncated" in kinds


def test_truncated_when_blocks_info_at_end():
    good = build_unityfs_ex(_blocks(3), blocks_info_at_end=True)
    with pytest.raises(UnityFSError) as exc:
        _open(good.data[: len(good.data) - 5])
    assert exc.value.kind in ("truncated", "blocks_info_decompress_failed", "bad_sizes")


def test_huge_size_field_is_bad_sizes_or_truncated():
    good = build_unityfs_ex(_blocks(2))
    for value, kinds in ((1 << 62, {"bad_sizes"}), (len(good.data) + 1000, {"truncated"}), (-5, {"bad_sizes"}), (3, {"bad_sizes"})):
        with pytest.raises(UnityFSError) as exc:
            _open(good.patched(good.size_field_offset, ">q", value))
        assert exc.value.kind in kinds, (value, exc.value.kind)


def test_blocks_info_size_fields_lie():
    good = build_unityfs_ex(_blocks(2))
    with pytest.raises(UnityFSError) as e1:  # compressed size larger than the file
        _open(good.patched(good.csize_field_offset, ">I", 0xFFFFFFF0))
    assert e1.value.kind in ("bad_sizes", "truncated")
    with pytest.raises(UnityFSError) as e2:  # absurd uncompressed size
        _open(good.patched(good.usize_field_offset, ">I", 0xFFFFFFF0))
    assert e2.value.kind == "bad_sizes"
    with pytest.raises(UnityFSError) as e3:  # declared uncompressed size does not match the content
        _open(good.patched(good.usize_field_offset, ">I", 12345))
    assert e3.value.kind == "blocks_info_decompress_failed"
    with pytest.raises(UnityFSError) as e4:  # compressed size too small => LZ4 stream cut short
        _open(good.patched(good.csize_field_offset, ">I", 6))
    assert e4.value.kind in ("blocks_info_decompress_failed", "truncated", "bad_blocks_info", "bad_sizes")


def test_unsupported_compression_and_version():
    good = build_unityfs_ex(_blocks(1))
    with pytest.raises(UnityFSError) as exc:
        _open(good.patched(good.flags_field_offset, ">I", 0x40 | 4))  # LZHAM
    assert exc.value.kind == "unsupported_compression"
    with pytest.raises(UnityFSError) as exc:
        _open(good.patched(good.flags_field_offset, ">I", 0x40 | 9))
    assert exc.value.kind == "unsupported_compression"
    with pytest.raises(UnityFSError) as exc:
        _open(build_unityfs(_blocks(1), format_version=99))
    assert exc.value.kind == "unsupported_version"
    with pytest.raises(UnityFSError) as exc:
        unityfs.parse_header(io.BytesIO(build_unityfs(_blocks(1), format_version=0x7FFFFFFF)))
    assert exc.value.kind == "unsupported_version"


def test_corrupt_blocks_info_content_is_detected():
    good = build_unityfs_ex(_blocks(2), compression="none")
    buf = bytearray(good.data)
    buf[good.blocks_info_offset + 16 : good.blocks_info_offset + 20] = struct.pack(">i", 1 << 28)  # huge block count
    with pytest.raises(UnityFSError) as exc:
        _open(bytes(buf))
    assert exc.value.kind == "bad_blocks_info"
    buf = bytearray(good.data)
    buf[good.blocks_info_offset + 16 : good.blocks_info_offset + 20] = struct.pack(">i", -1)
    with pytest.raises(UnityFSError) as exc:
        _open(bytes(buf))
    assert exc.value.kind == "bad_blocks_info"


def test_node_outside_data_is_bad_sizes():
    data = build_unityfs(_blocks(1), nodes=[("x", 0, 10_000_000, 4)])
    with pytest.raises(UnityFSError) as exc:
        _open(data)
    assert exc.value.kind == "bad_sizes"


def test_block_data_corruption_yields_block_error():
    good = build_unityfs_ex(_blocks(2), compression="lz4")
    buf = bytearray(good.data)
    for i in range(good.data_offset, good.data_offset + 40):
        buf[i] = 0xFF
    f, h, info = _open(bytes(buf))
    with pytest.raises(UnityFSError) as exc:
        list(unityfs.iter_decompressed(f, h, info))
    assert exc.value.kind == "block_decompress_failed"


def test_malicious_lz4_inside_block_is_contained():
    # a block whose declared uncompressed size is small but whose LZ4 stream wants to expand hugely
    bomb = bytes([0x1F]) + b"a" + struct.pack("<H", 1) + b"\xff" * 50_000 + b"\x00"
    good = build_unityfs_ex([b"x" * 100], compression="none")
    # re-pack: replace the stored block with the bomb and mark it LZ4 with a small declared size
    raw_blocks_info = b"\x00" * 16 + struct.pack(">i", 1) + struct.pack(">IIH", 100, len(bomb), 2)
    raw_blocks_info += struct.pack(">i", 1) + struct.pack(">qqI", 0, 100, 4) + b"n\x00"
    head = good.data[: good.size_field_offset]
    total = good.header_end + len(raw_blocks_info) + len(bomb)
    flags = 0 | 0x40
    data = head + struct.pack(">qIII", total, len(raw_blocks_info), len(raw_blocks_info), flags) + raw_blocks_info + bomb
    f, h, info = _open(data)
    tracemalloc.start()
    start = time.monotonic()
    with pytest.raises(UnityFSError) as exc:
        list(unityfs.iter_decompressed(f, h, info))
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert exc.value.kind == "block_decompress_failed"
    assert peak < 20 * 1024 * 1024
    assert time.monotonic() - start < 5


def test_iter_limits():
    data = build_unityfs([b"z" * 10_000, b"y" * 10_000], compression="lz4")
    f, h, info = _open(data)
    with pytest.raises(UnityFSError) as exc:
        list(unityfs.iter_decompressed(f, h, info, max_total=15_000))
    assert exc.value.kind == "limit_exceeded"
    with pytest.raises(UnityFSError) as exc:
        list(unityfs.iter_decompressed(f, h, info, max_block=5_000))
    assert exc.value.kind == "limit_exceeded"
    pieces = list(unityfs.iter_decompressed(f, h, info, chunk=4096))
    assert all(len(p) <= 4096 for p in pieces) and len(b"".join(pieces)) == 20_000
    with pytest.raises(ValueError):
        list(unityfs.iter_decompressed(f, h, info, chunk=0))


def test_stored_block_size_mismatch():
    raw = b"\x00" * 16 + struct.pack(">i", 1) + struct.pack(">IIH", 100, 50, 0) + struct.pack(">i", 0)
    good = build_unityfs_ex([b"x"], compression="none")
    head = good.data[: good.size_field_offset]
    total = good.header_end + len(raw) + 50
    data = head + struct.pack(">qIII", total, len(raw), len(raw), 0x40) + raw + b"\x00" * 50
    with pytest.raises(UnityFSError) as exc:
        _open(data)
    assert exc.value.kind == "bad_sizes"


def test_fuzzed_bytes_never_raise_other_exceptions():
    good = build_unityfs(_blocks(2), compression="lz4")
    rng = random.Random(11)
    deadline = time.monotonic() + 20
    for _ in range(400):
        buf = bytearray(good)
        for _ in range(rng.randrange(1, 6)):
            buf[rng.randrange(len(buf))] = rng.randrange(256)
        if rng.random() < 0.3:
            buf = buf[: rng.randrange(len(buf))]
        try:
            f = io.BytesIO(bytes(buf))
            h = unityfs.parse_header(f)
            info = unityfs.read_blocks_info(f, h)
            for _chunk in unityfs.iter_decompressed(f, h, info, max_total=1 << 22):
                pass
        except UnityFSError as exc:
            assert exc.kind in unityfs.ERROR_KINDS
        assert time.monotonic() < deadline


# ------------------------------------------------------------------------------ probe


def test_probe_standard():
    data = build_unityfs(_blocks(1))
    hyp = unityfs.probe_variants(data[:4096])
    assert [h.kind for h in hyp] == ["standard"]


def test_probe_variants_detects_each_shape():
    variants = build_unityfs_variants(_blocks(2))
    got = {name: unityfs.probe_variants(blob[:4096]) for name, blob in variants.items()}
    assert [h.kind for h in got["standard"]] == ["standard"]

    prefix = got["offset_prefix"]
    assert len(prefix) == 1 and prefix[0].kind == "offset_prefix" and prefix[0].offset == 37
    assert prefix[0].confidence >= 0.9

    single = [h for h in got["xor_single"] if h.kind == "xor_single"]
    assert single and single[0].key == b"\x5a" and single[0].confidence >= 0.9

    rep = [h for h in got["xor_repeating"] if h.kind == "xor_repeating"]
    assert rep and rep[0].key == b"\x13\x37\xab"

    assert got["high_entropy"] == []


def test_probe_edge_cases():
    assert unityfs.probe_variants(b"") == []
    assert unityfs.probe_variants(b"Unity") == []
    assert unityfs.probe_variants(b"\x00" * 64) == []  # zero key is not "XOR"
    assert unityfs.probe_variants(b"hello world, this is plain text" * 10) == []
    d = unityfs.probe_variants(build_unityfs(_blocks(1))[:64])[0].to_dict()
    assert d["kind"] == "standard" and d["key_hex"] == ""


def test_xor_wrong_continuation_gets_low_confidence():
    # signature XORs to a constant key but the remainder is not a plausible header
    key = 0x21
    fake = bytes(b ^ key for b in b"UnityFS\x00") + b"\xff" * 40
    hyp = unityfs.probe_variants(fake)
    assert hyp and hyp[0].kind == "xor_single" and hyp[0].confidence < 0.5


def test_lz4_encoder_used_by_builder_matches_decoder_on_large_block():
    big = random.Random(0).randbytes(200_000) + b"abc" * 100_000
    from ipa_analyzer.formats import lz4

    assert lz4.decompress_block(lz4_compress_block(big), expected_size=len(big)) == big


def test_iter_refuses_oversized_compressed_block_before_reading_it():
    # declared uncompressed size is small but the compressed size is huge: never read it into memory
    class NoRead:
        def seek(self, *_a):
            raise AssertionError("must not seek")

        def read(self, *_a):
            raise AssertionError("must not read")

    info = unityfs.BlocksInfo(uncompressed_data_hash=b"", blocks=[unityfs.StorageBlock(1000, 1 << 30, 3)], nodes=[])
    with pytest.raises(UnityFSError) as exc:
        list(unityfs.iter_decompressed(NoRead(), None, info))
    assert exc.value.kind == "limit_exceeded"
