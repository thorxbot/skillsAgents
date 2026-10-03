from __future__ import annotations

import random
import struct
import time

import pytest

from fixtures.formats_builder import lz4_compress_block, lzma_compress_unity
from ipa_analyzer.formats import lz4


def _samples():
    rng = random.Random(42)
    yield b""
    yield b"a"
    yield b"abcabcabcabcabcabcabcabc" * 3
    yield bytes(range(256)) * 20
    yield b"\x00" * 100_000
    yield rng.randbytes(5000)
    yield b" ".join(rng.choice([b"lua", b"unity", b"bundle", b"x"]) for _ in range(4000))


@pytest.mark.parametrize("data", list(_samples()))
def test_roundtrip_with_expected_size(data):
    comp = lz4_compress_block(data)
    assert lz4.decompress_block(comp, expected_size=len(data)) == data
    assert lz4.decompress_block(comp) == data


def test_known_vector_overlapping_match():
    # token 0x1F: 1 literal 'a', then match len 4+15+ext, offset 1 => run of 'a'
    comp = bytes([0x1F]) + b"a" + struct.pack("<H", 1) + bytes([10]) + bytes([0x50]) + b"zzzzz"
    out = lz4.decompress_block(comp)
    assert out == b"a" * (1 + 4 + 15 + 10) + b"zzzzz"


def test_literals_only_block():
    assert lz4.decompress_block(bytes([0x30]) + b"abc") == b"abc"


@pytest.mark.parametrize(
    "block,kind",
    [
        (bytes([0x10]), "truncated"),  # literal missing
        (bytes([0xF0]), "truncated"),  # literal length extension missing
        (bytes([0x10]) + b"a" + b"\x01", "truncated"),  # offset cut in half
        (bytes([0x10]) + b"a" + struct.pack("<H", 0), "bad_offset"),  # offset 0
        (bytes([0x10]) + b"a" + struct.pack("<H", 2), "bad_offset"),  # beyond history
        (bytes([0x1F]) + b"a" + struct.pack("<H", 1), "truncated"),  # match length extension missing
    ],
)
def test_malformed_blocks(block, kind):
    with pytest.raises(lz4.CompressionError) as exc:
        lz4.decompress_block(block)
    assert exc.value.kind == kind


def test_expected_size_mismatch_and_overrun():
    comp = lz4_compress_block(b"hello world, hello world, hello world")
    with pytest.raises(lz4.CompressionError) as e1:
        lz4.decompress_block(comp, expected_size=10)
    assert e1.value.kind == "output_too_large"
    with pytest.raises(lz4.CompressionError) as e2:
        lz4.decompress_block(comp, expected_size=1000)
    assert e2.value.kind == "size_mismatch"


def test_declared_size_over_limit_rejected_without_allocating():
    with pytest.raises(lz4.CompressionError) as exc:
        lz4.decompress_block(b"\x00", expected_size=1 << 40, max_output=1 << 20)
    assert exc.value.kind == "output_too_large"


def test_decompression_bomb_is_capped_quickly():
    # one literal then a match whose length extension is a megabyte of 0xFF => ~255 MB declared
    bomb = bytes([0x1F]) + b"a" + struct.pack("<H", 1) + b"\xff" * (1 << 20) + b"\x00"
    start = time.monotonic()
    with pytest.raises(lz4.CompressionError) as exc:
        lz4.decompress_block(bomb, max_output=1 << 20)
    assert exc.value.kind == "output_too_large"
    assert time.monotonic() - start < 5


def test_long_literal_run_bomb():
    data = bytes([0xF0]) + b"\xff" * (1 << 16) + b"\x00"
    with pytest.raises(lz4.CompressionError) as exc:
        lz4.decompress_block(data, max_output=1000)
    assert exc.value.kind in ("output_too_large", "truncated")


def test_random_garbage_never_crashes():
    rng = random.Random(5)
    for _ in range(500):
        blob = rng.randbytes(rng.randrange(0, 300))
        try:
            lz4.decompress_block(blob, max_output=1 << 16)
        except lz4.CompressionError:
            pass


def test_lzma_unity_roundtrip_both_header_styles():
    data = b"unity bundle payload " * 500
    packed = lzma_compress_unity(data)
    assert lz4.decompress_lzma_unity(packed, expected_size=len(data)) == data
    assert lz4.decompress_lzma_unity(packed[5:], packed[:5], expected_size=len(data)) == data


def test_lzma_unity_limits_and_errors():
    data = b"A" * 100_000
    packed = lzma_compress_unity(data)
    with pytest.raises(lz4.CompressionError) as e1:
        lz4.decompress_lzma_unity(packed, expected_size=10)
    assert e1.value.kind in ("output_too_large", "size_mismatch")
    with pytest.raises(lz4.CompressionError) as e2:
        lz4.decompress_lzma_unity(packed, max_output=1000)
    assert e2.value.kind == "output_too_large"
    with pytest.raises(lz4.CompressionError) as e3:
        lz4.decompress_lzma_unity(packed, expected_size=len(data) + 50)
    assert e3.value.kind in ("size_mismatch", "decode_error")
    with pytest.raises(lz4.CompressionError) as e4:
        lz4.decompress_lzma_unity(b"\x5d\x00")
    assert e4.value.kind == "truncated"
    with pytest.raises(lz4.CompressionError) as e5:
        lz4.decompress_lzma_unity(b"\xff\x00\x00\x10\x00rest")
    assert e5.value.kind == "bad_header"
    huge_dict = struct.pack("<BI", 0x5D, 0xFFFFFFFF) + b"\x00" * 20
    with pytest.raises(lz4.CompressionError) as e6:
        lz4.decompress_lzma_unity(huge_dict)
    assert e6.value.kind == "dict_too_large"
    with pytest.raises(lz4.CompressionError):
        lz4.decompress_lzma_unity(b"\x5d\x00\x00\x10\x00" + b"\xff" * 64, expected_size=1000)
