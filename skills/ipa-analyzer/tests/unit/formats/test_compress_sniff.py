from __future__ import annotations

import bz2
import gzip
import lzma
import random
import zlib

import pytest

from fixtures.formats_builder import lz4_compress_block, lzma_compress_unity
from ipa_analyzer.formats.compress_sniff import sniff

PAYLOAD = b"Lua scripts and assets " * 200


@pytest.mark.parametrize("level", [1, 6, 9, 0])
def test_zlib_levels(level):
    g = sniff(zlib.compress(PAYLOAD, level))
    assert g.kind == "zlib" and g.confidence >= 0.8


@pytest.mark.parametrize("head", [b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"])
def test_zlib_common_headers(head):
    assert sniff(head + b"\x00" * 10).kind == "zlib"


def test_zlib_checks_fcheck_and_fdict():
    assert sniff(b"\x78\x02" + b"\x00" * 10).kind != "zlib"  # fails (CMF*256+FLG) % 31
    assert sniff(b"\x78\x20" + b"\x00" * 10).kind != "zlib"
    assert sniff(b"\x79\x01" + b"\x00" * 10).kind != "zlib"  # CM != 8


def test_gzip():
    g = sniff(gzip.compress(PAYLOAD))
    assert g.kind == "gzip" and g.confidence >= 0.9


def test_lz4_frame():
    assert sniff(b"\x04\x22\x4d\x18\x64\x40\xa7").kind == "lz4_frame"
    assert sniff(b"\x04\x22\x4d\x18\x04").confidence < 0.9  # version bits wrong


def test_zstd():
    assert sniff(b"\x28\xb5\x2f\xfd" + b"\x00" * 8).kind == "zstd"


def test_bzip2_and_xz():
    g = sniff(bz2.compress(PAYLOAD))
    assert g.kind == "bzip2" and g.confidence >= 0.95
    assert sniff(b"BZh9").kind == "bzip2" and sniff(b"BZh0abcdef").kind != "bzip2"
    x = sniff(lzma.compress(PAYLOAD))
    assert x.kind == "xz" and x.confidence >= 0.95


def test_lzma_is_low_confidence():
    alone = lzma.compress(PAYLOAD, format=lzma.FORMAT_ALONE)
    g = sniff(alone)
    assert g.kind == "lzma" and g.confidence <= 0.5
    raw = sniff(lzma_compress_unity(PAYLOAD, dict_size=1 << 23))
    assert raw.kind == "lzma" and raw.confidence <= 0.3


def test_random_data_is_not_compression():
    rng = random.Random(3)
    hits = 0
    for _ in range(2000):
        g = sniff(rng.randbytes(64))
        if g.kind != "none":
            hits += 1
            assert g.confidence <= 0.6 or g.kind in ("bzip2", "xz", "zstd", "lz4_frame", "gzip")
    assert hits < 60  # zlib-shaped false positives are possible but rare


def test_plain_text_and_empty():
    for blob in (b"", b"a", b"hello world, this is just text", b"{\"json\": true}", b"\x1bLua\x53\x00\x19\x93", b"MZ\x90\x00", b"UnityFS\x00"):
        assert sniff(blob).kind == "none", blob


def test_raw_lz4_block_has_no_magic():
    assert sniff(lz4_compress_block(PAYLOAD)).kind in ("none", "zlib", "lzma")  # headerless: only a weak guess at best


def test_to_dict():
    d = sniff(gzip.compress(b"x")).to_dict()
    assert d["kind"] == "gzip" and 0 < d["confidence"] <= 1
