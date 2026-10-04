from __future__ import annotations

import gzip
import lzma
import struct
import zlib

import pytest

from fixtures.engine_builder import pak_with_zlib_blocks, random_blob, text_corpus, xor_png
from ipa_analyzer.engines import containers as C


def reader(data: bytes):
    return lambda off, n: data[off:off + n]


def analyze(data: bytes, **kw):
    return C.analyze_container(reader(data), len(data), path=kw.pop("path", "res/x.dat"), ext=kw.pop("ext", ".dat"), **kw)


# --- the four classes of the work package -----------------------------------------------------------------------------
def test_zlib_block_container_with_offset_table_is_custom_format_not_encrypted():
    r = analyze(pak_with_zlib_blocks(blocks=30, block_size=8000), ext=".pak")
    assert r.verdict == "custom_format" and r.compression == "zlib" and r.confidence <= C.MAX_CONFIDENCE
    assert r.header["offset_table"]["run"] >= 30 and r.header["offset_table"]["stride"] == 3
    assert r.streams["verified"] >= 8
    assert any("compression structure" in e.detail and "not encrypted" in e.detail for e in r.evidence)
    assert r.entropy is not None and r.xor_hypothesis is None


def test_random_uniform_blob_is_suspected_encrypted():
    r = analyze(random_blob(200_000))
    assert r.verdict == "encrypted_suspected" and r.entropy > 7.9 and r.confidence <= C.MAX_CONFIDENCE
    assert r.compression is None and "offset_table" not in r.header and r.xor_hypothesis is None


def test_plain_json_is_plain():
    data = b'{"levels": [' + b",".join(b'{"id": %d, "name": "stage"}' % i for i in range(2000)) + b"]}"
    r = analyze(data, ext=".json")
    assert r.verdict == "plain" and r.confidence >= 0.7 and r.entropy < 6


def test_single_byte_xor_png_gets_a_hypothesis_but_is_not_decoded():
    r = analyze(xor_png(0x5A), ext=".dat")
    assert r.xor_hypothesis == {"format": "png", "kind": "single_byte", "key_hex": "5a", "confidence": 0.6,
                                "note": "header equals the png signature XOR 0x5a"}
    assert r.verdict == "encrypted_suspected" and r.confidence <= 0.6
    assert any("XOR 0x5a" in e.detail for e in r.evidence)


def test_compressed_is_not_reported_as_encrypted():
    for blob, kind in ((zlib.compress(text_corpus(300_000)), "zlib"), (gzip.compress(text_corpus(300_000)), "gzip"),
                       (lzma.compress(text_corpus(300_000), format=lzma.FORMAT_ALONE), "lzma")):
        r = analyze(blob)
        assert r.verdict == "compressed" and r.compression == kind, (kind, r.verdict, r.compression)


def test_high_entropy_stream_without_structure_stays_suspected_only():
    r = analyze(random_blob(100_000, seed=2), ext=".bin")
    assert r.verdict in ("encrypted_suspected", "unknown") and r.confidence <= 0.6


def test_ascii_tag_with_size_field_is_a_custom_container_even_if_payload_is_opaque():
    body = random_blob(50_000, seed=9)
    data = b"NHPK" + struct.pack("<I", 8 + len(body)) + body
    r = analyze(data, ext=".json")
    assert r.verdict == "custom_format" and r.header["magic_ascii"] == "NHPK" and r.header["size_field"]["index"] == 1
    assert r.payload_hypothesis == "high_entropy_unknown"


# --- building blocks ------------------------------------------------------------------------------------------------------
def test_offset_table_detection_parameters():
    words = [100 + 60 * i for i in range(20)]
    head = struct.pack("<20I", *words) + b"\xff" * 100
    t = C.find_offset_table(head, 5000)
    assert t["run"] == 20 and t["stride"] == 1 and t["first"] == 100 and t["offsets"][:2] == [100, 160]
    # records of (offset, size) pairs: the offset column is found
    recs = []
    for i in range(16):
        recs += [1000 + 100 * i, 100]
    t = C.find_offset_table(struct.pack("<32I", *recs), 5000)
    assert t["stride"] == 2 and t["column"] == 0 and t["run"] == 16
    assert C.find_offset_table(b"\x00" * 64, 1000) is None
    # random words rarely form a table; values outside the file never do
    assert C.find_offset_table(random_blob(4096, 3), 1 << 20) is None
    assert C.find_offset_table(struct.pack("<16I", *range(1000, 17000, 1000)), 5000) is None      # all > file size
    assert C.find_offset_table(struct.pack("<16I", *range(1, 17)), 5000) is None                   # counters, not offsets


def test_offset_table_is_found_in_either_byte_order_and_64_bit():
    be = struct.pack(">12I", *[256 + 40 * i for i in range(12)])
    assert C.find_offset_table(be, 4000)["endian"] == ">"
    q = struct.pack("<10Q", *[512 + 64 * i for i in range(10)])
    assert C.find_offset_table(q, 4000)["width"] in (4, 8)


def test_size_field():
    head = struct.pack("<4I", 0x4B50484E, 12345, 7, 9)
    assert C.find_size_field(head, 12345)["index"] == 1
    assert C.find_size_field(head, 999) is None and C.find_size_field(b"", 10) is None


def test_xor_probe_variants_and_non_matches():
    key = 0x37
    unity = bytes(b ^ key for b in b"UnityFS\x00\x00\x00\x00\x00")
    assert C.xor_probe(unity)["format"] == "unityfs"
    plain_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
    assert C.xor_probe(plain_png) is None                                     # not obfuscated at all
    rep = bytes(b ^ k for b, k in zip(b"SQLite format 3\x00", b"\xa1\xb2" * 10))
    h = C.xor_probe(rep + b"\x00" * 8)
    assert h and h["kind"] == "repeating" and h["key_hex"] == "a1b2"
    assert C.xor_probe(random_blob(64)) is None and C.xor_probe(b"abc") is None
    # a fake IHDR check protects against coincidences
    bad = bytes(b ^ 0x11 for b in b"\x89PNG\r\n\x1a\n") + b"\x00" * 16
    assert C.xor_probe(bad) is None


def test_trial_inflation_distinguishes_real_streams_from_random_lookalikes():
    real = zlib.compress(text_corpus(50_000))
    assert C.find_streams(real)[0]["status"] == "verified"
    fake = b"\x78\x9c" + random_blob(5000, seed=4)
    assert [s for s in C.find_streams(fake) if s["status"] == "verified"] == []
    big = b"\x78\x9c" + random_blob(300_000, seed=5)
    assert not [s for s in C.find_streams(big) if s["status"] in ("verified", "probable")]


def test_stream_magic_hits_and_anchoring():
    z = b"\x28\xb5\x2f\xfd" + b"\x00" * 16
    assert C.find_streams(z)[0]["kind"] == "zstd" and C.find_streams(b"xx" + z)[0]["offset"] == 2
    assert C.find_streams(b"xx" + z, anchored=True) == []
    lz4 = b"\x04\x22\x4d\x18" + b"\x64" + b"\x00" * 16
    assert C.find_streams(lz4)[0]["kind"] == "lz4_frame"
    deflate = zlib.compress(text_corpus(9000))
    assert C.find_streams(b"\x01\x02" + deflate, anchored=True) == []
    assert C.find_streams(deflate, anchored=True)[0]["status"] == "verified"


def test_companions_and_pairs():
    sib = ["a/data.pck", "a/data.pkx", "a/data.idx", "a/other.pkx", "b/data.pkx", "a/data.png"]
    assert C.find_companions("a/data.pck", sib) == ["a/data.idx", "a/data.pkx"]
    assert C.find_companions("a/game.arcd", ["a/game.arci", "a/game.projectc"]) == ["a/game.arci"]
    assert C.find_companions("noext", ["noext.idx"]) == ["noext.idx"]


def test_companion_is_reported_in_the_analysis():
    r = analyze(random_blob(30_000), path="a/data.pck", ext=".pck", siblings=["a/data.pck", "a/data.pkx"])
    assert r.header["companions"] == ["a/data.pkx"] and any(e.kind == "file" for e in r.evidence)


# --- degenerate inputs -----------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("data", [b"", b"\x00", b"ab", b"\x00" * 5000, b"\xff" * 100])
def test_tiny_and_constant_inputs_do_not_crash(data):
    r = analyze(data)
    assert r.verdict in ("unknown", "plain", "custom_format", "encrypted_suspected", "compressed")
    assert r.confidence <= C.MAX_CONFIDENCE


def test_unreadable_file_is_unknown():
    r = C.analyze_container(lambda o, n: b"", 1000, path="x")
    assert r.verdict == "unknown" and r.evidence


def test_truncated_zlib_block_does_not_raise():
    blob = zlib.compress(text_corpus(60_000))[:2000]
    r = analyze(blob)
    assert r.verdict in ("compressed", "unknown", "plain", "encrypted_suspected")


# --- candidate selection ----------------------------------------------------------------------------------------------------
def row(path, size, ext, magic="unknown", cat="other"):
    return {"path": path, "size": size, "ext": ext, "magic": magic, "category": cat}


def test_candidate_rules():
    assert C.is_candidate("a.bin", 2 << 20, ".bin", "unknown") and C.is_candidate("a.pak", 5000, ".pak", "unknown")
    assert not C.is_candidate("a.txt", 5000, ".txt", "unknown")                      # small, ordinary extension
    assert not C.is_candidate("a.bin", 2 << 20, ".bin", "png")                         # known magic
    assert not C.is_candidate("a.bin", 2 << 20, ".bin", "unknown", "signing")          # SC_Info
    assert not C.is_candidate("a.assets", 2 << 20, ".assets", "unknown", "engine_data")
    assert C.is_candidate("a.bin", 2 << 20, ".bin", "empty") is True


def test_selection_spreads_over_directories_and_respects_limit():
    rows = [row("shards/%d.bin" % i, (10 - i) << 20, ".bin") for i in range(6)] + [row("other/big.dat", 3 << 20, ".dat")]
    cands, deep = C.select_candidates(rows, limit=3)
    assert len(cands) == 7 and len(deep) == 3
    assert "other/big.dat" in [d["path"] for d in deep] and deep[0]["path"] == "shards/0.bin"
    assert C.select_candidates(rows, limit=0)[1] == []


# --- header clusters --------------------------------------------------------------------------------------------------------------
def cluster_files(n=30, header=b"NHPK"):
    entries = {}
    for i in range(n):
        body = b'{"id": %d}' % i * 5
        data = header + struct.pack("<I", 8 + len(body)) + body
        entries["f/%d.json" % i] = data
    return entries


def test_cluster_with_size_field_and_standard_payload():
    ents = {}
    for i in range(25):
        body = b"\x89PNG\r\n\x1a\n" + bytes([i]) * 40
        ents["g/%d.png" % i] = b"NHPT" + struct.pack("<I", 20 + len(body)) + b"\x00" * 4 + b"\x01\x02\x03\x04\x05\x06\x07\x08" + body
    rows = [(p, len(d), ".png", d[:16]) for p, d in ents.items()]
    cl = C.cluster_headers(rows, lambda p, n: ents[p][:n])
    assert len(cl) == 1 and cl[0].header_ascii == "NHPT" and cl[0].count == 25
    assert cl[0].payload["standard_after_header"] == "png" and cl[0].payload["header_len"] == 20
    assert cl[0].payload["size_field"]["offset"] == 4 and cl[0].ext_mismatch == {".png": 25}
    assert cl[0].verdict == "custom_format" and 0.6 <= cl[0].confidence <= C.MAX_CONFIDENCE
    hit = cl[0].to_hit()
    assert hit.id == "header-cluster:NHPT" and hit.extra["kind"] == "header_cluster" and hit.extra["count"] == 25


def test_cluster_opaque_payload_and_thresholds():
    ents = cluster_files(30)
    rows = [(p, len(d), ".json", d[:16]) for p, d in ents.items()]
    cl = C.cluster_headers(rows, lambda p, n: ents[p][:n])
    assert cl and cl[0].header_ascii == "NHPK" and cl[0].payload["size_field"]["fraction"] == 1.0
    assert C.cluster_headers(rows[:10], lambda p, n: ents[p][:n]) == []                  # below MIN_CLUSTER
    assert C.cluster_headers(rows, lambda p, n: ents[p][:n], min_count=40) == []


def test_cluster_ignores_tiny_binary_records_without_an_ascii_tag():
    rows = [("r/%d.bin" % i, 12, ".bin", b"\x01\x01\x00\x00" + bytes(12)) for i in range(40)]
    assert C.cluster_headers(rows, lambda p, n: b"\x01\x01\x00\x00" * 3) == []


def test_cluster_read_errors_are_tolerated():
    ents = cluster_files(25)
    rows = [(p, len(d), ".json", d[:16]) for p, d in ents.items()]

    def bad(p, n):
        raise OSError("boom")

    cl = C.cluster_headers(rows, bad)
    assert cl and cl[0].payload["probed"] == 0
