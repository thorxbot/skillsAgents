"""AssetBundle classification, deep checks and aggregation on programmatic bundles."""
from __future__ import annotations

import io
import random
import struct
from types import SimpleNamespace

from fixtures.formats_builder import build_unityfs, build_unityfs_ex
from fixtures.unity_builder import (build_block_encrypted_bundle, build_bundle_variants, build_standard_bundle)
from ipa_analyzer.unity import bundles as ub


class MemSource:
    """Minimal ArchiveSource double over ``{name: bytes}``."""

    def __init__(self, files):
        self.files = dict(files)

    def read_head(self, name, n):
        return self.files[name][:n]

    def open(self, name):
        return io.BytesIO(self.files[name])

    def stat(self, name):
        n = len(self.files[name])
        return SimpleNamespace(size=n, compressed_size=n)


def analyze(files, why="ext", **kw):
    cands = [{"path": p, "size": len(d), "magic": "", "why": why} for p, d in sorted(files.items())]
    return ub.analyze_bundles(cands, MemSource(files), **kw)


# ---------------------------------------------------------------------------- header-level classes
def test_every_header_class():
    v = build_bundle_variants()
    cls = {k: ub.classify_head(d[: ub.HEAD_READ], len(d))[0] for k, d in v.items()}
    assert cls["standard"] == cls["standard_none"] == cls["standard_lzma"] == cls["standard_lz4hc"] == "standard"
    assert cls["offset_prefix"] == "offset_prefix"
    assert cls["xor_single"] == "xor_simple" and cls["xor_repeating"] == "xor_simple"
    assert cls["high_entropy"] == "high_entropy_unknown"


def test_xor_key_hypothesis_is_recovered():
    v = build_bundle_variants()
    _, d1 = ub.classify_head(v["xor_single"][:4096], len(v["xor_single"]))
    assert d1["key_hex"] == "5a" and d1["period"] == 1
    _, d3 = ub.classify_head(v["xor_repeating"][:4096], len(v["xor_repeating"]))
    assert d3["key_hex"] == "1337ab" and d3["period"] == 3
    _, dp = ub.classify_head(v["offset_prefix"][:4096], len(v["offset_prefix"]))
    assert dp["offset"] == 37


def test_known_formats_and_compression_are_other_not_encrypted():
    png = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 40
    cls, d = ub.classify_head(png, len(png))
    assert cls == "other" and d["format"] == "png"
    zlib_like = b"\x78\x9c" + random.Random(1).randbytes(8000)
    assert ub.classify_head(zlib_like, len(zlib_like))[0] == "other"
    text = b"csvconfigs_assets_csv_achievements.bundle\n" * 100
    assert ub.classify_head(text, len(text), "text")[0] == "other"


def test_entropy_thresholds_scale_with_size():
    rnd = random.Random(2).randbytes(1500)
    assert ub.classify_head(rnd, 1500)[0] == "high_entropy_unknown"       # small file: entropy capped at ~7.9
    low = bytes(range(32)) * 200
    assert ub.classify_head(low, len(low))[0] == "unknown"
    assert ub.classify_head(b"", 0)[0] == "unknown"


# ------------------------------------------------------------------------------------ aggregation
def test_all_standard_is_no():
    v = build_bundle_variants()
    files = {"a/%d.bundle" % i: v[k] for i, k in enumerate(["standard", "standard_none", "standard_lzma", "standard_lz4hc"])}
    r = analyze(files)
    assert r["verdict"] == "no" and r["by_class"]["standard"] == 4
    assert r["deep"]["ok"] == 4 and r["deep"]["fail"] == 0
    assert set(r["compression"]) <= {"lz4", "lz4hc", "lzma", "none"} and sum(r["compression"].values()) == 4
    assert r["unity_versions"] == {"2018.4.36f1": 1, "2021.3.16f1": 3}
    assert r["paths_sample"] and r["total"] == 4


def test_each_standard_compression_alone_is_no():
    for comp in ("none", "lz4", "lz4hc", "lzma"):
        r = analyze({"x.bundle": build_standard_bundle(comp)})
        assert r["verdict"] == "no", comp
        assert r["deep"]["ok"] == 1


def test_offset_prefix_is_classified_and_not_no():
    v = build_bundle_variants()
    r = analyze({"p%d.bundle" % i: v["offset_prefix"] for i in range(3)})
    assert r["by_class"]["offset_prefix"] == 3 and r["verdict"] == "suspected"


def test_xor_bundles_report_key_hypothesis_and_yes():
    v = build_bundle_variants()
    r = analyze({"x%d.bundle" % i: v["xor_single"] for i in range(4)})
    assert r["by_class"]["xor_simple"] == 4 and r["verdict"] == "yes"
    assert r["xor_hypotheses"] == [{"key_hex": "5a", "period": 1}]


def test_random_bundles_are_yes():
    v = build_bundle_variants()
    files = {"r%d.bundle" % i: random.Random(i).randbytes(20000) for i in range(6)}
    r = analyze(files)
    assert r["by_class"]["high_entropy_unknown"] == 6 and r["verdict"] == "yes" and r["confidence"] >= 0.85
    assert r["entropy_samples"]["high_entropy_files"] == 6


def test_mixed_80_20_is_suspected():
    v = build_bundle_variants()
    files = {"s%02d.bundle" % i: v["standard"] for i in range(8)}
    files.update({"h%d.bundle" % i: random.Random(i).randbytes(9000) for i in range(2)})
    r = analyze(files)
    assert r["by_class"]["standard"] == 8 and r["by_class"]["high_entropy_unknown"] == 2
    assert r["verdict"] == "suspected"


def test_no_bundles_is_unknown():
    r = analyze({})
    assert r["verdict"] == "unknown" and r["total"] == 0 and r["paths_sample"] == []
    assert set(r["by_class"]) >= {"standard", "offset_prefix", "xor_simple", "high_entropy_unknown",
                                  "block_encrypted_suspected", "other", "unknown"}


# ------------------------------------------------------------------------ block-level encryption
def test_block_encrypted_bundle_is_flagged_with_marker_evidence():
    data = build_block_encrypted_bundle()
    r = analyze({"enc.bundle": data})
    assert r["by_class"]["block_encrypted_suspected"] == 1 and r["by_class"]["standard"] == 0
    assert r["verdict"] == "suspected" and r["deep"]["block_encrypted"] == 1
    m = r["block_markers"][0]
    assert m["marker_hex"].startswith("d8d333cd3bd8eca4") and m["fixed_position"] is False
    assert m["blocks_with_marker"] == m["blocks_sampled"] == 6


def test_normal_lz4_blocks_are_not_misjudged_as_block_encrypted():
    for comp in ("lz4", "lz4hc"):
        data = build_standard_bundle(comp, n_blocks=8)
        r = analyze({"ok.bundle": data})
        assert r["by_class"]["block_encrypted_suspected"] == 0 and r["by_class"]["standard"] == 1


def test_block_encrypted_header_stays_standard_to_shallow_checks():
    data = build_block_encrypted_bundle()
    assert ub.classify_head(data[:ub.HEAD_READ], len(data))[0] == "standard"


def test_find_common_marker():
    rng = random.Random(1)
    chunks = []
    for i in range(6):
        c = bytearray(rng.randbytes(256))
        c[20 + 9 * i: 28 + 9 * i] = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        chunks.append(bytes(c))
    m = ub.find_common_marker(chunks, min_len=6)
    assert m and m["length"] >= 8 and not m["fixed_position"] and m["blocks_with_marker"] == 6
    assert ub.find_common_marker([rng.randbytes(256) for _ in range(6)], min_len=6) is None
    assert ub.find_common_marker([b"x" * 300], min_len=6) is None


# --------------------------------------------------------------------- malformed / hostile input
def test_truncated_bundle_does_not_crash():
    full = build_standard_bundle("lz4", n_blocks=4)
    for cut in (20, 60, len(full) // 2, len(full) - 5):
        r = analyze({"t.bundle": full[:cut]})
        assert r["total"] == 1 and r["verdict"] in ("no", "suspected", "yes", "unknown")
    r = analyze({"t.bundle": full[: len(full) // 2]})
    assert r["deep"]["fail"] == 1 and r["verdict"] != "no"


def test_huge_size_fields_are_rejected_without_allocating():
    built = build_unityfs_ex([bytes(4096)] * 2, compression="lz4")
    for offset, fmt, value in ((built.size_field_offset, ">q", 1 << 50), (built.usize_field_offset, ">I", 0xFFFFFFF0),
                               (built.csize_field_offset, ">I", 0xFFFFFFF0)):
        data = built.patched(offset, fmt, value)
        res = ub.deep_check(io.BytesIO(data), len(data))
        assert res["status"] == "fail" and res["error"] in ("bad_sizes", "truncated")


def test_blocks_info_compression_mismatch_is_a_failure():
    built = build_unityfs_ex([bytes(4096)] * 2, compression="lz4")
    data = built.patched(built.flags_field_offset, ">I", struct.unpack_from(">I", built.data, built.flags_field_offset)[0] ^ 0x3)
    res = ub.deep_check(io.BytesIO(data), len(data))
    assert res["status"] == "fail" and res["stage"] == "blocks_info"


def test_block_declaring_giant_output_is_skipped_not_allocated():
    # one LZ4 block that claims 1 GiB of output: the deep check must not try to decode it
    data = build_unityfs([b"\x00" * 64], compression="lz4")
    fh = io.BytesIO(data)
    from ipa_analyzer.formats import unityfs
    info = unityfs.read_blocks_info(fh, unityfs.parse_header(fh))
    info.blocks[0].uncompressed_size = 1 << 30
    status, err = ub._test_block(fh, info, ub._block_offsets(info), 0)
    assert status == "skipped" and err == "large_block"


def test_unityweb_signature_is_not_deep_checked():
    data = b"UnityWeb\x00" + struct.pack(">I", 3) + b"5.x.x\x00" + b"2018.4.1f1\x00" + b"\x00" * 64
    res = ub.deep_check(io.BytesIO(data), len(data))
    assert res["status"] == "unsupported"
    assert ub.classify_head(data, len(data))[0] == "standard"


def test_unreadable_candidate_is_unknown():
    class Broken(MemSource):
        def read_head(self, name, n):
            raise OSError("boom")
    r = ub.analyze_bundles([{"path": "a.bundle", "size": 100, "magic": "", "why": "ext"}], Broken({}))
    assert r["by_class"]["unknown"] == 1


# --------------------------------------------------------------------------- sampling and limits
def test_deep_sample_limit_and_paths_sample_cap():
    std = build_standard_bundle("lz4")
    files = {"d/%04d.bundle" % i: std for i in range(60)}
    r = analyze(files, deep_sample=10, paths_sample=7)
    assert 10 <= r["sampled"] <= 11 and len(r["paths_sample"]) == 7 and r["total"] == 60
    assert all(len(v) <= 10 for v in r["samples"].values())
    r2 = analyze(files, deep_sample=0)
    assert r2["sampled"] == 0 and r2["verdict"] == "no"


# ------------------------------------------------------------------------------------- discovery
def rows(*items):
    return [{"path": "Payload/A.app/" + p, "size": s, "magic": m, "category": c} for p, s, m, c in items]


def test_select_candidates_rules():
    rel = lambda n: n[len("Payload/A.app/"):]
    files = rows(("Data/Raw/a.bundle", 5000, "unknown", "assetbundle"), ("Data/Raw/b.b", 5000, "unknown", "other"),
                 ("Data/Raw/c", 5000, "unknown", "other"), ("Data/Raw/c.manifest", 5000, "unknown", "other"),
                 ("Data/Raw/m.ogg", 5000, "ogg", "audio"), ("Data/data.unity3d", 5000, "unityfs", "assetbundle"),
                 ("res/z.bytes", 5000, "unknown", "other"), ("res/q.dat", 5000, "unknown", "other"),
                 ("Data/Raw/aa/catalog.bin", 5000, "unknown", "other"), ("Data/Raw/tiny.b", 10, "unknown", "other"),
                 ("Data/Raw/aa/x.hash", 40, "unknown", "other"))
    got = {c["rel"]: c["why"] for c in ub.select_candidates(files, rel)}
    assert got == {"Data/Raw/a.bundle": "ext", "Data/Raw/b.b": "ext", "Data/Raw/c": "location",
                   "Data/data.unity3d": "magic", "res/z.bytes": "weak_ext"}


def test_location_only_and_weak_hits_do_not_count_against_the_population():
    std = build_standard_bundle("lz4")
    files = {"Data/Raw/ok.bundle": std, "Data/Raw/config": b"\x01\x02" * 200, "res/t.bytes": random.Random(3).randbytes(5000)}
    cands = [{"path": "Data/Raw/ok.bundle", "size": len(std), "magic": "", "why": "ext"},
             {"path": "Data/Raw/config", "size": 400, "magic": "", "why": "location"},
             {"path": "res/t.bytes", "size": 5000, "magic": "", "why": "weak_ext"}]
    r = ub.analyze_bundles(cands, MemSource(files))
    assert r["population"] == 1 and r["verdict"] == "no"


def test_addressables_detection():
    pairs = [("P/A.app/Data/Raw/aa/catalog.bin", "Data/Raw/aa/catalog.bin"),
             ("P/A.app/Data/Raw/aa/settings.json", "Data/Raw/aa/settings.json"),
             ("P/A.app/Data/Raw/aa_remote/v1/catalog_1.0.json", "Data/Raw/aa_remote/v1/catalog_1.0.json"),
             ("P/A.app/Data/Raw/aa/iOS/x.bundle", "Data/Raw/aa/iOS/x.bundle"),
             ("P/A.app/Data/Raw/other.json", "Data/Raw/other.json")]
    a = ub.detect_addressables(pairs)
    assert a["catalog_found"] and a["settings_found"] and len(a["catalogs"]) == 2 and a["aa_files"] >= 3
    assert ub.detect_addressables([("x", "Data/Raw/a.json")])["catalog_found"] is False
