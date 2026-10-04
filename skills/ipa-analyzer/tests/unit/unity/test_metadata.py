"""global-metadata.dat analysis: the four verdict situations plus layouts, versions and malformed input."""
from __future__ import annotations

import pytest

from fixtures.unity_builder import LAYOUT, build_metadata
from ipa_analyzer.unity import metadata as um


def run(data: bytes) -> um.MetadataAnalysis:
    return um.analyze_metadata_bytes(data)


@pytest.mark.parametrize("version", sorted(LAYOUT))
def test_normal_metadata_is_no(version):
    a = run(build_metadata(version))
    assert a.verdict == "no", a.reasons
    assert a.magic_ok and a.version == version and a.header_ok is True and a.string_region_ok is True
    assert a.confidence >= 0.8
    assert a.supported_by            # version inside some backend's range


def test_header_sizes_match_hand_derived_values():
    # independent of the module's tables: measured on real samples (31, 39) / derived from Il2CppDumper (24)
    assert um.header_layout(31).header_size == 256
    assert um.header_layout(39).header_size == 380
    assert um.header_layout(24, 264).header_size == 264
    assert um.header_layout(24, 272).header_size == 272      # 24.0/24.1 variant carries rgctxEntries
    assert um.header_layout(15) is None and um.header_layout(36) is None


def test_wrong_magic_low_entropy_is_suspected():
    a = run(build_metadata(31, "wrong_magic"))
    assert a.verdict == "suspected" and not a.magic_ok
    assert "magic_modified" in a.reasons and a.version == 31
    a2 = run(build_metadata(31, "wrong_magic_garbage"))
    assert a2.verdict == "suspected" and "wrong_magic_low_entropy" in a2.reasons


def test_random_high_entropy_is_yes():
    a = run(build_metadata(31, "random", names=3000))
    assert a.verdict == "yes" and "high_entropy" in a.reasons and a.entropy >= um.HIGH_ENTROPY


def test_xor_strings_is_suspected_with_key_hypothesis():
    a = run(build_metadata(31, "xor_strings", xor_key=0x5A))
    assert a.verdict == "suspected" and a.magic_ok and a.header_ok is True
    assert a.string_region_ok is False and "string_region_unreadable" in a.reasons
    keys = [h["key"] for h in a.hypotheses if h["type"] == "xor_string_region"]
    assert 0x5A in keys


def test_xor_header_hypothesis_is_recorded_not_applied():
    a = run(build_metadata(29, "xor_header", xor_key=0x42))
    assert a.verdict == "suspected" and "xor_header" in a.reasons
    h = next(h for h in a.hypotheses if h["type"] == "xor_header")
    assert h["key_hex"] == "42" and h["period"] == 1 and h["version"] == 29


def test_offset_prefix_is_suspected():
    a = run(build_metadata(31, "offset_prefix"))
    assert a.verdict == "suspected" and "offset_prefix" in a.reasons
    assert next(h for h in a.hypotheses if h["type"] == "offset_prefix")["offset"] == 32


def test_bad_section_table_is_suspected():
    a = run(build_metadata(31, "bad_header"))
    assert a.verdict == "suspected" and a.header_ok is False and "header_inconsistent" in a.reasons
    assert any(d.startswith("out_of_file") for d in a.header.decisive)


@pytest.mark.parametrize("variant", ["truncated", "empty"])
def test_truncated_and_empty_do_not_crash(variant):
    a = run(build_metadata(31, variant))
    assert a.verdict in ("suspected", "yes") and a.verdict != "no"


def test_version_beyond_every_backend_is_suspected_not_no():
    data = bytearray(build_metadata(31))
    data[4:8] = (200).to_bytes(4, "little")
    a = run(bytes(data))
    assert a.version == 200 and a.version_known is False and a.verdict == "suspected"
    assert "version_out_of_range" in a.reasons


def test_version_beyond_dumper_but_inside_other_backends_is_no():
    a = run(build_metadata(39))
    assert a.verdict == "no"
    assert "il2cppdumper" not in a.supported_by and {"cpp2il", "redux"} <= set(a.supported_by)
    assert "cpp2il" in a.needs_unity_version


def test_backend_support_uses_the_catalog():
    cat = {"backends": {"a": {"metadata_versions": {"min": 20, "max": 30}},
                        "b": {"metadata_versions": {"min": 25, "max": 40}, "requires_unity_version": True}}}
    s = um.backend_support(28, cat)
    assert s["supported_by"] == ["a", "b"] and s["needs_unity_version"] == ["b"]
    assert um.backend_support(50, cat)["known"] is False
    assert um.version_range(cat) == (20, 40)


def test_tiny_garbage_file():
    a = run(b"\x00" * 10)
    assert a.verdict == "suspected" and "empty_or_short" in a.reasons


def test_obfuscated_identifiers_are_flagged_but_metadata_is_still_plain():
    data = build_metadata(31, obfuscated=True, names=800)
    a = run(data)
    assert a.verdict == "no"
    import io
    with io.BytesIO(data) as fh:
        stats = um.identifier_stats(um.string_region_info(fh, a.string_region))
    assert stats["level"] == "high" and stats["short_ratio"] > 0.5
    plain = build_metadata(31, names=800)
    with io.BytesIO(plain) as fh:
        a2 = run(plain)
        assert um.identifier_stats(um.string_region_info(fh, a2.string_region))["level"] == "none"


def test_evidence_lines_are_strings():
    a = run(build_metadata(31, "xor_strings"))
    lines = um.evidence_lines(a)
    assert lines and all(isinstance(k, str) and isinstance(d, str) for k, d in lines)
    assert a.to_dict()["verdict"] == "suspected"
