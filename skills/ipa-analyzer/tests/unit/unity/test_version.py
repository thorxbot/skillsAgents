"""Unity version parsing and cross-source resolution (including conflicts)."""
from __future__ import annotations

import pytest

from fixtures.unity_builder import build_serialized_file
from ipa_analyzer.unity import version as uv


@pytest.mark.parametrize("text,core,suffix", [
    ("2022.3.62f3c1", "2022.3.62f3", "c1"), ("6000.3.10f1", "6000.3.10f1", ""), ("5.6.7f1", "5.6.7f1", ""),
    ("2019.4.40f1c1", "2019.4.40f1", "c1"), ("2021.1.0b3", "2021.1.0b3", ""),
])
def test_parse_unity_version(text, core, suffix):
    p = uv.parse_unity_version(text)
    assert p["core"] == core and p["suffix"] == suffix


@pytest.mark.parametrize("text", ["", "2022.3", "5.x.x", "abc", "2022.3.62", "12019.4.1f1x"])
def test_parse_rejects_non_versions(text):
    assert uv.parse_unity_version(text) is None


@pytest.mark.parametrize("fmt", [22, 21, 17, 9])
def test_serialized_header_formats(fmt):
    h = uv.parse_serialized_header(build_serialized_file("2021.3.16f1", format_version=fmt, platform=9))
    assert h == {"format_version": fmt, "unity_version": "2021.3.16f1", "target_platform": 9, "little_endian": True}


@pytest.mark.parametrize("blob", [b"", b"\x00" * 10, b"PK\x03\x04" + b"\x00" * 60, b"\xff" * 80,
                                  build_serialized_file("2021.3.16f1")[:30]])
def test_serialized_header_rejects_garbage_and_truncation(blob):
    assert uv.parse_serialized_header(blob) is None


def test_serialized_source_kind():
    k = uv.serialized_source_kind
    assert k("Data/globalgamemanagers") == "serialized:globalgamemanagers"
    assert k("Data/unity default resources") == "serialized:default_resources"
    assert k("Data/level12") == "serialized" and k("Data/sharedassets3.assets") == "serialized"
    assert k("Data/Resources/unity_builtin_extra") == "serialized"
    assert k("Data/sharedassets3.assets.resS") is None and k("Data/Raw/foo.b") is None


def src(kind, value, ref="x"):
    return {"source": kind, "value": value, "ref": ref}


def test_resolve_agreeing_sources():
    r = uv.resolve_version([src("serialized:globalgamemanagers", "2021.3.16f1"), src("binary", "2021.3.16f1"),
                            src("bundle", "2021.3.16f1")])
    assert r["value"] == "2021.3.16f1" and r["conflicts"] == [] and len(r["sources"]) == 3


def test_resolve_no_sources():
    assert uv.resolve_version([]) == {"value": None, "sources": [], "conflicts": []}
    assert uv.resolve_version([src("binary", "nonsense")])["value"] is None


def test_default_resources_conflict_is_stale_and_ranked_last():
    r = uv.resolve_version([src("serialized:default_resources", "2022.3.54f1"),
                            src("serialized:globalgamemanagers", "2022.3.62f3c1"), src("serialized", "2022.3.62f3c1")])
    assert r["value"] == "2022.3.62f3c1"
    assert [c["kind"] for c in r["conflicts"]] == ["stale"] and r["conflicts"][0]["other"] == "2022.3.54f1"
    assert r["sources"][-1]["source"] == "serialized:default_resources"


def test_bundle_conflict_and_real_conflict():
    r = uv.resolve_version([src("serialized:globalgamemanagers", "2021.3.16f1"), src("bundle", "2021.3.10f1"),
                            src("binary", "2021.3.20f1")])
    assert r["value"] == "2021.3.16f1"
    assert {c["kind"] for c in r["conflicts"]} == {"bundle", "real"}


def test_suffix_difference_is_not_a_conflict():
    r = uv.resolve_version([src("serialized:globalgamemanagers", "2022.3.62f3c1"), src("binary", "2022.3.62f3")])
    assert r["conflicts"] == [] and r["value"] == "2022.3.62f3c1"


def test_same_priority_majority_wins():
    r = uv.resolve_version([src("serialized", "2020.3.1f1", "a"), src("serialized", "2020.3.2f1", "b"),
                            src("serialized", "2020.3.2f1", "c")])
    assert r["value"] == "2020.3.2f1" and r["conflicts"][0]["kind"] == "real"


def test_china_variant_hint():
    assert uv.china_variant("2022.3.62f3c1") and not uv.china_variant("2022.3.62f3") and not uv.china_variant(None)
