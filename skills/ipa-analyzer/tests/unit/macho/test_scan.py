from __future__ import annotations

import mmap
import re

import pytest

from ipa_analyzer.macho import scan
from ipa_analyzer.macho.scan import (UNITY_VERSION_RE, find_unity_version_hits, find_unity_version_strings,
                                     scan_file)


def _write(tmp_path, blob, name="blob.bin"):
    p = tmp_path / name
    p.write_bytes(blob)
    return p


def test_scan_finds_hits_with_offsets(tmp_path):
    blob = b"\0" * 100 + b"il2cpp_init" + b"\0" * 50 + b"il2cpp_shutdown" + b"\0" * 10
    p = _write(tmp_path, blob)
    res = scan_file(p, [re.compile(rb"il2cpp_\w+"), re.compile(rb"nothing")])
    hits = res[rb"il2cpp_\w+"]
    assert [(h.offset, h.data) for h in hits] == [(100, b"il2cpp_init"), (161, b"il2cpp_shutdown")]
    assert res[rb"nothing"] == [] and res.scanned == len(blob) and not res.truncated
    assert res.counts[rb"il2cpp_\w+"] == 2


@pytest.mark.parametrize("chunk,overlap", [(16, 64), (50, 64), (100, 32), (1, 40), (8 * 1024 * 1024, 256)])
def test_matches_straddling_window_boundaries_are_found_once(tmp_path, chunk, overlap):
    marker = b"MARKER_0123456789"
    blob = bytearray(b"." * 1000)
    positions = [0, 18, 36, 60, 80, 100, 497, 600, 983]       # non-overlapping, several straddle windows
    for pos in positions:
        blob[pos:pos + len(marker)] = marker
    p = _write(tmp_path, bytes(blob))
    pat = re.compile(re.escape(marker))
    res = scan_file(p, [pat], chunk=chunk, overlap=overlap)
    assert [h.offset for h in res[pat.pattern]] == positions


def test_limit_truncates_but_counts(tmp_path):
    p = _write(tmp_path, b"abc " * 1000)
    res = scan_file(p, [re.compile(rb"abc")], limit=10)
    assert len(res[rb"abc"]) == 10 and res.truncated and res.counts[rb"abc"] == 1000


def test_empty_file_and_non_bytes_pattern(tmp_path):
    p = _write(tmp_path, b"")
    assert scan_file(p, [re.compile(rb"x")]) == {rb"x": []}
    with pytest.raises(TypeError):
        scan_file(p, [re.compile("text")])


def test_fallback_without_mmap(tmp_path, monkeypatch):
    blob = b"\0" * 5000 + b"Unity 2021.3.16f1 player" + b"\0" * 5000
    p = _write(tmp_path, blob)

    def boom(*a, **k):
        raise OSError("no mmap")

    monkeypatch.setattr(mmap, "mmap", boom)
    res = scan_file(p, [UNITY_VERSION_RE], chunk=777, overlap=64)
    assert [(h.offset, h.data) for h in res[UNITY_VERSION_RE.pattern]] == [(5006, b"2021.3.16f1")]


@pytest.mark.parametrize("text,expected", [
    (b"2021.3.16f1", ["2021.3.16f1"]), (b"2019.4.40f1c1", ["2019.4.40f1c1"]), (b"5.6.7f1", ["5.6.7f1"]),
    (b"2017.4.40f1", ["2017.4.40f1"]), (b"2022.3.10f1", ["2022.3.10f1"]), (b"6000.0.23f1", ["6000.0.23f1"]),
    (b"2020.2.0b3", ["2020.2.0b3"]), (b"2018.4.36p1", ["2018.4.36p1"]), (b"2023.2.20a1", ["2023.2.20a1"]),
    (b"Version: 2021.3.16f1 (abc123def456)", ["2021.3.16f1"]),
    # negatives
    (b"12021.3.16f1", []), (b"2021.3.16", []), (b"2021.3.16f", []), (b"1.2.3f4", []), (b"2021.3.16f1x", []),
    (b"9.9.9.9", []), (b"v2021.3.16f1x", []), (b"2021.3.16f123", []), (b"3000.0.1f1", []),
    (b"a2021.3.16f1", []), (b"2021.3.16f1.5", []),
])
def test_unity_version_regex(tmp_path, text, expected):
    p = _write(tmp_path, b"\0\0" + text + b"\0\0")
    assert find_unity_version_strings(p) == expected


def test_unity_versions_sorted_by_frequency(tmp_path):
    blob = b"\0".join([b"2019.4.1f1", b"2021.3.16f1", b"2021.3.16f1", b"5.6.7f1", b"2021.3.16f1", b"5.6.7f1"])
    p = _write(tmp_path, blob)
    assert find_unity_version_strings(p) == ["2021.3.16f1", "5.6.7f1", "2019.4.1f1"]
    hits = find_unity_version_hits(p)
    assert len(hits) == 6 and hits[0].offset == 0 and hits[0].data == b"2019.4.1f1"


def test_scan_releases_file_for_deletion(tmp_path):
    p = _write(tmp_path, b"x" * 100)
    scan_file(p, [re.compile(rb"x+")])
    p.unlink()                                   # Windows would fail here if the mapping leaked
    assert not p.exists()


def test_module_exports():
    assert {"scan_file", "find_unity_version_strings", "ScanHit", "ScanResult"} <= set(scan.__all__)
