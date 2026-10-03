"""300 MB-class synthetic binary: streaming must keep Python-level memory small (run with --runslow)."""
from __future__ import annotations

import re
import shutil
import time
import tracemalloc

import pytest

from fixtures.macho_builder import write_macho_file
from ipa_analyzer.macho import parse, scan_file, write_thin

pytestmark = pytest.mark.slow

GAP = 300 * 1024 * 1024
LIMIT = 24 * 1024 * 1024        # generous: chunks, regex state and Python overhead only


@pytest.fixture(scope="module")
def big(tmp_path_factory):
    d = tmp_path_factory.mktemp("big")
    if shutil.disk_usage(d).free < GAP * 2:
        pytest.skip("not enough free disk space for the sparse fixture")
    return write_macho_file(d / "big.bin", big_cstring=GAP, strings=["head-string", "UnityFramework"],
                            imports=["_dlopen"], code_signature=dict(team_id="ABCDE12345"))


def test_iter_cstrings_streams_without_loading_the_file(big):
    tracemalloc.start()
    try:
        with parse(big) as mf:
            sl = mf.slices[0]
            assert sl.size >= GAP
            start = time.monotonic()
            found = list(sl.iter_cstrings())
            elapsed = time.monotonic() - start
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert found == ["head-string", "UnityFramework", "END_OF_BIG_CSTRING"]
    assert peak < LIMIT, "peak %d bytes" % peak
    assert elapsed < 120


def test_scan_file_streams(big):
    tracemalloc.start()
    try:
        res = scan_file(big, [re.compile(rb"END_OF_BIG_\w+"), re.compile(rb"UnityFramework")])
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert [h.data for h in res[rb"END_OF_BIG_\w+"]] == [b"END_OF_BIG_CSTRING"]
    assert res[rb"UnityFramework"][0].offset < 1 << 20
    assert peak < LIMIT


def test_write_thin_of_big_file_is_chunked(big, tmp_path):
    tracemalloc.start()
    try:
        with parse(big) as mf:
            out = write_thin(mf.slices[0], tmp_path / "copy.bin")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert out.stat().st_size == big.stat().st_size and peak < LIMIT


def test_metadata_parsing_is_instant_on_big_files(big):
    start = time.monotonic()
    with parse(big) as mf:
        sl = mf.slices[0]
        assert sl.code_signature.team_id == "ABCDE12345" and [s.name for s in sl.iter_imported_symbols()] == ["_dlopen"]
    assert time.monotonic() - start < 2
