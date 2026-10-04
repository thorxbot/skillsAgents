"""Small-scale performance regression (``slow``: use ``--runslow``). The 1 GB / 60 s / 500 MB target of 01-REQUIREMENTS
section 4 is *not* verified here (no 1 GB fixtures, by decision): this only guards against accidental whole-file reads.
"""
from __future__ import annotations

import plistlib
import sys
import time

import pytest

from fixtures.ipa_builder import build_ipa
from fixtures.macho_builder import build_macho
from ipa_analyzer import pipeline
from ipa_analyzer.config import Config
from ipa_analyzer.context import AnalysisContext

pytestmark = pytest.mark.slow
MIB = 1 << 20


def rss_mib() -> float:
    try:
        import resource
    except ImportError:                                  # Windows
        return -1.0
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / MIB if sys.platform == "darwin" else peak / 1024.0


def test_64_mib_of_stored_zero_files_is_analysed_quickly_without_reading_everything(tmp_path):
    files = {"Info.plist": plistlib.dumps({"CFBundleExecutable": "Perf", "CFBundleIdentifier": "com.example.perf"}),
             "Perf": build_macho(arch="arm64", strings=["x"])}
    for i in range(16):
        files["Data/Raw/blob%02d.bin" % i] = b"\0" * (4 * MIB)            # 64 MiB, compressible and uninteresting
    for i in range(300):
        files["res/f%03d.png" % i] = b"\x89PNG\r\n\x1a\n" + b"\0" * 200
    ipa = build_ipa(tmp_path / "perf.ipa", files, app_name="Perf", compress=False)
    assert ipa.stat().st_size > 64 * MIB
    before = rss_mib()
    ctx = AnalysisContext(Config(output_dir=tmp_path / "out", offline=True), ipa)
    pipeline.ensure_analyzers_loaded()
    t0 = time.monotonic()
    run = pipeline.run(ctx)
    ctx.close()
    secs = time.monotonic() - t0
    assert not [r.name for r in run.stage_results if r.status.value == "failed"]
    assert secs < 30, "64 MiB took %.1f s" % secs
    if before >= 0:
        assert rss_mib() - before < 300, "peak RSS grew by %.0f MiB" % (rss_mib() - before)
    assert ctx.results["inventory"]["files_total"] >= 300
