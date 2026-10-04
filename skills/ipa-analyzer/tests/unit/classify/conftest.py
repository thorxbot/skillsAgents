from __future__ import annotations

import plistlib
from pathlib import Path
from typing import Dict, Optional, Sequence

import pytest

from fixtures.ipa_builder import build_ipa
from ipa_analyzer import pipeline
from ipa_analyzer.config import Config
from ipa_analyzer.context import AnalysisContext

INFO = plistlib.dumps({"CFBundleIdentifier": "com.example.t", "CFBundleName": "T", "CFBundleExecutable": "T",
                       "CFBundleShortVersionString": "1.0", "CFBundleVersion": "1"})


@pytest.fixture()
def run_stages(tmp_path):
    """``run(files, stages, libs_user=None, results=None) -> ctx`` over a synthetic IPA (never a real one)."""
    counter = {"n": 0}

    def run(files: Dict[str, bytes], stages: Sequence[str] = ("ingest", "inventory", "macho", "libs"), *,
            libs_user: Optional[Path] = None, inject: Optional[Dict[str, dict]] = None, info: bytes = INFO):
        counter["n"] += 1
        d = tmp_path / ("case%d" % counter["n"])
        d.mkdir()
        allfiles = {"Info.plist": info}
        allfiles.update(files)
        ipa = build_ipa(d / "T.ipa", allfiles, app_name="T")
        cfg = Config(output_dir=d / "out", stages=tuple(stages), formats=("json",), libs_user_path=libs_user)
        ctx = AnalysisContext(cfg, ipa)
        pipeline.run(ctx, pipeline.ensure_analyzers_loaded())
        if inject is not None:
            ctx.results.update(inject)
        return ctx

    return run
