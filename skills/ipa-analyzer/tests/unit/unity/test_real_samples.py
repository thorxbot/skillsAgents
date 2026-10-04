"""Optional: the engine.unity stage on real Unity IPAs (``IPA_SAMPLES_DIR``); nothing is copied into the repo.

The expectations for the two known samples (JiangNan, GoodCoffee) were measured on 2026-10-04; both main binaries
are FairPlay-encrypted, so the dump is expected to be blocked by the pre-check.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from ipa_analyzer import pipeline
from ipa_analyzer.analyzers.unity import EngineUnityStage
from ipa_analyzer.config import Config
from ipa_analyzer.context import AnalysisContext
from ipa_analyzer.models import Status, to_jsonable

DIR = Path(os.environ["IPA_SAMPLES_DIR"]) if os.environ.get("IPA_SAMPLES_DIR") else None
pytestmark = pytest.mark.skipif(DIR is None, reason="IPA_SAMPLES_DIR not set")

DETECT = {"primary": {"id": "unity", "confidence": 0.9, "confirmed": True},
          "candidates": [{"id": "unity", "confidence": 0.9, "confirmed": True}]}


def run_sample(name: str, tmp_path: Path):
    ipa = DIR / name
    if not ipa.is_file():
        pytest.skip("%s not available" % name)
    cfg = Config(output_dir=tmp_path / "out", stages=("macho",), formats=("json",))
    cfg.offline = True
    ctx = AnalysisContext(cfg, ipa)
    pipeline.ensure_analyzers_loaded()
    pipeline.run(ctx)
    ctx.results["engine.detect"] = DETECT
    return EngineUnityStage().run(ctx)


def test_jiangnan_metadata_v31_and_block_encrypted_bundles(tmp_path):
    res = run_sample("com.cis.jiangnan.cn_6.0.2.ipa", tmp_path)
    assert res.status == Status.OK and to_jsonable(res.data) == res.data
    d = res.data
    assert d["backend"] == "il2cpp" and d["version"]["value"] == "2022.3.62f3c1"
    assert d["metadata"]["version"] == 31 and d["metadata"]["header_ok"] is True
    assert d["metadata"]["verdict"] == "no" and d["metadata"]["string_region_ok"] is True
    assert d["precheck"]["error_code"] == "E_BINARY_FAIRPLAY" and d["dump"]["ran"] is False
    b = d["bundles"]
    assert b["by_class"]["block_encrypted_suspected"] == b["population"] > 0
    assert b["verdict"] == "suspected"
    assert any(c["kind"] == "stale" for c in d["version"]["conflicts"])


def test_goodcoffee_metadata_v39_and_unreadable_bundles(tmp_path):
    res = run_sample("com.tapblaze.coffeebusiness_1.24.1.ipa", tmp_path)
    assert res.status == Status.OK
    d = res.data
    assert d["version"]["value"] == "6000.3.10f1"
    assert d["metadata"]["version"] == 39 and d["metadata"]["header_ok"] is True and d["metadata"]["verdict"] == "no"
    assert "il2cppdumper" not in d["metadata"]["supported_by"] and "redux" in d["metadata"]["supported_by"]
    b = d["bundles"]
    assert b["by_class"]["high_entropy_unknown"] >= 2000 and b["by_class"]["standard"] == 0
    assert b["verdict"] == "yes" and b["addressables"]["catalog_found"] is True
