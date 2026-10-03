"""Optional: run the macho stage over real IPAs (``IPA_SAMPLES_DIR``); nothing is copied into the repo."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from ipa_analyzer.analyzers.macho_stage import MachoStage
from ipa_analyzer.config import Config
from ipa_analyzer.context import AnalysisContext
from ipa_analyzer.ingest import open_source
from ipa_analyzer.models import Status, to_jsonable

SAMPLES = sorted(Path(os.environ["IPA_SAMPLES_DIR"]).glob("*.ipa")) if os.environ.get("IPA_SAMPLES_DIR") else []
pytestmark = pytest.mark.skipif(not SAMPLES, reason="IPA_SAMPLES_DIR not set")


@pytest.mark.parametrize("ipa", SAMPLES, ids=lambda p: p.name)
def test_stage_on_real_ipa(ipa, tmp_path):
    src = open_source(ipa)
    names = [e.name for e in src.namelist()]
    app = next(n for n in names if n.startswith("Payload/") and n.count("/") >= 2)
    ctx = AnalysisContext(Config(output_dir=tmp_path / "out"), ipa, source=src,
                          app_root="/".join(app.split("/")[:2]) + "/")
    ctx.bind_input("ef" * 32, ipa.stem)
    ctx.results["inventory"] = {}                    # forces header sniffing
    try:
        res = MachoStage().run(ctx)
    finally:
        ctx.close()
    assert res.status in (Status.OK, Status.PARTIAL)
    summary = res.data["summary"]
    assert summary["main_binary"] and summary["archs"]
    main = next(b for b in res.data["binaries"] if b["role"] == "main")
    assert all(s["cryptid"] in (0, 1, None) for s in main["slices"])
    assert to_jsonable(res.data) == res.data
