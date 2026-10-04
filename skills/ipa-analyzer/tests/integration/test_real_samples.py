"""OPTIONAL end-to-end run on real IPAs. Skipped unless ``IPA_SAMPLES_DIR`` points at a directory with ``*.ipa`` files.

By project decision (docs/05) no real sample is used by the automated work; run this yourself when you have samples::

    IPA_SAMPLES_DIR=/path/to/ipas python -m pytest tests/integration/test_real_samples.py -v

Nothing from the samples is copied into the repository. Only structural expectations that hold for *any* IPA are
asserted (the run completes, the report validates, FairPlay is reported consistently with the Mach-O flags).
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from fixtures.e2e_support import run_cli

DIR = Path(os.environ["IPA_SAMPLES_DIR"]) if os.environ.get("IPA_SAMPLES_DIR") else None
pytestmark = pytest.mark.skipif(DIR is None or not DIR.is_dir(), reason="IPA_SAMPLES_DIR not set")


def samples():
    return sorted(DIR.glob("*.ipa")) if DIR is not None and DIR.is_dir() else []


@pytest.mark.parametrize("ipa", samples() or [None], ids=lambda p: p.name if p else "none")
def test_real_sample_end_to_end(tmp_path, check_report, ipa):
    if ipa is None:
        pytest.skip("no *.ipa in IPA_SAMPLES_DIR")
    home = tmp_path / "home"
    home.mkdir()
    r = run_cli(ipa, tmp_path / "out", home, [], name=ipa.stem)
    assert r.returncode in (0, 3), r.proc.stderr[-1000:]
    assert r.report is not None and check_report(r.report) == []
    assert [s["name"] for s in r.report["stages"]][-1] == "report"
    macho = r.report["structure"]["binaries"]
    main = next((b for b in macho if b["role"] == "main"), None)
    if main is not None:
        enc = any(s["encrypted"] for s in main["slices"])
        if enc:
            assert r.verdict("protect.fairplay") == "yes"
            assert r.report["engine_details"].get("unity", {}).get("dump", {}).get("ok") in (None, False)
