"""Malformed-input robustness: random truncation / bit flips of the whole-package fixtures must neither crash nor hang.

Every mutated archive goes through the full pipeline in a watchdog thread (a hang fails the test instead of the
suite).  A damaged *entry* must not fail stages (it is skipped / reported); only ``ingest`` may reject the input.
Run the bigger campaign with ``--runslow``.
"""
from __future__ import annotations

import random
import struct
import threading
import time
from pathlib import Path
from typing import List, Tuple

import pytest

from fixtures.full_ipa_builders import build_fixture
from ipa_analyzer import pipeline
from ipa_analyzer.config import Config
from ipa_analyzer.context import AnalysisContext

FUZZ_FIXTURES = ["unity_il2cpp_plain", "unity_xlua_lua53", "custom_engine", "cocos_creator3_wrapped", "media_app",
                 "native_swift_app", "flutter_app"]
WATCHDOG_S = 60.0


def mutations(data: bytes, rng: random.Random, n: int) -> List[Tuple[str, bytes]]:
    out: List[Tuple[str, bytes]] = []
    for i in range(n):
        b = bytearray(data)
        kind = i % 3
        if kind == 0:
            out.append(("truncate", bytes(b[: rng.randrange(1, len(b))])))
        elif kind == 1:
            for _ in range(rng.randrange(1, 40)):
                b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
            out.append(("bitflip", bytes(b)))
        else:                                                    # damage the end: central directory / EOCD
            lo = max(0, len(b) - rng.randrange(100, 4000))
            for _ in range(rng.randrange(1, 12)):
                b[rng.randrange(lo, len(b))] ^= 1 << rng.randrange(8)
            out.append(("tail-flip", bytes(b)))
    return out


def run_guarded(path: Path, out: Path):
    cfg = Config(output_dir=out, offline=True)
    ctx = AnalysisContext(cfg, path)
    box = {}

    def work() -> None:
        try:
            box["run"] = pipeline.run(ctx)
        except BaseException as exc:                              # noqa: BLE001 - reported below
            box["exc"] = exc

    th = threading.Thread(target=work, daemon=True)
    started = time.monotonic()
    th.start()
    th.join(WATCHDOG_S)
    try:
        assert not th.is_alive(), "pipeline hung (> %.0f s) on %s" % (WATCHDOG_S, path.name)
        assert "exc" not in box, "pipeline raised %r on %s" % (box["exc"], path.name)
    finally:
        ctx.close()
    return box["run"], ctx, time.monotonic() - started


def campaign(tmp_path: Path, per_fixture: int) -> None:
    pipeline.ensure_analyzers_loaded()
    for name in FUZZ_FIXTURES:
        data = build_fixture(name, tmp_path / "src").read_bytes()
        rng = random.Random(sum(map(ord, name)))
        for i, (kind, blob) in enumerate(mutations(data, rng, per_fixture)):
            p = tmp_path / "m" / ("%s-%s-%d.ipa" % (name, kind, i))
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(blob)
            run, ctx, secs = run_guarded(p, tmp_path / "o" / p.stem)
            assert secs < 30, (p.name, secs)
            bad = [(r.name, r.error) for r in run.stage_results if r.status.value == "failed" and r.name != "ingest"]
            assert not bad, (p.name, bad)
            # whatever happened, the report stage ran and every skipped / failed stage explains itself
            assert run.stage_results[-1].name == "report" and run.stage_results[-1].status.value == "ok", p.name
            for r in run.stage_results:
                if r.status.value == "skipped":
                    assert r.reason, (p.name, r.name)
                if r.status.value == "failed":
                    assert r.error and r.name == "ingest"


def test_random_truncation_and_bit_flips_do_not_crash_or_hang(tmp_path):
    campaign(tmp_path, 9)


@pytest.mark.slow
def test_larger_fuzz_campaign(tmp_path):
    campaign(tmp_path, 60)


def corrupt_entry(ipa: Path, entry: bytes, dest: Path) -> Path:
    """Copy of ``ipa`` in which the deflate data of ``entry`` is damaged (headers and central directory stay valid)."""
    data = bytearray(ipa.read_bytes())
    at = data.index(entry)                                         # local file header of the entry
    nlen, xlen = struct.unpack_from("<HH", data, at - 4)
    start = at + nlen + xlen
    for k in range(12):
        data[start + 2 + k] ^= 0xFF
    dest.write_bytes(bytes(data))
    return dest


@pytest.mark.parametrize("fixture,entry", [
    ("unity_il2cpp_plain", b"Payload/Game.app/Info.plist"),                          # read by macho / libs / engine stages
    ("unity_xlua_lua53", b"Payload/Game.app/Data/globalgamemanagers"),             # serialized file scanned by the hot-update stage
    ("unity_xlua_lua53", b"Payload/Game.app/Data/Raw/lua_scripts.bundle"),
    ("unity_il2cpp_plain", b"Payload/Game.app/Data/Managed/Metadata/global-metadata.dat"),
    ("custom_engine", b"Payload/Mystic.app/res/data.pak"),
])
def test_damaged_entry_is_skipped_not_fatal(tmp_path, fixture, entry):
    """Corrupt the deflate data of one entry: no stage may fail (one bad entry is not a bad input)."""
    bad = corrupt_entry(build_fixture(fixture, tmp_path / "src"), entry, tmp_path / "bad.ipa")
    run, ctx, _ = run_guarded(bad, tmp_path / "out")
    assert not [r.name for r in run.stage_results if r.status.value == "failed"], \
        [(r.name, r.error) for r in run.stage_results if r.status.value == "failed"]
    assert run.invalid_input is False
    assert ctx.results["engine.detect"]                                         # the rest of the analysis is intact
    assert run.stage_results[-1].name == "report" and run.stage_results[-1].status.value == "ok"


def test_deeply_nested_and_many_entries_archive_is_bounded(tmp_path):
    """10 000 tiny entries and a 400-level deep path: must finish quickly and stay within the limits."""
    from fixtures.ipa_builder import build_ipa
    from fixtures.macho_builder import build_macho
    import plistlib

    files = {"Info.plist": plistlib.dumps({"CFBundleExecutable": "Big", "CFBundleIdentifier": "com.example.big"}),
             "Big": build_macho(arch="arm64", strings=["x"]), "/".join(["d"] * 400) + "/leaf.txt": b"deep"}
    for i in range(10_000):
        files["res/f%05d.txt" % i] = b"x"
    ipa = build_ipa(tmp_path / "big.ipa", files, app_name="Big")
    run, ctx, secs = run_guarded(ipa, tmp_path / "out")
    assert secs < 60 and run.stage_results[-1].status.value == "ok"
    assert ctx.results["inventory"]["files_total"] >= 10_000
    assert not [r.name for r in run.stage_results if r.status.value == "failed"]


def test_corrupt_entry_error_is_invalid_input_and_os_error(tmp_path):
    """Entry-level read errors are ``CorruptEntry`` (an ``InvalidInput`` *and* an ``OSError``); archive-level ones stay plain."""
    from fixtures.ipa_builder import build_zip_bytes
    from ipa_analyzer.errors import CorruptEntry, InvalidInput
    from ipa_analyzer.ingest import open_source

    zb = build_zip_bytes({"Payload/A.app/Info.plist": b"x" * 5000})
    p = tmp_path / "e.ipa"
    p.write_bytes(zb)
    src = open_source(p)
    start = zb.index(b"Payload/A.app/Info.plist") + len(b"Payload/A.app/Info.plist")
    bad = bytearray(zb)
    for k in range(6):
        bad[start + 2 + k] ^= 0xFF
    q = tmp_path / "bad.ipa"
    q.write_bytes(bytes(bad))
    with pytest.raises(CorruptEntry) as ei:
        with open_source(q).open("Payload/A.app/Info.plist") as fh:
            fh.read()
    assert isinstance(ei.value, InvalidInput) and isinstance(ei.value, OSError)
    src.close()
    garbage = tmp_path / "g.ipa"
    garbage.write_bytes(b"not a zip at all" * 20)
    with pytest.raises(InvalidInput) as gi:
        open_source(garbage)
    assert not isinstance(gi.value, CorruptEntry)
