"""The Unreal checker against real ``UnrealPak`` output (repak's test packs; see ``tests/fixtures/public/README.md``).

Ground truth comes from the generator's flags, not from this code base, so these tests catch footer-layout mistakes
that a self-written builder would reproduce.
"""
from __future__ import annotations

import base64
import json
import struct
from pathlib import Path

import pytest

from ipa_analyzer.engines.formats.pak_ue import TAIL_BYTES, parse_footer
from ipa_analyzer.models import Verdict as V

PUBLIC = Path(__file__).resolve().parents[2] / "fixtures" / "public" / "unreal_pak"
MANIFEST = json.loads((PUBLIC / "MANIFEST.json").read_text(encoding="utf-8"))
PACKS = sorted(MANIFEST["packs"])


@pytest.mark.parametrize("name", PACKS)
def test_footer_matches_unrealpak_ground_truth(name):
    truth = MANIFEST["packs"][name]
    blob = (PUBLIC / name).read_bytes()
    info = parse_footer(blob[-TAIL_BYTES:], len(blob))
    assert info.valid and info.index_in_bounds, info.note
    assert info.version == truth["version"]
    assert info.index_encrypted is truth["index_encrypted"]


@pytest.mark.parametrize("name", PACKS)
def test_checker_verdict_on_real_pak(runner, name):
    truth = MANIFEST["packs"][name]
    r = runner.run({"cookeddata/Proj/Content/Paks/" + name: (PUBLIC / name).read_bytes()}, detect=["unreal"])
    f = r.finding("engine.pak.encrypted", "unreal")
    assert f.verdict == (V.YES if truth["index_encrypted"] else V.NO)


@pytest.mark.parametrize("name", [n for n, t in MANIFEST["packs"].items() if t["entries_encrypted"]])
def test_known_limit_entry_only_encryption_is_not_reported(runner, name):
    """``-encrypt`` without ``-encryptindex``: the data is encrypted but the flag the checker reads is not set.

    Documented in ``references/engine-resource-protection.md``; if the checker ever learns to parse entries this test
    must flip to ``V.YES`` (and the doc note be removed).
    """
    r = runner.run({"cookeddata/Proj/Content/Paks/" + name: (PUBLIC / name).read_bytes()}, detect=["unreal"])
    assert r.finding("engine.pak.encrypted", "unreal").verdict == V.NO


@pytest.mark.parametrize("name", [n for n, t in MANIFEST["packs"].items() if t["index_encrypted"]])
def test_public_test_key_decrypts_index_to_a_mount_point(name):
    """UE index encryption = AES-256-ECB over the whole index; a correct key shows a sane mount-point string first."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    blob = (PUBLIC / name).read_bytes()
    info = parse_footer(blob[-TAIL_BYTES:], len(blob))
    index = blob[info.index_offset:info.index_offset + info.index_size]
    assert len(index) % 16 == 0                                    # block cipher, no padding
    dec = Cipher(algorithms.AES(base64.b64decode(MANIFEST["key_base64"])), modes.ECB()).decryptor()
    plain = dec.update(index) + dec.finalize()
    n = struct.unpack_from("<i", plain, 0)[0]                      # FString: length incl. NUL
    assert plain[4:4 + n - 1].decode("ascii") == MANIFEST["mount_point"]
