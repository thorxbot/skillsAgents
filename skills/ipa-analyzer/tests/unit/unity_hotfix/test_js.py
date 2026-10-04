from __future__ import annotations

import base64
import random
import zlib

from ipa_analyzer.unity.hotfix import js
from ipa_analyzer.unity.hotfix.storage import Blob


def urandom(n: int) -> bytes:
    return random.Random(n).randbytes(n)


def blob(data: bytes, name="main.mjs") -> Blob:
    return Blob("js", "loose", "Payload/X.app/Data/Raw/" + name, name, len(data), data[:4096], data[:65536])


def test_classification():
    assert js.classify_blob(blob(b"import {a} from './b.mjs';\nconsole.log(a);\n" * 5)) == "plain"
    assert js.classify_blob(blob(zlib.compress(b"x" * 600))) == "compressed"
    assert js.classify_blob(blob(urandom(4096))) == "encrypted_suspected"
    assert js.classify_blob(blob(base64.b64encode(urandom(2000)))) == "encrypted_suspected"
    assert js.classify_blob(blob(b"\x02\x05\x00\x01" * 100)) == "binary_non_text"
    assert js.classify_blob(blob(b"")) == "binary_non_text"


def test_analyze_backends_and_files():
    out = js.analyze([blob(b"var a=1;\n" * 20), blob(urandom(4096), "x.mjs")],
                     [{"id": "v8", "confidence": 0.5}], [{"id": "quickjs", "confidence": 0.85}], named_in_containers=3,
                     extensions=[".mjs", ".mjs", ".cjs"])
    assert out["files"] == {"plain": 1, "encrypted_suspected": 1, "binary_non_text": 0, "compressed": 0, "total": 2}
    assert [b["id"] for b in out["backends"]] == ["quickjs", "v8"] and out["extensions"] == [".cjs", ".mjs"]
    assert out["named_in_containers"] == 3 and "plain" in out["formats"]


def test_nodejs_implies_v8_and_bytecode_is_not_claimed():
    out = js.analyze([], [], [{"id": "nodejs", "confidence": 0.5}])
    assert {b["id"] for b in out["backends"]} == {"nodejs", "v8"}
    assert "bytecode" not in out["files"] and "not identified" in out["notes"][0]


def test_protection():
    def pv(blobs, **kw):
        return js.protection_verdict(js.analyze(blobs, [], []), containers_unreadable=kw.get("unread", 0),
                                     js_signal=kw.get("signal", False), coverage_limited=kw.get("limited", False))
    assert pv([blob(b"var a=1;\n" * 20)])["verdict"] == "no"
    assert pv([blob(urandom(4096))])["verdict"] == "suspected"
    assert pv([])["verdict"] == "n/a"
    assert pv([], signal=True)["verdict"] == "unknown" and pv([], limited=True)["verdict"] == "unknown"
