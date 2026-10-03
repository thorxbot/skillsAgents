from __future__ import annotations

import hashlib
import io
import os
import plistlib

from ipa_analyzer.util.entropy import sampled_entropy, shannon
from ipa_analyzer.util.hashing import sha256_bytes, sha256_stream
from ipa_analyzer.util.plist_utils import load_plist, to_jsonable_plist


def test_sha256_stream_path_and_fileobj(tmp_path):
    data = os.urandom(3_000_000)
    p = tmp_path / "f.bin"
    p.write_bytes(data)
    expected = hashlib.sha256(data).hexdigest()
    assert sha256_stream(p) == expected
    assert sha256_stream(str(p), chunk=7777) == expected
    assert sha256_stream(io.BytesIO(data)) == expected
    assert sha256_bytes(b"") == hashlib.sha256(b"").hexdigest()


def test_shannon_extremes():
    assert shannon(b"") == 0.0
    assert shannon(b"\x00" * 1000) == 0.0
    assert abs(shannon(bytes(range(256)) * 4) - 8.0) < 1e-9
    assert abs(shannon(b"ab" * 100) - 1.0) < 1e-9


def test_sampled_entropy_small_file_equals_full():
    data = os.urandom(10_000)
    assert sampled_entropy(io.BytesIO(data), len(data)) == shannon(data)
    assert sampled_entropy(io.BytesIO(b""), 0) == 0.0


def test_sampled_entropy_large_file_reads_only_a_fraction():
    class Counting(io.BytesIO):
        n = 0

        def read(self, size=-1):
            b = super().read(size)
            Counting.n += len(b)
            return b

    plain = b"hello world " * 1_000_000   # 12 MB, low entropy
    f = Counting(plain)
    e = sampled_entropy(f, len(plain))
    assert e < 4.0 and Counting.n < 300_000
    rnd = os.urandom(2_000_000)
    assert sampled_entropy(io.BytesIO(rnd), len(rnd)) > 7.9


def test_load_plist_xml_binary_and_garbage():
    obj = {"CFBundleName": "X", "n": 3, "l": [1, 2]}
    assert load_plist(plistlib.dumps(obj, fmt=plistlib.FMT_XML)) == obj
    assert load_plist(plistlib.dumps(obj, fmt=plistlib.FMT_BINARY)) == obj
    assert load_plist(b"\xef\xbb\xbf" + plistlib.dumps(obj, fmt=plistlib.FMT_XML)) == obj
    assert load_plist(b"") is None
    assert load_plist(b"not a plist at all") is None
    assert load_plist(plistlib.dumps(obj, fmt=plistlib.FMT_BINARY)[:20]) is None
    assert load_plist("text") is None  # type: ignore[arg-type]


def test_to_jsonable_plist():
    import datetime
    out = to_jsonable_plist({"d": b"\x00" * 100, "t": datetime.datetime(2020, 1, 1), "l": [b"a"]})
    assert out["d"].startswith("<data 100 bytes:") and out["d"].endswith("...>")
    assert out["t"].startswith("2020-01-01") and out["l"] == ["<data 1 bytes: 61>"]
