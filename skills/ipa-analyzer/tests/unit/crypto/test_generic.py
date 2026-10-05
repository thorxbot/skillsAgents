"""Operator-key decryption escape hatch (crypto/generic.py)."""
from __future__ import annotations

import gzip
import zlib

import pytest

from ipa_analyzer.crypto import ccz, generic, xxtea


def test_xor_roundtrip_repeating_key():
    pt = b"server config payload that is longer than the key"
    ct = generic.xor_bytes(pt, b"KEY")
    assert generic.decrypt(ct, "xor", key_text="KEY").data == pt


def test_xor_hex_key():
    ct = generic.xor_bytes(b"abcdef", bytes([0xAA, 0xBB]))
    r = generic.decrypt(ct, "xor", key_text="hex:aabb")
    assert r.ok and r.data == b"abcdef"


def test_xor_empty_key_fails():
    assert not generic.decrypt(b"x", "xor", key_text="").ok


def test_xxtea_wholefile_with_gzip_post():
    ct = xxtea.encrypt(gzip.compress(b'{"json":true}'), "k")
    r = generic.decrypt(ct, "xxtea", key_text="k")
    assert r.ok and r.post == "gzip" and r.data == b'{"json":true}'


def test_xxtea_zlib_post():
    ct = xxtea.encrypt(zlib.compress(b"x" * 500), "k")
    r = generic.decrypt(ct, "xxtea", key_text="k")
    assert r.ok and r.post == "zlib" and r.data == b"x" * 500


def test_xxtea_with_sign():
    ct = b"XXTEA" + xxtea.encrypt(b"local a=1 return a", "mykey")
    r = generic.decrypt(ct, "xxtea", key_text="mykey", sign=b"XXTEA")
    assert r.ok and r.data == b"local a=1 return a"


def test_xxtea_sign_mismatch_fails():
    ct = xxtea.encrypt(b"body", "mykey")
    assert not generic.decrypt(ct, "xxtea", key_text="mykey", sign=b"XXTEA").ok


def test_xxtea_wrong_key_fails():
    ct = xxtea.encrypt(b"the original plaintext", "right")
    assert not generic.decrypt(ct, "xxtea", key_text="wrongkey").ok


def test_ccz_scheme():
    enc = ccz.encrypt_ccz(b"RAW" * 400, (1, 2, 3, 4))
    r = generic.decrypt(enc, "ccz", key_text="1 2 3 4")
    assert r.ok and r.data == b"RAW" * 400


def test_unknown_scheme():
    assert not generic.decrypt(b"x", "aes", key_text="k").ok


def test_no_decompress_flag_keeps_raw():
    blob = gzip.compress(b"hello")
    ct = xxtea.encrypt(blob, "k")
    r = generic.decrypt(ct, "xxtea", key_text="k", decompress=False)
    assert r.ok and r.post == "" and r.data == blob


@pytest.mark.parametrize("text,expect", [("hex:0a0b", b"\x0a\x0b"), ("str:abc", b"abc"), ("plain", b"plain")])
def test_parse_key_bytes(text, expect):
    assert generic.parse_key_bytes(text) == expect
