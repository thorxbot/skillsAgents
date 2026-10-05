"""XXTEA core: xxtea-c wire format, round-trip and wrong-key rejection.

The expected byte vectors below were produced with the authoritative ``xxtea`` package (Ma Bingyao, byte-compatible
with the ``xxtea-c`` library cocos bundles) under ``Padding.LENGTH_WORD_SUFFIX`` -- the scheme cocos uses -- and are
pinned here so the implementation stays locked to that format without a runtime dependency on that package.
"""
from __future__ import annotations

import os
import random

import pytest

from ipa_analyzer.crypto import xxtea

KEY16 = b"0123456789abcdef"

# (plaintext, key, ciphertext_hex) -- authoritative xxtea-c, LENGTH_WORD_SUFFIX padding.
VECTORS = [
    (b"A", KEY16, "91f040172b25f672"),
    (b"AAAA", KEY16, "f7d29c8d26950df5"),
    (b"AAAAA", KEY16, "1a1e44f5540a5d9a0e68c168"),
    (b"AAAAAAAA", KEY16, "4e5f62268ec50ac8c240831a"),
    (b"AAAAAAAAA", KEY16, "3e10089b876feffb550b0768d6d62834"),
]


@pytest.mark.parametrize("plain,key,ct_hex", VECTORS)
def test_known_vectors(plain, key, ct_hex):
    assert xxtea.encrypt(plain, key).hex() == ct_hex
    assert xxtea.decrypt(bytes.fromhex(ct_hex), key) == plain


def test_ciphertext_length_framing():
    # (ceil(n/4) + 1) * 4 bytes: a length word is appended, so always a multiple of 4 and >= 8.
    for n, expect in [(1, 8), (4, 8), (5, 12), (8, 12), (9, 16), (12, 16)]:
        assert len(xxtea.encrypt(b"x" * n, KEY16)) == expect


@pytest.mark.parametrize("n", [1, 2, 3, 7, 16, 17, 100, 255, 1024])
def test_roundtrip_random(n):
    data = os.urandom(n)
    key = os.urandom(random.randint(1, 16))
    assert xxtea.decrypt(xxtea.encrypt(data, key), key) == data


def test_short_key_zero_padded_to_16():
    data = b"hello cocos lua chunk"
    # a short key behaves as if right-padded with NUL bytes to 16 bytes
    assert xxtea.encrypt(data, b"abc") == xxtea.encrypt(data, b"abc\x00\x00\x00")


def test_str_and_bytes_key_equivalent():
    data = b"payload payload"
    assert xxtea.encrypt(data, "secret") == xxtea.encrypt(data, b"secret")


def test_wrong_key_returns_none_or_mismatch():
    ct = xxtea.encrypt(b"the original plaintext body", "rightkey")
    # a wrong key almost always makes the trailing length word invalid -> None
    wrong = xxtea.decrypt(ct, "wrong-key!!")
    assert wrong != b"the original plaintext body"


def test_non_multiple_of_four_is_rejected():
    assert xxtea.decrypt(b"abc", KEY16) is None       # < 8 bytes
    assert xxtea.decrypt(b"a" * 9, KEY16) is None     # not a multiple of 4


def test_empty_input():
    assert xxtea.encrypt(b"", KEY16) == b""
    assert xxtea.decrypt(b"", KEY16) is None
