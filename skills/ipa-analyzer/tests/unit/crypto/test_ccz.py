"""Cocos CCZp/PVR texture decryption (crypto/ccz.py)."""
from __future__ import annotations

import os
import struct
import zlib

import pytest

from ipa_analyzer.crypto import ccz

PARTS = (0x01020304, 0x05060708, 0x090A0B0C, 0x0D0E0F10)


@pytest.mark.parametrize("n", [1, 3, 15, 16, 64, 512 * 4, 70000])
def test_ccz_roundtrip(n):
    raw = os.urandom(n)
    enc = ccz.encrypt_ccz(raw, PARTS)
    assert enc[:4] == b"CCZp"
    assert ccz.decrypt_ccz(enc, PARTS) == raw


def test_keystream_is_deterministic_and_long():
    ks = ccz.pvr_keystream(PARTS)
    assert len(ks) == 1024 and all(0 <= w <= 0xFFFFFFFF for w in ks)
    assert ks == ccz.pvr_keystream(PARTS)                 # pure function of the key
    assert ccz.pvr_keystream((1, 2, 3, 4)) != ks          # different key, different stream


def test_wrong_key_rejected():
    enc = ccz.encrypt_ccz(os.urandom(4096), PARTS)
    assert ccz.decrypt_ccz(enc, (1, 2, 3, 4)) is None


def test_plain_ccz_inflated_without_key():
    raw = b"hello texture " * 50
    plain = struct.pack(">4sHHII", b"CCZ!", 0, 2, 0, len(raw)) + zlib.compress(raw)
    assert ccz.decrypt_ccz(plain, (0, 0, 0, 0)) == raw


def test_not_ccz_returns_none():
    assert ccz.decrypt_ccz(b"not a ccz file at all", PARTS) is None


@pytest.mark.parametrize("text,expect", [
    ("01020304 05060708 090a0b0c 0d0e0f10", PARTS),
    ("0102030405060708090a0b0c0d0e0f10", PARTS),
    ("0x1,0x2,0x3,0x4", (1, 2, 3, 4)),
    ("aabbccdd 11223344 55667788 99aabbcc", (0xAABBCCDD, 0x11223344, 0x55667788, 0x99AABBCC)),
])
def test_parse_key(text, expect):
    assert ccz.parse_key(text) == expect


@pytest.mark.parametrize("bad", ["", "1 2 3", "zz", "0102"])
def test_parse_key_rejects_bad(bad):
    with pytest.raises(ValueError):
        ccz.parse_key(bad)
