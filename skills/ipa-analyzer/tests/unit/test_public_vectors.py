"""Public reference vectors (``tests/fixtures/public/vectors.json``): XXTEA (xxtea-c), AES-256 (FIPS-197), UnityCN
signature relation (UnityPy).  The XXTEA reference below is test-local on purpose: it pins the algorithm
(little-endian words, trailing length word, key zero-padded / truncated to 16 bytes, DELTA 0x9e3779b9, rounds
6 + 52 / n) so any implementation added to the package can be pointed at the same vectors.
"""
from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

VECTORS = json.loads((Path(__file__).resolve().parents[1] / "fixtures" / "public" / "vectors.json")
                     .read_text(encoding="utf-8"))
M32 = 0xFFFFFFFF
DELTA = 0x9E3779B9


def _words(b: bytes, with_len: bool):
    n = (len(b) + 3) // 4
    w = list(struct.unpack("<%dI" % n, b.ljust(n * 4, b"\0")))
    return w + [len(b)] if with_len else w


def _mx(s, y, z, p, e, k):
    return ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((s ^ y) + (k[(p & 3) ^ e] ^ z))) & M32


def _key(key: bytes):
    key = key[:16].ljust(16, b"\0")
    return list(struct.unpack("<4I", key))


def xxtea_encrypt(data: bytes, key: bytes) -> bytes:
    v, k = _words(data, True), _key(key)
    n = len(v) - 1
    z, s = v[n], 0
    for _ in range(6 + 52 // (n + 1)):
        s = (s + DELTA) & M32
        e = (s >> 2) & 3
        for p in range(n):
            y = v[p + 1]
            v[p] = z = (v[p] + _mx(s, y, z, p, e, k)) & M32
        y = v[0]
        v[n] = z = (v[n] + _mx(s, y, z, n, e, k)) & M32
    return struct.pack("<%dI" % len(v), *v)


def xxtea_decrypt(data: bytes, key: bytes) -> bytes:
    v, k = list(struct.unpack("<%dI" % (len(data) // 4), data)), _key(key)
    n = len(v) - 1
    q = 6 + 52 // (n + 1)
    s = (q * DELTA) & M32
    y = v[0]
    while s:
        e = (s >> 2) & 3
        for p in range(n, 0, -1):
            z = v[p - 1]
            v[p] = y = (v[p] - _mx(s, y, z, p, e, k)) & M32
        z = v[n]
        v[0] = y = (v[0] - _mx(s, y, z, 0, e, k)) & M32
        s = (s - DELTA) & M32
    out = struct.pack("<%dI" % len(v), *v)
    length = v[-1]
    assert len(out) - 7 <= length <= len(out) - 4, "bad trailing length word (wrong key?)"
    return out[:length]


@pytest.mark.parametrize("vec", VECTORS["xxtea"], ids=lambda v: v["name"])
def test_xxtea_matches_reference_implementation(vec):
    key, plain, cipher = vec["key"].encode(), bytes.fromhex(vec["plain_hex"]), bytes.fromhex(vec["cipher_hex"])
    assert xxtea_encrypt(plain, key) == cipher
    assert xxtea_decrypt(cipher, key) == plain


def test_xxtea_wrong_key_is_detectable_via_the_length_word():
    vec = VECTORS["xxtea"][-1]
    with pytest.raises(AssertionError):
        xxtea_decrypt(bytes.fromhex(vec["cipher_hex"]), b"not-the-key")


def test_xxtea_key_is_zero_padded_and_truncated_to_16():
    by_name = {v["name"]: v for v in VECTORS["xxtea"]}
    long = by_name["len100_key20_truncated"]
    plain, cipher = bytes.fromhex(long["plain_hex"]), bytes.fromhex(long["cipher_hex"])
    assert xxtea_encrypt(plain, long["key"][:16].encode()) == cipher            # bytes past 16 are ignored
    short = by_name["len17_key3"]
    assert xxtea_encrypt(bytes.fromhex(short["plain_hex"]), b"abc" + b"\0" * 13) == bytes.fromhex(short["cipher_hex"])


def test_aes256_fips197_vector_and_unitycn_signature_relation():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def ecb_encrypt(key: bytes, block: bytes) -> bytes:
        enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        return enc.update(block) + enc.finalize()

    f = VECTORS["aes256_ecb_fips197"]
    assert ecb_encrypt(bytes.fromhex(f["key_hex"]), bytes.fromhex(f["plain_hex"])).hex() == f["cipher_hex"]

    u = VECTORS["unitycn_signature_check"]                  # UnityPy decrypt_key(key_sig, data_sig, key)
    pad = ecb_encrypt(u["synthetic_key_ascii"].encode(), bytes.fromhex(u["key_sig_hex"]))
    sig = bytes(a ^ b for a, b in zip(bytes.fromhex(u["data_sig_hex"]), pad))
    assert sig == u["signature_ascii"].encode() == b"#$unity3dchina!@"
    wrong = ecb_encrypt(b"fedcba9876543210", bytes.fromhex(u["key_sig_hex"]))
    assert bytes(a ^ b for a, b in zip(bytes.fromhex(u["data_sig_hex"]), wrong)) != b"#$unity3dchina!@"
