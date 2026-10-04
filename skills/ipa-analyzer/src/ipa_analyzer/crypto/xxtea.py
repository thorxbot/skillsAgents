"""XXTEA (Corrected Block TEA), byte-for-byte compatible with the ``xxtea-c`` library cocos bundles.

Cocos encrypts Lua chunks and Cocos Creator ``.jsc`` scripts with the xxtea-c library by Ma Bingyao
(``external/xxtea``; same family as ``https://github.com/xxtea/xxtea-c``).  Its wire format, which this module
reproduces, is:

* the key is packed little-endian into 32-bit words and zero-padded to 16 bytes (4 words);
* the plaintext is packed little-endian into words; on encrypt an extra trailing word holds the original byte
  length, so ciphertext is ``(ceil(len / 4) + 1) * 4`` bytes -- always a multiple of 4 and at least 8;
* the mixing function uses ``DELTA = 0x9E3779B9`` and ``rounds = 6 + 52 // n``.

``decrypt`` reverses this and recovers the exact original length from the trailing word; it returns ``None`` when
the length word is inconsistent (wrong key, or not xxtea-c ciphertext), so callers can treat ``None`` as "this key
does not fit".  Nothing here reads files, keys or the network: it is pure bytes-in / bytes-out.
"""
from __future__ import annotations

import struct
from typing import List, Optional

DELTA = 0x9E3779B9
_MASK = 0xFFFFFFFF


def _mx(summ: int, y: int, z: int, p: int, e: int, key: List[int]) -> int:
    return ((((z >> 5) ^ ((y << 2) & _MASK)) + ((y >> 3) ^ ((z << 4) & _MASK)))
            ^ (((summ ^ y) + (key[(p & 3) ^ e] ^ z)) & _MASK)) & _MASK


def _to_words(data: bytes, include_length: bool) -> List[int]:
    """Pack ``data`` little-endian into 32-bit words; append a length word when ``include_length``."""
    n = (len(data) + 3) // 4
    words = [0] * n
    for i, b in enumerate(data):
        words[i >> 2] |= b << ((i & 3) << 3)
    if include_length:
        words.append(len(data))
    return words


def _from_words(words: List[int], include_length: bool) -> Optional[bytes]:
    """Inverse of :func:`_to_words`; validates and honours the trailing length word when ``include_length``."""
    n = len(words) << 2
    if include_length:
        m = words[-1]
        n -= 4
        if m < n - 3 or m > n:        # xxtea-c rejects a length word outside this window
            return None
        n = m
        words = words[:-1]
    out = bytearray(n)
    for i in range(n):
        out[i] = (words[i >> 2] >> ((i & 3) << 3)) & 0xFF
    return bytes(out)


def _fix_key(key: bytes) -> List[int]:
    k = _to_words(key, False)
    while len(k) < 4:                 # xxtea-c pads a short key to 16 bytes (4 words) with zeros
        k.append(0)
    return k


def _encrypt_words(v: List[int], key: List[int]) -> None:
    n = len(v)
    if n < 2:
        return
    rounds = 6 + 52 // n
    summ = 0
    z = v[n - 1]
    for _ in range(rounds):
        summ = (summ + DELTA) & _MASK
        e = (summ >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            z = v[p] = (v[p] + _mx(summ, y, z, p, e, key)) & _MASK
        y = v[0]
        z = v[n - 1] = (v[n - 1] + _mx(summ, y, z, n - 1, e, key)) & _MASK


def _decrypt_words(v: List[int], key: List[int]) -> None:
    n = len(v)
    if n < 2:
        return
    rounds = 6 + 52 // n
    summ = (rounds * DELTA) & _MASK
    y = v[0]
    while summ != 0:
        e = (summ >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            y = v[p] = (v[p] - _mx(summ, y, z, p, e, key)) & _MASK
        z = v[n - 1]
        y = v[0] = (v[0] - _mx(summ, y, z, 0, e, key)) & _MASK
        summ = (summ - DELTA) & _MASK


def _as_bytes(key) -> bytes:
    return key.encode("utf-8") if isinstance(key, str) else bytes(key)


def encrypt(data: bytes, key) -> bytes:
    """xxtea-c ``xxtea_encrypt``: encrypt ``data`` under ``key`` (str or bytes). Empty input returns empty."""
    if not data:
        return b""
    v = _to_words(bytes(data), True)
    _encrypt_words(v, _fix_key(_as_bytes(key)))
    return b"".join(struct.pack("<I", w) for w in v)


def decrypt(data: bytes, key) -> Optional[bytes]:
    """xxtea-c ``xxtea_decrypt``: recover the plaintext, or ``None`` if ``key`` / input does not fit the format.

    Returns ``None`` (never raises) when the length is not a positive multiple of 4, when there are fewer than two
    words, or when the decrypted trailing length word is out of range -- all of which mean "wrong key" in practice.
    """
    data = bytes(data)
    if len(data) < 8 or len(data) % 4 != 0:
        return None
    v = list(struct.unpack("<%dI" % (len(data) // 4), data))
    _decrypt_words(v, _fix_key(_as_bytes(key)))
    return _from_words(v, True)
