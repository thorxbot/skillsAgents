"""Cocos2d-x ``CCZp`` (encrypted ``.ccz``) textures, matching ``cocos/base/ZipUtils.cpp`` byte-for-byte.

The app ships a 128-bit key as four ``unsigned int`` parts (``ZipUtils::setPvrEncryptionKey``). ``decodeEncodedPvr``
expands them into a 1024-word keystream by running the XXTEA mix (``DELTA=0x9E3779B9``, 6 rounds) over a zeroed
1024-word block -- i.e. an XXTEA *encrypt* of zeros under the 4-word key -- and then XORs the file words from offset
12: the first 512 words consecutively (wrapping the keystream index at 1024), then every 64th word after that. The
operation is symmetric, so the same routine encrypts and decrypts. After the XOR the header ``len`` field (big-endian,
at offset 12) holds the uncompressed size and the payload from offset 16 is plain zlib.

Only the four key parts are needed and the app embeds them; this is for apps the operator owns or is authorised to
assess. A wrong key leaves garbage, so :func:`decrypt_ccz` validates by a successful zlib inflate to the declared
length and reports failure otherwise.
"""
from __future__ import annotations

import struct
import zlib
from typing import List, Optional, Sequence, Tuple

from . import xxtea

HEADER = struct.Struct(">4sHHII")          # sig, compression_type, version, reserved, len
ENCLEN = 1024
SECURELEN = 512
DISTANCE = 64
SIG_PLAIN = b"CCZ!"
SIG_ENCRYPTED = b"CCZp"


def pvr_keystream(parts: Sequence[int]) -> List[int]:
    """The 1024-word keystream ``decodeEncodedPvr`` derives from the four u32 key parts."""
    if len(parts) != 4:
        raise ValueError("pvr key needs exactly 4 u32 parts")
    v = [0] * ENCLEN
    xxtea._encrypt_words(v, [p & 0xFFFFFFFF for p in parts])   # XXTEA encrypt of zeros, rounds = 6 + 52//1024 = 6
    return v


def _xor_decode(words: List[int], keystream: List[int]) -> None:
    b = 0
    n = len(words)
    i = 0
    while i < n and i < SECURELEN:
        words[i] ^= keystream[b]
        b = 0 if b + 1 >= ENCLEN else b + 1
        i += 1
    while i < n:
        words[i] ^= keystream[b]
        b = 0 if b + 1 >= ENCLEN else b + 1
        i += DISTANCE


def parse_key(text: str) -> Tuple[int, int, int, int]:
    """Parse a ``--pvr-key``: 32 hex chars (16 bytes), or four comma/space separated u32 (hex ``0x..`` or decimal)."""
    s = text.strip()
    cleaned = s[2:] if s[:2].lower() == "0x" else s
    if all(c in "0123456789abcdefABCDEF" for c in cleaned) and len(cleaned) == 32:
        raw = bytes.fromhex(cleaned)
        return tuple(struct.unpack(">4I", raw))  # type: ignore[return-value]
    parts = [p for p in s.replace(",", " ").split() if p]
    if len(parts) != 4:
        raise ValueError("pvr key must be 32 hex chars or four u32 values")
    # four tokens: hex by convention (the key parts are written as hex constants); "0x" optional
    out = [int(p[2:] if p.lower().startswith("0x") else p, 16) for p in parts]
    return tuple(v & 0xFFFFFFFF for v in out)  # type: ignore[return-value]


def _inflate(payload: bytes) -> Optional[bytes]:
    """Inflate a zlib stream, tolerating trailing bytes (the XOR region is truncated to whole words)."""
    try:
        d = zlib.decompressobj()
        out = d.decompress(payload)
        out += d.flush()
    except zlib.error:
        return None
    return out


def inflate_plain_ccz(buf: bytes) -> Optional[bytes]:
    """Inflate an unencrypted ``CCZ!`` buffer; ``None`` if the header is not a supported plain CCZ."""
    if len(buf) < HEADER.size or buf[:4] != SIG_PLAIN:
        return None
    _sig, comp, ver, _reserved, _length = HEADER.unpack(buf[:HEADER.size])
    if comp != 0 or ver > 2:
        return None
    return _inflate(buf[HEADER.size:])


def decrypt_ccz(buf: bytes, parts: Sequence[int]) -> Optional[bytes]:
    """Decrypt a ``CCZp`` texture to its raw (uncompressed) bytes, or ``None`` if the key does not fit.

    A plain ``CCZ!`` buffer is inflated directly (no key needed).
    """
    buf = bytes(buf)
    if buf[:4] == SIG_PLAIN:
        return inflate_plain_ccz(buf)
    if len(buf) < HEADER.size or buf[:4] != SIG_ENCRYPTED:
        return None
    _sig, comp, ver, _reserved, _len = HEADER.unpack(buf[:HEADER.size])
    if comp != 0 or ver > 0:
        return None
    region = buf[12:]
    nwords = len(region) // 4
    if nwords < 1:
        return None
    words = list(struct.unpack("<%dI" % nwords, region[: nwords * 4]))
    _xor_decode(words, pvr_keystream(parts))
    dec = struct.pack("<%dI" % nwords, *words) + region[nwords * 4:]
    plain = buf[:12] + dec
    length = struct.unpack(">I", plain[12:16])[0]
    out = _inflate(plain[HEADER.size:])
    if out is None:
        return None                      # wrong key: payload is not valid zlib
    if length and len(out) != length:
        return None                      # inflated size disagrees with the header -> wrong key
    return out


def encrypt_ccz(raw: bytes, parts: Sequence[int], *, reserved: int = 0) -> bytes:
    """Build a ``CCZp`` file from raw bytes (used by tests; symmetric with :func:`decrypt_ccz`)."""
    compressed = zlib.compress(raw)
    body = struct.pack(">I", len(raw)) + compressed        # the len field lives at offset 12, inside the XOR region
    nwords = len(body) // 4                                # only whole words are XORed (C truncates (len-12)/4)
    words = list(struct.unpack("<%dI" % nwords, body[: nwords * 4]))
    _xor_decode(words, pvr_keystream(parts))               # XOR is symmetric: same routine encrypts
    enc = struct.pack("<%dI" % nwords, *words) + body[nwords * 4:]
    head = struct.pack(">4sHHI", SIG_ENCRYPTED, 0, 0, reserved)   # sig, comp, ver, reserved (len is already in body)
    return head + enc
