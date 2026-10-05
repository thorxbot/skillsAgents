"""Operator-key decryption for arbitrary files, used by the ``decrypt`` CLI subcommand.

A cross-engine escape hatch for apps the operator owns or is authorised to assess: when the detection stages flag a
file as encrypted but the scheme is custom, the operator supplies the key and the scheme here and gets plaintext out.
No key is recovered or guessed -- the caller provides it. Schemes:

* ``xor``   -- repeating-key XOR (key as raw bytes / ASCII / hex).
* ``xxtea`` -- cocos xxtea-c; optional ``sign`` prefix (Lua), optional gunzip of the result (Creator ``.jsc``).
* ``ccz``   -- cocos2d-x ``CCZp`` texture (4-part PVR key); see :mod:`.ccz`.

Each scheme can be followed by an automatic decompress step (gzip / zlib) when the plaintext is a compressed stream.
Nothing executes; output is bytes.
"""
from __future__ import annotations

import gzip
import zlib
from dataclasses import dataclass
from typing import Optional

from . import ccz as _ccz
from . import xxtea

SCHEMES = ("xor", "xxtea", "ccz")


@dataclass
class Decrypted:
    ok: bool
    data: Optional[bytes] = None
    scheme: str = ""
    post: str = ""                 # "" | gzip | zlib (decompression applied after the cipher)
    reason: str = ""

    def __bool__(self) -> bool:
        return self.ok


def parse_key_bytes(text: str) -> bytes:
    """A key given as ``hex:0a1b..`` (hex) or ``str:..`` / plain text (UTF-8). Empty is rejected by callers."""
    if text.startswith("hex:"):
        return bytes.fromhex(text[4:].strip())
    if text.startswith("str:"):
        return text[4:].encode("utf-8")
    return text.encode("utf-8")


def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("xor key must be non-empty")
    k = key
    if len(k) < len(data):
        k = (key * (len(data) // len(key) + 1))[: len(data)]
    return bytes(b ^ k[i] for i, b in enumerate(data))


def _auto_decompress(data: bytes) -> "tuple[bytes, str]":
    if data[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(data), "gzip"
        except OSError:
            return data, ""
    if data[:1] in (b"\x78",) and len(data) > 2:
        try:
            return zlib.decompress(data), "zlib"
        except zlib.error:
            return data, ""
    return data, ""


def decrypt(data: bytes, scheme: str, *, key_text: str = "", sign: bytes = b"",
            decompress: bool = True) -> Decrypted:
    """Decrypt ``data`` with ``scheme`` and the operator's key; optionally auto-decompress the result."""
    data = bytes(data)
    if scheme not in SCHEMES:
        return Decrypted(False, reason="unknown scheme %r (choose from %s)" % (scheme, ", ".join(SCHEMES)))

    if scheme == "xor":
        try:
            out = xor_bytes(data, parse_key_bytes(key_text))
        except ValueError as exc:
            return Decrypted(False, reason=str(exc))
    elif scheme == "xxtea":
        body = data[len(sign):] if sign and data[:len(sign)] == sign else data
        if sign and data[:len(sign)] != sign:
            return Decrypted(False, reason="data does not start with the given sign prefix")
        out = xxtea.decrypt(body, parse_key_bytes(key_text))
        if out is None:
            return Decrypted(False, reason="xxtea length word rejected (wrong key or not xxtea-c ciphertext)")
    else:  # ccz
        try:
            parts = _ccz.parse_key(key_text)
        except ValueError as exc:
            return Decrypted(False, reason=str(exc))
        out = _ccz.decrypt_ccz(data, parts)
        if out is None:
            return Decrypted(False, reason="CCZ decrypt failed (wrong key or not a CCZ/CCZp file)")

    post = ""
    if decompress and scheme != "ccz":     # ccz already inflates internally
        out, post = _auto_decompress(out)
    return Decrypted(True, out, scheme, post)
