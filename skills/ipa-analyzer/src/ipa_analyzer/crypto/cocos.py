"""Decrypt cocos script protection, and recover the XXTEA key the app embeds in its own binary.

Two script schemes are handled (both use xxtea-c; see :mod:`.xxtea` and ``references/cocos-family.md``):

* **Lua** (``CCLuaStack.cpp`` ``luaLoadBuffer``): a chunk whose first bytes equal the project *sign* is decrypted by
  passing ``chunk + signLen`` to ``xxtea_decrypt``.  The template sign is ``"XXTEA"``.  :func:`decrypt_lua`.
* **Cocos Creator ``.jsc``** (``jsb_global_init.cpp``): the whole file is ``xxtea_decrypt``-ed (no sign) and then
  gunzipped when the plaintext is gzip ("Zip Compress" build option).  :func:`decrypt_jsc`.

The key is not transported or derived cryptographically -- the app ships it so it can decrypt its own content at
run time.  :func:`recover_key` mirrors what a reviewer does by hand: harvest printable strings from the app binary
(plus any the operator supplies), try each as the key against a few encrypted samples, and keep the one whose
output is valid script.  This only works on apps whose binary is readable (not FairPlay-encrypted) and whose key
is a plain string, and it is meant for apps the operator owns or is authorised to assess.
"""
from __future__ import annotations

import gzip
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence

from . import xxtea

DEFAULT_SIGN = b"XXTEA"
LUA_BYTECODE_MAGIC = b"\x1bLua"
GZIP_MAGIC = b"\x1f\x8b"

# Printable-ASCII runs that could be a key: 4..32 bytes, no whitespace/control.
_ASCII_RUN = re.compile(rb"[\x21-\x7e]{4,32}")


def _as_bytes(value) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else bytes(value)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    ok = sum(1 for b in data if b in (9, 10, 13) or 0x20 <= b < 0x7F)
    return ok / len(data)


def looks_like_lua(data: bytes) -> bool:
    """Decrypted Lua is either compiled bytecode (``\\x1bLua``) or mostly-printable source."""
    if not data:
        return False
    if data[:4] == LUA_BYTECODE_MAGIC:
        return True
    return _printable_ratio(data[:4096]) >= 0.85


def looks_like_text_asset(data: bytes) -> bool:
    """A decrypted ``.jsc`` is JS/JSON source: decodes as UTF-8 and is mostly printable."""
    if not data:
        return False
    try:
        data[:4096].decode("utf-8")
    except UnicodeDecodeError:
        return False
    return _printable_ratio(data[:4096]) >= 0.85


@dataclass
class DecryptResult:
    ok: bool
    plaintext: Optional[bytes] = None
    scheme: str = ""              # lua | jsc
    gunzipped: bool = False
    reason: str = ""

    def __bool__(self) -> bool:
        return self.ok


def decrypt_lua(data: bytes, key, sign: bytes = DEFAULT_SIGN) -> DecryptResult:
    """Decrypt a cocos Lua chunk: require the ``sign`` prefix, then xxtea-decrypt the remainder."""
    data = bytes(data)
    sign = bytes(sign)
    if sign and data[:len(sign)] != sign:
        return DecryptResult(False, reason="missing sign prefix")
    body = data[len(sign):]
    plain = xxtea.decrypt(body, _as_bytes(key))
    if plain is None:
        return DecryptResult(False, reason="xxtea length word rejected (wrong key?)")
    if not looks_like_lua(plain):
        return DecryptResult(False, reason="decrypted bytes are not Lua")
    return DecryptResult(True, plain, "lua")


def decrypt_jsc(data: bytes, key) -> DecryptResult:
    """Decrypt a Cocos Creator ``.jsc``: xxtea-decrypt the whole file, gunzip when the plaintext is gzip."""
    plain = xxtea.decrypt(bytes(data), _as_bytes(key))
    if plain is None:
        return DecryptResult(False, reason="xxtea length word rejected (wrong key?)")
    gunzipped = False
    if plain[:2] == GZIP_MAGIC:
        try:
            plain = gzip.decompress(plain)
            gunzipped = True
        except OSError:
            return DecryptResult(False, reason="gzip magic but inflate failed (wrong key?)")
    if not looks_like_text_asset(plain):
        return DecryptResult(False, reason="decrypted bytes are not script text")
    return DecryptResult(True, plain, "jsc", gunzipped=gunzipped)


# ------------------------------------------------------------------------------------- key recovery
@dataclass
class Sample:
    """One encrypted script to validate a candidate key against."""
    scheme: str                   # lua | jsc
    data: bytes


@dataclass
class KeyRecovery:
    key: Optional[bytes] = None
    sign: bytes = DEFAULT_SIGN
    source: str = ""              # provided | binary_string
    tried: int = 0
    validated_samples: int = 0
    candidates_from_binary: int = 0
    extra_keys: List[bytes] = field(default_factory=list)   # other candidates that also validated

    def to_dict(self) -> Dict[str, object]:
        return {
            "found": self.key is not None,
            "key_ascii": self.key.decode("ascii", "replace") if self.key else None,
            "key_hex": self.key.hex() if self.key else None,
            "sign_ascii": self.sign.decode("ascii", "replace") if self.sign else None,
            "source": self.source or None,
            "candidates_tried": self.tried,
            "candidates_from_binary": self.candidates_from_binary,
            "samples_validated": self.validated_samples,
            "other_matching_keys": [k.decode("ascii", "replace") for k in self.extra_keys] or None,
        }


def candidate_keys_from_binary(binary: bytes, *, max_bytes: int = 64 * 1024 * 1024,
                               max_candidates: int = 20000) -> List[bytes]:
    """Distinct printable-ASCII runs (4..32 bytes) in the first ``max_bytes`` of the binary, order preserved."""
    seen: Dict[bytes, None] = {}
    for m in _ASCII_RUN.finditer(binary[:max_bytes]):
        run = m.group(0)
        if run not in seen:
            seen[run] = None
            if len(seen) >= max_candidates:
                break
    return list(seen.keys())


def _validate(key: bytes, sign: bytes, samples: Sequence[Sample]) -> int:
    """How many samples ``key`` decrypts cleanly (0 means this key does not fit)."""
    hits = 0
    for s in samples:
        res = decrypt_jsc(s.data, key) if s.scheme == "jsc" else decrypt_lua(s.data, key, sign)
        if res.ok:
            hits += 1
    return hits


def recover_key(samples: Sequence[Sample], *, provided_keys: Sequence[bytes] = (),
                binary: Optional[bytes] = None, sign: bytes = DEFAULT_SIGN,
                binary_candidate_cap: int = 20000) -> KeyRecovery:
    """Find a key that decrypts ``samples``.

    Order of trial: operator-provided keys, the template default, then printable strings from ``binary``.  A key
    must validate at least one sample to count.  Returns the first key that validates **all** samples, else the
    key that validates the most (ties broken by trial order).
    """
    rec = KeyRecovery(sign=bytes(sign))
    if not samples:
        return rec
    ordered: List[tuple] = [(_as_bytes(k), "provided") for k in provided_keys]
    ordered.append((DEFAULT_SIGN, "provided"))          # "XXTEA" is a common key as well as the sign
    from_binary: List[bytes] = []
    if binary:
        from_binary = candidate_keys_from_binary(binary, max_candidates=binary_candidate_cap)
        rec.candidates_from_binary = len(from_binary)
        ordered.extend((k, "binary_string") for k in from_binary)

    best: Optional[tuple] = None        # (hits, key, source)
    matches: List[bytes] = []
    tried_keys: Dict[bytes, None] = {}
    for key, source in ordered:
        if key in tried_keys:
            continue
        tried_keys[key] = None
        rec.tried += 1
        hits = _validate(key, rec.sign, samples)
        if hits:
            matches.append(key)
            if best is None or hits > best[0]:
                best = (hits, key, source)
            if hits == len(samples):
                break
    if best is not None:
        rec.key, rec.validated_samples, rec.source = best[1], best[0], best[2]
        rec.extra_keys = [k for k in matches if k != best[1]][:5]
    return rec


DecryptFn = Callable[[bytes, bytes], DecryptResult]
