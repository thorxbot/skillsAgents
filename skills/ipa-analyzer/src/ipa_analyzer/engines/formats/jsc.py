"""Cocos ``.jsc`` script blobs.

What a ``.jsc`` is depends on the Cocos flavour:

* Cocos Creator (1.7+ / 2.x / 3.x): not bytecode.  ``cocos-engine`` ``native/cocos/bindings/jswrapper/sm/
  ScriptEngine.cpp`` says "jsc file isn't bytecode format anymore, it's a xxtea encrypted binary format instead"
  and ``bindings/manual/jsb_global_init.cpp`` decrypts it with ``xxtea_decrypt`` (no sign prefix) and gunzips the
  result when ``ZipUtils::isGZipBuffer`` says so (the "Zip Compress" build option).
* cocos2d-x JS bindings (3.x): SpiderMonkey bytecode loaded through ``JS_DecodeScript``
  (``ScriptingCore.cpp``).  UNVERIFIED: the byte layout of that format, so it cannot be told apart from ciphertext
  by content; only the flavour (directory layout) decides the interpretation.

``classify_jsc`` therefore reports structure facts (text / gzip / opaque, entropy, size parity) and leaves the
interpretation to the caller.  Nothing is decrypted.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from ...util import magic as _magic


@dataclass
class JscInfo:
    kind: str                       # plain_text | gzip | opaque | empty
    entropy_high: Optional[bool] = None
    size_mod4_zero: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "entropy_high": self.entropy_high, "size_mod4_zero": self.size_mod4_zero}


def classify_jsc(head: bytes, size: int, entropy_high: Optional[bool]) -> JscInfo:
    head = bytes(head)
    if size == 0 or not head:
        return JscInfo("empty")
    if _magic.is_texty(head[:1024]):
        return JscInfo("plain_text", entropy_high, size % 4 == 0)
    if head[:2] == b"\x1f\x8b":
        return JscInfo("gzip", entropy_high, size % 4 == 0)
    return JscInfo("opaque", entropy_high, size % 4 == 0)


def interpret(flavour: str, info: JscInfo) -> str:
    """``creator_xxtea_documented`` | ``spidermonkey_bytecode_or_cipher`` | ``plain`` | ``gzip_only``."""
    if info.kind == "plain_text":
        return "plain"
    if info.kind == "gzip":
        return "gzip_only"
    if flavour.startswith("cocos_creator"):
        return "creator_xxtea_documented"
    return "spidermonkey_bytecode_or_cipher"
