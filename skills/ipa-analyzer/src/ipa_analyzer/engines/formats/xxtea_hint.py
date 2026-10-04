"""Structure hints for XXTEA-style script protection (detection only: no key, no decryption).

Facts used:

* cocos2d-x Lua (``cocos/scripting/lua-bindings/manual/CCLuaStack.cpp``, ``luaLoadBuffer``): a chunk is decrypted
  when it starts with the configured *sign* (``strncmp(chunk, _xxteaSign, _xxteaSignLen) == 0``) and the rest is
  passed to ``xxtea_decrypt``.  There is no default; the lua project template calls
  ``setXXTEAKeyAndSign(<key>, <key length>, "XXTEA", 5)`` so "XXTEA" is the sign of unmodified projects.
* ``xxtea-c`` (``xxtea.c``): the plaintext length is appended as an extra 32-bit word and the data is padded to
  whole words, so ciphertext length is ``(ceil(len/4) + 1) * 4`` -- a multiple of 4 and at least 8 bytes.
  (cocos bundles an XXTEA library of the same family; byte-identical behaviour is UNVERIFIED.)
* Cocos Creator's ``.jsc`` has no sign prefix (``jsb_global_init.cpp`` passes the whole file to ``xxtea_decrypt``).

A shared leading byte string plus ``(size - prefix) % 4 == 0`` for (almost) all high-entropy files is therefore
the footprint of "sign + XXTEA"; one of the two alone proves nothing (any custom header has a shared prefix; one
file in four has a size divisible by four).
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Optional, Sequence

DEFAULT_TEMPLATE_SIGN = b"XXTEA"


def common_prefix(heads: Sequence[bytes], *, min_len: int, max_len: int, support_min: float,
                  min_files: int) -> Optional[Dict[str, Any]]:
    """Longest prefix (``min_len``..``max_len`` bytes) shared by at least ``support_min`` of ``heads``."""
    heads = [bytes(h) for h in heads if len(h) >= min_len]
    n = len(heads)
    if n < min_files:
        return None
    for k in range(min(max_len, min(len(h) for h in heads)), min_len - 1, -1):
        pref, cnt = Counter(h[:k] for h in heads).most_common(1)[0]
        if cnt / float(n) >= support_min:
            printable = pref.decode("ascii") if all(0x20 <= b < 0x7F for b in pref) else None
            return {"length": k, "hex": pref.hex(), "ascii": printable, "support": round(cnt / float(n), 3),
                    "files": n, "is_template_default_sign": pref[:5] == DEFAULT_TEMPLATE_SIGN}
    return None


def size_structure(sizes: Sequence[int], prefix_len: int) -> Dict[str, Any]:
    """Share of files whose size minus the prefix is a multiple of 4 and at least 8 (the xxtea-c ciphertext shape)."""
    body = [s - prefix_len for s in sizes]
    n = len(body)
    if n == 0:
        return {"files": 0, "mod4_share": None, "min8_share": None}
    return {"files": n, "mod4_share": round(sum(1 for b in body if b % 4 == 0) / float(n), 3),
            "min8_share": round(sum(1 for b in body if b >= 8) / float(n), 3)}


def script_hint(heads: Sequence[bytes], sizes: Sequence[int], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Combine prefix and size structure for the high-entropy script files (``cfg`` = ``xxtea`` settings)."""
    pref = common_prefix(heads, min_len=cfg["prefix_min_len"], max_len=cfg["prefix_max_len"],
                         support_min=cfg["prefix_support_min"], min_files=cfg["min_files"])
    plen = pref["length"] if pref else 0
    sz = size_structure(sizes, plen)
    mod4 = sz["mod4_share"]
    structured = bool(mod4 is not None and mod4 >= cfg["mod4_share_min"] and sz["files"] >= cfg["min_files"])
    return {"sign_prefix": pref, "size_structure": sz, "xxtea_shape": structured,
            "consistent_sign_and_shape": bool(pref and structured)}


def deviations(hint: Dict[str, Any], binary_hits: Dict[str, List[str]]) -> List[str]:
    """Deviations from stock cocos XXTEA usage (ids; evidence only)."""
    out: List[str] = []
    native = bool(binary_hits.get("xxtea_api") or binary_hits.get("xxtea_key_setter"))
    if native and not hint.get("sign_prefix") and hint.get("size_structure", {}).get("files"):
        out.append("xxtea_in_binary_but_no_common_sign_prefix_in_scripts")
    if hint.get("sign_prefix") and not hint.get("xxtea_shape"):
        out.append("common_prefix_without_xxtea_size_structure")
    if hint.get("sign_prefix") and not hint["sign_prefix"].get("is_template_default_sign"):
        out.append("non_default_sign_prefix")
    if binary_hits.get("blowfish"):
        out.append("blowfish_hint_in_binary")
    return out
