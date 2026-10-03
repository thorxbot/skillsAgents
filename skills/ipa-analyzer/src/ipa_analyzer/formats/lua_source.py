"""Lexical Lua *source* dialect hints (minimum language version) for plain-text scripts.

Comments and string literals are stripped first (single linear pass, no regex backtracking over
long strings), then the remaining code is checked for syntax that only exists from a given Lua
version on.  Language facts used (Lua reference manuals, "Incompatibilities with the previous
version" sections of 5.2, 5.3 and 5.4, https://www.lua.org/manual/):

* 5.2 added ``goto`` / ``::label::`` and the ``bit32`` library (deprecated in 5.3, absent in 5.4).
* 5.3 added the bitwise operators ``& | ~ << >>`` (``~`` also as unary), floor division ``//``,
  ``utf8``, ``string.pack/unpack``, ``math.tointeger/type`` and ``table.move``.
* 5.4 added variable attributes ``<const>`` and ``<close>``.
* ``setfenv``, ``getfenv`` and ``table.getn`` were removed in 5.2; ``module``, ``loadstring`` and the
  global ``unpack`` were deprecated in 5.2 and removed in 5.3.  They only indicate a 5.1-style
  script (compat builds and LuaJIT still provide most of them), so they are reported as style
  hints and never as a maximum version.
* LuaJIT accepts ``goto`` and adds ``ffi``, ``jit``, ``bit`` and the ``LL`` / ``ULL`` integer
  suffixes; those are reported as ``luajit_signals`` because they say nothing about PUC versions.

Lua 5.5 syntax (e.g. the ``global`` declaration) is intentionally not inferred -- UNVERIFIED.
This is a heuristic on text only: a script that uses none of these features is compatible with
every version and gets ``min_version=None``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Union

__all__ = ["DialectHints", "MAX_SOURCE_BYTES", "strip_comments_and_strings", "infer_dialect"]

#: Only the first 256 KiB are examined; ``DialectHints.truncated`` says when that cut anything off.
MAX_SOURCE_BYTES = 256 * 1024

_TOKEN_START = re.compile(r"--|\"|'|\[=*\[")
_LONG_OPEN = re.compile(r"\[(=*)\[")
_DQ = re.compile(r'(?:\\.|[^"\\\n])*"', re.DOTALL)
_SQ = re.compile(r"(?:\\.|[^'\\\n])*'", re.DOTALL)


def strip_comments_and_strings(text: str) -> str:
    """Return ``text`` with comments removed and string literals replaced by ``""``.

    Newlines inside removed regions are kept so line structure survives.  Unterminated strings or
    long brackets swallow the rest of the input, like a Lua lexer error would.
    """
    return _strip(text, keep_strings=False)


def _strip(text: str, *, keep_strings: bool) -> str:
    out: List[str] = []
    pos = 0
    n = len(text)
    while pos < n:
        m = _TOKEN_START.search(text, pos)
        if m is None:
            out.append(text[pos:])
            break
        start = m.start()
        out.append(text[pos:start])
        tok = m.group(0)
        if tok == "--":
            lm = _LONG_OPEN.match(text, start + 2)
            if lm:
                close = "]" + lm.group(1) + "]"
                end = text.find(close, lm.end())
                end = n if end < 0 else end + len(close)
                out.append("\n" * text.count("\n", start, end))
                pos = end
            else:
                nl = text.find("\n", start)
                pos = n if nl < 0 else nl  # keep the newline itself
        elif tok in ('"', "'"):
            sm = (_DQ if tok == '"' else _SQ).match(text, start + 1)
            if sm:
                if keep_strings:
                    out.append(text[start : sm.end()])
                else:
                    out.append('""')
                    out.append("\n" * text.count("\n", start, sm.end()))
                pos = sm.end()
            else:  # unterminated: drop the quote and carry on
                pos = start + 1
        else:  # long string
            lm = _LONG_OPEN.match(text, start)
            close = "]" + (lm.group(1) if lm else "") + "]"
            end = text.find(close, lm.end() if lm else start + 2)
            end = n if end < 0 else end + len(close)
            if keep_strings:
                out.append(text[start:end])
            else:
                out.append('""')
                out.append("\n" * text.count("\n", start, end))
            pos = end
    return "".join(out)


@dataclass
class DialectHints:
    min_version: Optional[str] = None  # "5.1".."5.4" or None when nothing version-specific was seen
    signals: List[str] = field(default_factory=list)
    style_hints: List[str] = field(default_factory=list)  # e.g. "lua51_api"
    luajit_signals: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    confidence: float = 0.0
    scanned_bytes: int = 0
    truncated: bool = False

    def to_dict(self) -> dict:
        return {
            "min_version": self.min_version,
            "signals": list(self.signals),
            "style_hints": list(self.style_hints),
            "luajit_signals": list(self.luajit_signals),
            "conflicts": list(self.conflicts),
            "confidence": self.confidence,
            "scanned_bytes": self.scanned_bytes,
            "truncated": self.truncated,
        }


# (signal name, compiled regex, minimum version, strength)
_SYNTAX_RULES: Tuple[Tuple[str, "re.Pattern[str]", str, float], ...] = (
    ("label", re.compile(r"::\s*[A-Za-z_]\w*\s*::"), "5.2", 0.9),
    ("goto", re.compile(r"(?<![\w.:])goto\s+[A-Za-z_]\w*"), "5.2", 0.8),
    ("floor_division", re.compile(r"//"), "5.3", 0.9),
    ("bitwise_shift", re.compile(r"<<|>>"), "5.3", 0.9),
    ("bitwise_and_or", re.compile(r"[&|]"), "5.3", 0.9),
    ("bitwise_xor_not", re.compile(r"~(?!=)"), "5.3", 0.9),
    ("attrib_const_close", re.compile(r"[A-Za-z_]\w*\s*<\s*(?:const|close)\s*>"), "5.4", 0.95),
)
_LIB_RULES: Tuple[Tuple[str, "re.Pattern[str]", str, float], ...] = (
    ("lib_bit32", re.compile(r"(?<![\w.])bit32\s*\."), "5.2", 0.6),
    ("lib_table_unpack", re.compile(r"(?<![\w])table\s*\.\s*unpack\b"), "5.2", 0.5),
    ("lib_utf8", re.compile(r"(?<![\w.])utf8\s*\."), "5.3", 0.6),
    ("lib_math_53", re.compile(r"(?<![\w])math\s*\.\s*(?:tointeger|type|ult)\b"), "5.3", 0.6),
    ("lib_string_pack", re.compile(r"(?<![\w])string\s*\.\s*(?:pack|unpack|packsize)\b"), "5.3", 0.6),
    ("lib_table_move", re.compile(r"(?<![\w])table\s*\.\s*move\b"), "5.3", 0.6),
)
_STYLE_RULES: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("setfenv_getfenv", re.compile(r"(?<![\w.:])(?:setfenv|getfenv)\s*\(")),
    ("module_call", re.compile(r"(?<![\w.:])module\s*(?:\(|[\"'])")),
    ("loadstring", re.compile(r"(?<![\w.:])loadstring\s*[(\"']")),
    ("global_unpack", re.compile(r"(?<![\w.:])unpack\s*\(")),
    ("table_getn", re.compile(r"(?<![\w])table\s*\.\s*getn\b")),
)
_LUAJIT_RULES: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("ffi", re.compile(r"(?<![\w.])ffi\s*\.\s*(?:cdef|new|load|cast|typeof|string|C)\b")),
    ("jit", re.compile(r"(?<![\w.])jit\s*\.\s*(?:on|off|status|opt|flush|version)\b")),
    ("bit_lib", re.compile(r"(?<![\w.])bit\s*\.\s*(?:band|bor|bxor|bnot|lshift|rshift|arshift|rol|ror|tobit|tohex|bswap)\b")),
    ("ll_suffix", re.compile(r"\b(?:0[xX][0-9A-Fa-f]+|\d+)(?:U?LL)\b")),
)
_REQUIRE_FFI = re.compile(r"(?<![\w.])require\s*\(?\s*[\"']ffi[\"']")
# UNVERIFIED: Lua 5.5 syntax (e.g. the `global` declaration) is deliberately not inferred.
_VERSION_ORDER = {"5.1": 1, "5.2": 2, "5.3": 3, "5.4": 4}


def infer_dialect(text: Union[str, bytes], *, max_bytes: int = MAX_SOURCE_BYTES) -> DialectHints:
    """Infer the minimum Lua version needed by ``text`` from lexical features.

    Only the first ``max_bytes`` are examined (cut at a line boundary); ``truncated`` is set when
    the input was longer.  ``confidence`` is the strongest matching signal (0.0 when none).
    """
    hints = DialectHints()
    if isinstance(text, (bytes, bytearray)):
        raw = bytes(text)
        hints.truncated = len(raw) > max_bytes
        raw = raw[:max_bytes]
        if hints.truncated and b"\n" in raw:
            raw = raw[: raw.rfind(b"\n")]
        hints.scanned_bytes = len(raw)
        src = raw.decode("utf-8", "replace")
    else:
        enc_len = len(text)
        hints.truncated = enc_len > max_bytes
        src = text[:max_bytes]
        if hints.truncated and "\n" in src:
            src = src[: src.rfind("\n")]
        hints.scanned_bytes = len(src.encode("utf-8", "replace"))

    if src.startswith("﻿"):
        src = src[1:]
    if src.startswith("#"):  # shebang line
        nl = src.find("\n")
        src = "" if nl < 0 else src[nl:]

    code = strip_comments_and_strings(src)
    code_strings = _strip(src, keep_strings=True)  # for require("ffi")-style checks

    best = 0
    best_version: Optional[str] = None
    strongest = 0.0
    versions_seen = {}
    for name, rx, version, strength in _SYNTAX_RULES + _LIB_RULES:
        if rx.search(code):
            hints.signals.append(f"{name}>={version}")
            versions_seen[name] = version
            strongest = max(strongest, strength)
            if _VERSION_ORDER[version] > best:
                best = _VERSION_ORDER[version]
                best_version = version
    for name, rx in _STYLE_RULES:
        if rx.search(code):
            hints.style_hints.append(name)
    for name, rx in _LUAJIT_RULES:
        if rx.search(code) or (name == "ffi" and _REQUIRE_FFI.search(code_strings)):
            hints.luajit_signals.append(name)

    hints.min_version = best_version
    hints.confidence = round(strongest, 2)
    if hints.style_hints and best >= _VERSION_ORDER["5.3"]:
        hints.conflicts.append("lua51_style_api_with_5.3_or_newer_syntax")
    return hints
