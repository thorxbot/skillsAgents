"""Tolerant parser for ``*.lproj/*.strings`` files plus language-code normalisation.

``InfoPlist.strings`` comes in three shapes: binary plist, XML plist, or the OpenStep-style text
format (``"key" = "value";``) encoded as UTF-8 or UTF-16 (with or without BOM). All of them are
handled; malformed input never raises, the parser resynchronises on the next ``;``.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple

from ..util.plist_utils import load_plist

log = logging.getLogger(__name__)

__all__ = ["decode_strings_bytes", "parse_strings_text", "parse_strings_file", "normalize_lang",
           "lang_from_lproj", "lang_rank"]

# Legacy ``<Name>.lproj`` directory names used before ISO codes became the norm.
# Source: Apple "Internationalization and Localization Guide" (legacy language names).
_LEGACY_LPROJ = {
    "english": "en", "french": "fr", "german": "de", "italian": "it", "spanish": "es",
    "dutch": "nl", "japanese": "ja", "swedish": "sv", "danish": "da", "finnish": "fi",
    "norwegian": "nb", "portuguese": "pt", "korean": "ko", "russian": "ru",
}
_HANS_REGIONS = {"CN", "SG"}
_HANT_REGIONS = {"TW", "HK", "MO"}

_UNQUOTED_STOP = set(" \t\r\n=;,{}()\"")


# --- language codes ---------------------------------------------------------------------------
def normalize_lang(code: str) -> str:
    """Normalise a locale / lproj name: ``zh_CN`` -> ``zh-Hans``, ``zh-TW`` -> ``zh-Hant``,
    ``en_GB`` -> ``en-GB``, ``English`` -> ``en``, ``base`` -> ``Base``. Empty input -> ``""``."""
    c = (code or "").strip().replace("_", "-")
    if not c:
        return ""
    low = c.lower()
    if low == "base":
        return "Base"
    if low in _LEGACY_LPROJ:
        return _LEGACY_LPROJ[low]
    parts = [p for p in c.split("-") if p]
    lang = parts[0].lower()
    rest = parts[1:]
    if lang == "zh":
        for p in rest:
            pl = p.lower()
            if pl == "hans":
                return "zh-Hans"
            if pl == "hant":
                return "zh-Hant"
        for p in rest:
            if p.upper() in _HANS_REGIONS:
                return "zh-Hans"
            if p.upper() in _HANT_REGIONS:
                return "zh-Hant"
        return "zh"
    out = [lang]
    for p in rest:
        if len(p) == 4 and p.isalpha():
            out.append(p.title())
        elif (len(p) == 2 and p.isalpha()) or (len(p) == 3 and p.isdigit()):
            out.append(p.upper())
        else:
            out.append(p)
    return "-".join(out)


def lang_from_lproj(dirname: str) -> str:
    """``zh-Hans.lproj`` -> ``zh-Hans`` (accepts a bare directory name or a path component)."""
    name = dirname.rstrip("/").rsplit("/", 1)[-1]
    if name.lower().endswith(".lproj"):
        name = name[:-6]
    return normalize_lang(name)


def lang_rank(lang: str) -> Tuple[int, str]:
    """Sort key giving the project-name language priority: zh-Hans, zh, zh-Hant, en, en-*, Base, others."""
    if lang == "zh-Hans":
        return (0, lang)
    if lang == "zh":
        return (1, lang)
    if lang == "zh-Hant":
        return (2, lang)
    if lang == "en":
        return (3, lang)
    if lang.startswith("en-"):
        return (4, lang)
    if lang == "Base":
        return (5, lang)
    return (10, lang)


# --- decoding ---------------------------------------------------------------------------------
def decode_strings_bytes(data: bytes) -> str:
    """Decode a ``.strings`` payload: BOM-driven, then NUL-pattern sniffing, then UTF-8 (lossy)."""
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le", errors="replace")
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16-be", errors="replace")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")
    head = data[:512]
    if len(head) >= 4:
        pairs = len(head) // 2
        odd_nul = sum(1 for i in range(1, pairs * 2, 2) if head[i] == 0)
        even_nul = sum(1 for i in range(0, pairs * 2, 2) if head[i] == 0)
        if odd_nul * 10 >= pairs * 4 and even_nul * 10 < pairs:
            return data.decode("utf-16-le", errors="replace")
        if even_nul * 10 >= pairs * 4 and odd_nul * 10 < pairs:
            return data.decode("utf-16-be", errors="replace")
    return data.decode("utf-8", errors="replace")


# --- text parser ------------------------------------------------------------------------------
def _skip_ws(s: str, i: int) -> int:
    n = len(s)
    while i < n:
        ch = s[i]
        if ch in " \t\r\n﻿\x00":
            i += 1
        elif s.startswith("/*", i):
            end = s.find("*/", i + 2)
            i = n if end < 0 else end + 2
        elif s.startswith("//", i):
            end = s.find("\n", i + 2)
            i = n if end < 0 else end + 1
        else:
            break
    return i


_SIMPLE_ESC = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "f": "\f", "v": "\v",
               '"': '"', "'": "'", "\\": "\\"}
_HEX4 = re.compile(r"[0-9a-fA-F]{1,4}")


def _read_quoted(s: str, i: int) -> Tuple[str, int]:
    """``s[i]`` is the opening quote. Returns (decoded text, index after closing quote or end)."""
    n = len(s)
    quote = s[i]
    i += 1
    out: List[str] = []
    pending_hi: Optional[int] = None

    def flush_hi() -> None:
        nonlocal pending_hi
        if pending_hi is not None:
            out.append("�")
            pending_hi = None

    while i < n:
        ch = s[i]
        if ch == quote:
            flush_hi()
            return "".join(out), i + 1
        if ch != "\\":
            flush_hi()
            out.append(ch)
            i += 1
            continue
        i += 1
        if i >= n:
            break
        esc = s[i]
        if esc in "Uu":
            m = _HEX4.match(s, i + 1)
            if not m:
                flush_hi()
                out.append(esc)
                i += 1
                continue
            cp = int(m.group(0), 16)
            i = m.end()
            if 0xD800 <= cp < 0xDC00:
                flush_hi()
                pending_hi = cp
            elif 0xDC00 <= cp < 0xE000 and pending_hi is not None:
                out.append(chr(0x10000 + ((pending_hi - 0xD800) << 10) + (cp - 0xDC00)))
                pending_hi = None
            else:
                flush_hi()
                out.append("�" if 0xD800 <= cp < 0xE000 else chr(cp))
            continue
        flush_hi()
        if esc in "01234567":
            j = i
            while j < n and j < i + 3 and s[j] in "01234567":
                j += 1
            out.append(chr(int(s[i:j], 8)))
            i = j
        else:
            out.append(_SIMPLE_ESC.get(esc, esc))
            i += 1
    flush_hi()
    return "".join(out), n


def _read_token(s: str, i: int) -> Tuple[Optional[str], int]:
    """Quoted or unquoted string at ``i``; ``(None, i)`` if the next char cannot start a string."""
    if i >= len(s):
        return None, i
    if s[i] in "\"'":
        return _read_quoted(s, i)
    j = i
    while j < len(s) and s[j] not in _UNQUOTED_STOP:
        j += 1
    if j == i:
        return None, i
    return s[i:j], j


def _skip_value(s: str, i: int) -> int:
    """Skip a ``{...}`` / ``(...)`` value (strings and comments aware); returns the index after it."""
    n = len(s)
    depth = 0
    while i < n:
        i = _skip_ws(s, i)
        if i >= n:
            break
        ch = s[i]
        if ch in "\"'":
            _, i = _read_quoted(s, i)
            continue
        if ch in "{(":
            depth += 1
        elif ch in "})":
            depth -= 1
            if depth <= 0:
                return i + 1
        i += 1
    return n


def _resync(s: str, i: int) -> int:
    """Move past the next ``;`` (outside quotes) after a syntax error."""
    n = len(s)
    while i < n:
        ch = s[i]
        if ch in "\"'":
            _, i = _read_quoted(s, i)
            continue
        i += 1
        if ch == ";":
            return i
    return n


def parse_strings_text(text: str) -> Dict[str, str]:
    """Parse OpenStep-style ``key = value;`` text. Later duplicates win; non-string values are skipped."""
    s = text
    n = len(s)
    out: Dict[str, str] = {}
    i = _skip_ws(s, 0)
    if i < n and s[i] == "{":     # old-style dictionary wrapper
        i += 1
    guard = 0
    while i < n and guard < 2_000_000:
        guard += 1
        i = _skip_ws(s, i)
        if i >= n or s[i] == "}":
            break
        key, j = _read_token(s, i)
        if key is None:
            i = _resync(s, i + 1 if s[i] != ";" else i)
            continue
        j = _skip_ws(s, j)
        if j < n and s[j] == ";":                  # ``key;`` shorthand -> value is the key
            out[key] = key
            i = j + 1
            continue
        if j >= n or s[j] != "=":
            i = _resync(s, j)
            continue
        j = _skip_ws(s, j + 1)
        if j < n and s[j] in "{(":
            i = _resync(s, _skip_value(s, j))
            continue
        val, j = _read_token(s, j)
        if val is None:
            i = _resync(s, j)
            continue
        j = _skip_ws(s, j)
        if j < n and s[j] == ";":
            j += 1
        out[key] = val
        i = j
    return out


def parse_strings_file(data: bytes) -> Dict[str, str]:
    """Parse any ``.strings`` payload into ``{key: str}``. Returns ``{}`` for hopeless input."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        return {}
    data = bytes(data)
    stripped = data.lstrip(b"\xef\xbb\xbf \t\r\n")
    if stripped.startswith(b"bplist00") or stripped.startswith(b"<?xml") or stripped.startswith(b"<plist"):
        obj = load_plist(data)
        if isinstance(obj, dict):
            return {str(k): v for k, v in obj.items() if isinstance(v, str)}
        return {}
    try:
        return parse_strings_text(decode_strings_bytes(data))
    except Exception:  # noqa: BLE001 - parser must never raise
        log.debug("strings parse failed", exc_info=True)
        return {}
