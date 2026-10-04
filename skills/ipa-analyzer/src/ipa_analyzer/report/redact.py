"""Last-line-of-defence redaction of personal data in the final report.

Producers (meta) already blank purchaser fields; this pass scans every string of the finished report
(and the rendered Markdown / HTML text) for: e-mail addresses, UDIDs (new ``XXXXXXXX-XXXXXXXXXXXXXXXX``
anywhere; legacy 40 hex only under device-identifier keys / wording, never under cdhash / sha1 / digest
keys), user names inside home-directory paths (only at the start of a path), and values stored under
Apple-ID-like keys. Placeholders are plain ASCII and contain no ``<``/``>`` so they survive Markdown.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

__all__ = ["RedactionStats", "redact_text", "redact_obj", "redact_report", "SENSITIVE_KEYS", "PLACEHOLDERS"]

PLACEHOLDERS = {
    "email": "[REDACTED-EMAIL]",
    "udid": "[REDACTED-UDID]",
    "value": "[REDACTED]",
    "user": "[user]",
}

# Normalised (lower-case, ``-``/``_``/space removed) key names whose *values* are always blanked.
# Source: docs/02-ARCHITECTURE.md section 6 (apple-id / userName / DSPersonID / purchaseDate / receipt).
SENSITIVE_KEYS = frozenset({
    "appleid", "applid", "username", "dspersonid", "dsid", "purchasedate", "originalpurchasedate", "receipt",
    "accountinfo", "appleidaccount", "buyername", "purchaser",
})

# A leading "@2x" style asset suffix (icon@2x.png) must not look like an address, and neither must an
# asset name whose "domain" ends in a resource extension (btn@ipad.png).
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@(?!\d+[xX]\b)[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.([A-Za-z]{2,})")
_NOT_A_TLD = frozenset({
    "png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "icns", "svg", "tga", "dds", "ktx", "pvr", "astc", "heic", "tif",
    "tiff", "pdf", "plist", "json", "xml", "strings", "nib", "car", "mp3", "mp4", "m4a", "wav", "ogg", "caf", "aac",
    "ttf", "otf", "js", "css", "html", "txt", "dat", "bin", "pak", "bundle", "lua", "atlas", "fnt", "mom", "xib",
    "storyboardc", "lproj", "dylib", "framework", "ccz",
})
# 40 hex digits are only a legacy UDID in device-identity context; the same shape is also a SHA-1 / cdhash.
_UDID_LEGACY_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])")
_UDID_NEW_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}(?![0-9A-Fa-f])")
_DEVICE_WORD_RE = re.compile(r"udid|devices?|provisioned|设备", re.IGNORECASE)
_HASH_WORD_RE = re.compile(r"cdhash|sha-?1|sha-?256|sha-?512|digest|hash|checksum|fingerprint|thumbprint|commit|哈希|摘要",
                           re.IGNORECASE)
_CONTEXT_WINDOW = 40
# Home directories: only at the start of a path (the previous character is not part of a path), so
# ``res/home/btn.png`` and ``https://example.com/home/page`` stay untouched.
_HOME_POSIX_RE = re.compile(
    r"(?:(?<![A-Za-z0-9_.~%@+:\-/\\])|(?<=file://))(/(?:Users|home)/)([^/\\\s\"'<>|:*?]+)"
    r"(?=[/\\\s\"'<>|:*?,;)\]]|$)")
# Windows: user names may contain spaces, so the name runs to the next separator (or the end of the value).
_WIN_NAME = r"(\[user\]|[^\\/\"'<>|:*?\r\n\t,;)\]\s](?:[^\\/\"'<>|:*?\r\n\t,;)\]]*[^\\/\"'<>|:*?\r\n\t,;)\]\s])?)"
_HOME_WIN_RE = re.compile(r"((?<![A-Za-z])[A-Za-z]:[\\/]+Users[\\/]+)" + _WIN_NAME, re.IGNORECASE)
_HOME_UNC_RE = re.compile(r"((?<![\\/\w])[\\/]{2}(?:\?[\\/]UNC[\\/])?[^\\/\s\"'<>|:*?]+[\\/]+[^\\/\s\"'<>|:*?]+[\\/]+Users[\\/]+)"
                          + _WIN_NAME, re.IGNORECASE)
_KEEP_USER_NAMES = frozenset({"shared", "public", "default", "guest", "all users", "[user]", "<user>", "user"})
_HINT_DEVICE, _HINT_HASH = "device", "hash"


@dataclass
class RedactionStats:
    counts: Dict[str, int] = field(default_factory=dict)

    def hit(self, name: str, n: int = 1) -> None:
        self.counts[name] = self.counts.get(name, 0) + n

    @property
    def fields(self) -> List[str]:
        return sorted(self.counts)

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def merge(self, other: "RedactionStats") -> None:
        for k, v in other.counts.items():
            self.hit(k, v)


def _norm_key(key: str) -> str:
    return re.sub(r"[\s_\-]+", "", key).lower()


def key_hint(key: str) -> str:
    """Context a dict key gives its value: ``"device"`` (device identifiers), ``"hash"`` (digests) or ``""``."""
    n = _norm_key(key)
    if "udid" in n or "device" in n or "provisioned" in n:
        return _HINT_DEVICE
    if any(w in n for w in ("cdhash", "sha1", "sha256", "sha512", "digest", "hash", "checksum", "fingerprint",
                            "thumbprint", "commit")):
        return _HINT_HASH
    return ""


def _legacy_udid_context(text: str, start: int) -> bool:
    """Do the characters just before a 40-hex run talk about a device (and not about a hash)?"""
    window = text[max(0, start - _CONTEXT_WINDOW):start]
    dev = [m.start() for m in _DEVICE_WORD_RE.finditer(window)]
    if not dev:
        return False
    hsh = [m.start() for m in _HASH_WORD_RE.finditer(window)]
    return not hsh or max(dev) > max(hsh)


def redact_text(text: str, stats: Optional[RedactionStats] = None, *, hint: str = "") -> str:
    """Return ``text`` with e-mails, UDIDs and home-directory user names replaced.

    ``hint`` is the context of the value (see ``key_hint``). A bare 40-hex string is redacted as a legacy
    UDID only for ``hint == "device"`` or when the preceding words mention a device / UDID; under a hash
    hint (cdhash, sha1 ...) it is never touched.
    """
    if not text:
        return text
    st = stats if stats is not None else RedactionStats()
    out = text

    def _email(m: "re.Match[str]") -> str:
        if m.group(1).lower() in _NOT_A_TLD:
            return m.group(0)
        st.hit("email")
        return PLACEHOLDERS["email"]

    def _legacy(m: "re.Match[str]") -> str:
        if hint == _HINT_HASH or not (hint == _HINT_DEVICE or _legacy_udid_context(m.string, m.start())):
            return m.group(0)
        st.hit("udid")
        return PLACEHOLDERS["udid"]

    def _home(m: "re.Match[str]") -> str:
        if m.group(2).lower() in _KEEP_USER_NAMES:
            return m.group(0)
        st.hit("home_path")
        return m.group(1) + PLACEHOLDERS["user"]

    out = _EMAIL_RE.sub(_email, out)
    new, n = _UDID_NEW_RE.subn(PLACEHOLDERS["udid"], out)
    if n:
        st.hit("udid", n)
    out = _UDID_LEGACY_RE.sub(_legacy, new)
    out = _HOME_UNC_RE.sub(_home, out)
    out = _HOME_POSIX_RE.sub(_home, out)
    out = _HOME_WIN_RE.sub(_home, out)
    return out


def redact_obj(obj: Any, stats: RedactionStats, hint: str = "") -> Any:
    """Deep-copy ``obj`` (JSON-native types) with all strings redacted and sensitive-key values blanked.

    ``hint`` is inherited from the enclosing dict key (device-identifier keys redact bare 40-hex strings,
    digest keys such as ``cdhash`` / ``sha1`` never do).
    """
    if isinstance(obj, str):
        return redact_text(obj, stats, hint=hint)
    if isinstance(obj, list):
        return [redact_obj(v, stats, hint) for v in obj]
    if isinstance(obj, dict):
        out: Dict[Any, Any] = {}
        for k, v in obj.items():
            if isinstance(k, str) and _norm_key(k) in SENSITIVE_KEYS and v not in (None, "", [], {}):
                if isinstance(v, str) and v.strip().lower() in ("<redacted>", PLACEHOLDERS["value"].lower()):
                    out[k] = v
                else:
                    out[k] = PLACEHOLDERS["value"]
                    stats.hit("key:" + _norm_key(k))
                continue
            out[k] = redact_obj(v, stats, (key_hint(k) if isinstance(k, str) else "") or hint)
        return out
    return obj


def redact_report(report: Dict[str, Any], *, enabled: bool = True, producer_fields: Iterable[str] = (),
                  extras: Optional[Dict[str, Any]] = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Redact a report dict. Returns ``(new_report, redaction)`` where ``redaction`` is the value for the
    ``redaction`` key: ``{"applied", "fields": [names], "counts": {name: n}}``.

    With ``enabled=False`` the report is returned unchanged (``applied`` false). ``producer_fields``
    lists field names that upstream stages (meta) reported as redacted; they are merged in. ``extras``
    (side files such as ``details/*.json``) is redacted in place and counted in the same statistics.
    """
    prod = sorted({str(x) for x in producer_fields})
    if not enabled:
        return report, {"applied": False, "fields": prod, "counts": {}}
    stats = RedactionStats()
    scrubbed = {k: (redact_obj(v, stats, key_hint(k) if isinstance(k, str) else "") if k != "redaction" else v)
                for k, v in report.items()}
    if extras is not None:
        for name in list(extras):
            extras[name] = redact_obj(extras[name], stats)
    fields = sorted(set(stats.fields) | set(prod))
    info: Dict[str, Any] = {"applied": True, "fields": fields, "counts": dict(sorted(stats.counts.items()))}
    scrubbed["redaction"] = info
    return scrubbed, info
