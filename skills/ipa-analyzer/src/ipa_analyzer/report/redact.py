"""Last-line-of-defence redaction of personal data in the final report.

Producers (meta) already blank purchaser fields; this pass scans every string of the finished report
(and the rendered Markdown / HTML text) for: e-mail addresses, UDIDs (legacy 40 hex, new
``XXXXXXXX-XXXXXXXXXXXXXXXX``), user names inside home-directory paths, and values stored under
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

# A leading "@2x" style asset suffix (icon@2x.png) must not look like an address.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@(?!\d+[xX]\b)[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
_UDID_LEGACY_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])")
_UDID_NEW_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}(?![0-9A-Fa-f])")
_HOME_POSIX_RE = re.compile(r"(/(?:Users|home)/)([^/\\\s\"'<>|:*?]+)(?=[/\\\s\"'<>|:*?,;)\]]|$)")
_HOME_WIN_RE = re.compile(r"([A-Za-z]:[\\/]+Users[\\/]+)([^\\/\s\"'<>|:*?]+)(?=[\\/\s\"'<>|:*?,;)\]]|$)", re.IGNORECASE)
_KEEP_USER_NAMES = frozenset({"shared", "public", "default", "guest", "all users", "[user]", "<user>", "user"})


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


def redact_text(text: str, stats: Optional[RedactionStats] = None) -> str:
    """Return ``text`` with e-mails, UDIDs and home-directory user names replaced."""
    if not text:
        return text
    st = stats if stats is not None else RedactionStats()
    out = text

    def _sub(rx: "re.Pattern[str]", repl: Any, name: str, s: str) -> str:
        new, n = rx.subn(repl, s)
        if n:
            st.hit(name, n)
        return new

    out = _sub(_EMAIL_RE, PLACEHOLDERS["email"], "email", out)
    out = _sub(_UDID_NEW_RE, PLACEHOLDERS["udid"], "udid", out)
    out = _sub(_UDID_LEGACY_RE, PLACEHOLDERS["udid"], "udid", out)

    def _home(m: "re.Match[str]") -> str:
        if m.group(2).lower() in _KEEP_USER_NAMES:
            return m.group(0)
        st.hit("home_path")
        return m.group(1) + PLACEHOLDERS["user"]

    out = _HOME_POSIX_RE.sub(_home, out)
    out = _HOME_WIN_RE.sub(_home, out)
    return out


def redact_obj(obj: Any, stats: RedactionStats) -> Any:
    """Deep-copy ``obj`` (JSON-native types) with all strings redacted and sensitive-key values blanked."""
    if isinstance(obj, str):
        return redact_text(obj, stats)
    if isinstance(obj, list):
        return [redact_obj(v, stats) for v in obj]
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
            out[k] = redact_obj(v, stats)
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
    scrubbed = {k: (redact_obj(v, stats) if k != "redaction" else v) for k, v in report.items()}
    if extras is not None:
        for name in list(extras):
            extras[name] = redact_obj(extras[name], stats)
    fields = sorted(set(stats.fields) | set(prod))
    info: Dict[str, Any] = {"applied": True, "fields": fields, "counts": dict(sorted(stats.counts.items()))}
    scrubbed["redaction"] = info
    return scrubbed, info
