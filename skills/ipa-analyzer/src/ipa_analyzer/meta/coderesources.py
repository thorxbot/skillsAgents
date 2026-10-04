"""``_CodeSignature/CodeResources`` seal verification (P1 ``meta.signature_integrity``).

CodeResources is a plist with ``files`` (v1 seal) and ``files2`` (v2 seal) tables plus ``rules`` /
``rules2``. Entry shapes (checked against real macOS bundles' CodeResources, key names only):

* ``files``:  ``path -> <data SHA-1>`` or ``path -> {hash: <data>, optional: bool}``
* ``files2``: ``path -> {hash2: <data SHA-256>}`` (older toolchains also ``hash`` = SHA-1,
  optionally ``optional``), nested code ``path -> {cdhash, requirement}`` and ``symlink``.
* ``rules2``: ``regex -> true | {weight, omit, optional, nested}`` (highest matching weight wins).

Hashing is streamed and bounded by total bytes and wall-clock time; unchecked files are counted.
Passing the check does NOT prove authenticity: a re-signed package carries a fresh, consistent seal.
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
import unicodedata
from typing import Any, Dict, Iterable, List, Mapping, Optional, Pattern, Tuple

from ..ingest import ArchiveSource, EntryInfo
from ..util.plist_utils import load_plist

log = logging.getLogger(__name__)

__all__ = ["parse_code_resources", "verify_code_resources", "compile_rules", "rule_expects", "rule_risk",
           "DEFAULT_MAX_BYTES", "DEFAULT_MAX_SECONDS", "DEFAULT_RULE_SECONDS", "MAX_EXAMPLES",
           "MAX_RULE_LENGTH", "MAX_RULE_INPUT"]

DEFAULT_MAX_BYTES = 2 * 1024 ** 3
DEFAULT_MAX_SECONDS = 60.0
# Wall-clock budget for the whole "files outside the seal" rule evaluation. The regexes come from the
# (untrusted) IPA, so they are screened (``rule_risk``), run on bounded input and bounded in total time.
DEFAULT_RULE_SECONDS = 5.0
MAX_RULE_LENGTH = 200
MAX_RULE_INPUT = 256
_MAX_UNBOUNDED = 2          # more unbounded repeats than this is polynomial-time risky (n^k backtracking)
_LARGE_REPEAT = 20          # {n,m} with m above this counts as unbounded
MAX_EXAMPLES = 10
_CHUNK = 1024 * 1024

# Digest length (bytes) -> algorithm, used when the key name (hash / hash2) disagrees with the length.
_ALGO_BY_LEN = {20: "sha1", 32: "sha256", 48: "sha384", 64: "sha512"}

# Added after signing or not sealed by design; never reported as "extra".
_IGNORED_PREFIXES = ("_CodeSignature/", "SC_Info/")
_IGNORED_NAMES = ("CodeResources", ".DS_Store")


def parse_code_resources(data: bytes) -> Optional[Dict[str, Any]]:
    obj = load_plist(data)
    return obj if isinstance(obj, dict) and ("files" in obj or "files2" in obj) else None


# --- rules ------------------------------------------------------------------------------------
_BRACE_RE = re.compile(r"\{(\d*)(,?)(\d*)\}")


def _quantifier_at(pat: str, i: int) -> Tuple[Optional[str], int]:
    """Quantifier starting at ``pat[i]`` -> ``(kind, length)``; kind is ``None``, ``"bounded"`` or ``"unbounded"``."""
    if i >= len(pat):
        return None, 0
    c = pat[i]
    if c in "*+":
        kind, ln = "unbounded", 1
    elif c == "?":
        kind, ln = "bounded", 1
    elif c == "{":
        m = _BRACE_RE.match(pat, i)
        if m is None or not (m.group(1) or m.group(3)):
            return None, 0
        hi = m.group(3)
        unbounded = bool(m.group(2)) and (not hi or int(hi) > _LARGE_REPEAT)
        unbounded = unbounded or (not m.group(2) and int(m.group(1) or 0) > _LARGE_REPEAT)
        kind, ln = ("unbounded" if unbounded else "bounded"), m.end() - i
    else:
        return None, 0
    if i + ln < len(pat) and pat[i + ln] in "?+":      # lazy / possessive modifier
        ln += 1
    return kind, ln


def rule_risk(pat: str) -> Optional[str]:
    """Why ``pat`` must not be executed against attacker-chosen text, or ``None`` when it looks safe.

    A conservative scanner (no regex engine is run): rejects over-long patterns, a group holding a
    repeat or an alternation that is itself repeated without bound (``(a+)+``, ``(a|aa)*``) and more
    than ``_MAX_UNBOUNDED`` unbounded repeats. Real Apple rule sets (``^(.*/)?Info\\.plist$`` ...) pass.
    """
    if len(pat) > MAX_RULE_LENGTH:
        return "too long"
    stack: List[List[bool]] = []
    cur = [False, False]                       # [holds a repeat, holds an alternation]
    unbounded = 0
    i, n = 0, len(pat)
    while i < n:
        c = pat[i]
        if c == "\\":
            i += 2
            kind, ln = _quantifier_at(pat, i)
        elif c == "[":
            j = i + 1
            if j < n and pat[j] == "^":
                j += 1
            if j < n and pat[j] == "]":
                j += 1
            while j < n and pat[j] != "]":
                j += 2 if pat[j] == "\\" else 1
            i = j + 1
            kind, ln = _quantifier_at(pat, i)
        elif c == "(":
            i += 1
            opened = True
            if pat.startswith("?", i):
                if pat.startswith("?P<", i):
                    i = pat.find(">", i) + 1 or n
                elif pat[i + 1:i + 2] in (":", "=", "!"):
                    i += 2
                elif pat[i + 1:i + 3] in ("<=", "<!"):
                    i += 3
                else:                          # flags ``(?i)``, comments, ``(?P=name)``: not a group
                    j = pat.find(")", i)
                    i = (j + 1) if j >= 0 else n
                    opened = False
            if opened:
                stack.append(cur)
                cur = [False, False]
            continue
        elif c == ")":
            i += 1
            if not stack:
                continue
            inner, cur = cur, stack.pop()
            kind, ln = _quantifier_at(pat, i)
            if kind == "unbounded":
                if inner[0] or inner[1]:
                    return "nested quantifier"
                unbounded += 1
            cur[0] = cur[0] or inner[0] or kind is not None
            cur[1] = cur[1] or inner[1]
            i += ln
            if unbounded > _MAX_UNBOUNDED:
                return "too many unbounded repeats"
            continue
        elif c == "|":
            cur[1] = True
            i += 1
            continue
        elif c in "*+?{":
            kind, ln = _quantifier_at(pat, i)
            if kind is None:
                i += 1
                continue
            cur[0] = True
            unbounded += kind == "unbounded"
            i += ln
            if unbounded > _MAX_UNBOUNDED:
                return "too many unbounded repeats"
            continue
        else:
            i += 1
            kind, ln = _quantifier_at(pat, i)
        # an atom (escape, class, literal) followed by an optional quantifier
        if kind is not None:
            cur[0] = True
            unbounded += kind == "unbounded"
            i += ln
            if unbounded > _MAX_UNBOUNDED:
                return "too many unbounded repeats"
    return None


def compile_rules(rules: Any, rejected: Optional[List[str]] = None) -> List[Tuple[Pattern[str], float, bool]]:
    """``[(regex, weight, omit)]`` from a ``rules`` / ``rules2`` dict.

    Invalid regexes are skipped. Regexes the IPA could abuse for catastrophic backtracking (``rule_risk``)
    are never compiled; their text is appended to ``rejected`` (when given) so callers can warn and
    treat the rule set as incomplete.
    """
    out: List[Tuple[Pattern[str], float, bool]] = []
    if not isinstance(rules, dict):
        return out
    for pat in sorted(str(k) for k in rules):
        val = rules.get(pat)
        weight, omit = 1.0, False
        if isinstance(val, dict):
            w = val.get("weight")
            weight = float(w) if isinstance(w, (int, float)) and not isinstance(w, bool) else 1.0
            omit = val.get("omit") is True
        elif val is False:
            omit = True
        risk = rule_risk(pat)
        if risk is not None:
            log.debug("not evaluating CodeResources rule %r: %s", pat[:80], risk)
            if rejected is not None:
                rejected.append(pat)
            continue
        try:
            out.append((re.compile(pat), weight, omit))
        except re.error:
            log.debug("skipping invalid CodeResources rule %r", pat)
    return out


def rule_expects(rules: List[Tuple[Pattern[str], float, bool]], rel: str, *, max_input: int = MAX_RULE_INPUT) -> bool:
    """Would the seal cover ``rel``? Highest-weight matching rule decides; ``omit`` -> not covered.

    The path is truncated to ``max_input`` characters before matching (bounds regex work).

    UNVERIFIED: tie-breaking between equal weights and case sensitivity of the regexes are not
    documented by Apple; ties are resolved towards "covered" and matching is case-sensitive.
    """
    rel = rel[:max_input]
    best: Optional[Tuple[float, bool]] = None
    for rx, weight, omit in rules:
        if rx.search(rel):
            if best is None or weight > best[0] or (weight == best[0] and not omit):
                best = (weight, omit)
    return best is not None and not best[1]


# --- verification -----------------------------------------------------------------------------
def _entry_digest(value: Any) -> Tuple[Optional[bytes], Optional[str], bool, bool]:
    """-> (digest, algo, optional, skip). ``skip`` for nested code (cdhash) / symlinks / no usable digest.

    ``hash2`` is SHA-256 and ``hash`` is SHA-1 by definition; the digest length picks the algorithm so
    a mislabelled entry is still compared correctly.
    """
    optional = False
    if isinstance(value, (bytes, bytearray)):
        digest = bytes(value)
    elif isinstance(value, dict):
        optional = value.get("optional") is True
        if "symlink" in value:
            return None, None, optional, True
        if isinstance(value.get("hash2"), (bytes, bytearray)):
            digest = bytes(value["hash2"])
        elif isinstance(value.get("hash"), (bytes, bytearray)):
            digest = bytes(value["hash"])
        else:                                   # nested code carries only cdhash / requirement
            return None, None, optional, True
    else:
        return None, None, optional, True
    algo = _ALGO_BY_LEN.get(len(digest))
    return digest, algo, optional, algo is None


def _nfc(s: str) -> str:
    return unicodedata.normalize("NFC", s)


def _ancestors(rel: str) -> Iterable[str]:
    """``a/b/c`` -> ``a/b``, ``a``."""
    parts = rel.split("/")
    for i in range(len(parts) - 1, 0, -1):
        yield "/".join(parts[:i])


def verify_code_resources(source: ArchiveSource, app_root: str, plist: Mapping[str, Any],
                          entries: Iterable[EntryInfo], *, executable: Optional[str] = None,
                          max_bytes: int = DEFAULT_MAX_BYTES,
                          max_seconds: float = DEFAULT_MAX_SECONDS,
                          max_rule_seconds: float = DEFAULT_RULE_SECONDS) -> Dict[str, Any]:
    """Compare the seal in ``plist`` against the archive content.

    Returns ``{checked, missing, modified, extra, examples[{kind,path}], details{...}}``;
    ``details.truncated`` is true when the byte / time budget stopped hashing early; ``details.rules_incomplete``
    when rules had to be left unevaluated or the rule time budget ran out (the "extra" count is then a lower
    bound). ``warnings`` lists such conditions.
    """
    warnings: List[str] = []
    table_name = "files2" if isinstance(plist.get("files2"), dict) and plist.get("files2") else "files"
    table = plist.get(table_name) if isinstance(plist.get(table_name), dict) else {}
    rejected_rules: List[str] = []
    rules = compile_rules(plist.get("rules2") if plist.get("rules2") else plist.get("rules"), rejected_rules)
    if rejected_rules:
        warnings.append("CodeResources: %d rule(s) not evaluated (over-long or backtracking-prone regex)"
                        % len(rejected_rules))

    by_name: Dict[str, EntryInfo] = {}
    dir_prefixes = set()
    nested_roots = set()
    for e in entries:
        if not e.name.startswith(app_root):
            continue
        rel = e.name[len(app_root):]
        if not rel or e.is_dir:
            continue
        by_name[rel] = e
        dir_prefixes.update(_ancestors(rel))
        if rel.endswith("/_CodeSignature/CodeResources"):
            nested_roots.add(rel[:-len("/_CodeSignature/CodeResources")])
    nfc_index = {_nfc(k): k for k in by_name}

    missing: List[str] = []
    modified: List[str] = []
    checked = skipped = unsupported = unchecked_budget = 0
    bytes_hashed = 0
    truncated = False
    started = time.monotonic()

    for key in sorted(str(k) for k in table):
        digest, algo, optional, skip = _entry_digest(table.get(key))
        rel = key.rstrip("/")
        hit = by_name.get(rel) or by_name.get(nfc_index.get(_nfc(rel), ""))
        if hit is None:
            if optional:
                continue
            if skip and rel in dir_prefixes:
                skipped += 1              # nested bundle: sealed by its own signature
            else:
                missing.append(key)
            continue
        if skip or digest is None or algo is None:
            skipped += 1
            if algo is None and digest is not None:
                unsupported += 1
            continue
        if truncated or bytes_hashed + hit.size > max_bytes or time.monotonic() - started > max_seconds:
            truncated = True
            unchecked_budget += 1
            continue
        try:
            h = hashlib.new(algo)
            with source.open(hit.name) as fh:
                while True:
                    block = fh.read(_CHUNK)
                    if not block:
                        break
                    h.update(block)
        except (KeyError, OSError, ValueError, EOFError, RuntimeError) as exc:
            log.debug("cannot hash %s: %s", hit.name, exc)
            skipped += 1
            continue
        bytes_hashed += hit.size
        checked += 1
        if h.digest() != digest:
            modified.append(key)

    listed = {_nfc(str(k).rstrip("/")) for k in table}
    extra_files: List[str] = []
    rule_started = time.monotonic()
    rules_timed_out = False
    for rel in sorted(by_name):
        n = _nfc(rel)
        if n in listed:
            continue
        if rel.startswith(_IGNORED_PREFIXES) or rel.rsplit("/", 1)[-1] in _IGNORED_NAMES:
            continue
        if executable and rel == executable:
            continue
        if any(a in nested_roots or _nfc(a) in listed for a in _ancestors(rel)):
            continue                      # inside a nested bundle / a directory the seal lists
        if time.monotonic() - rule_started > max_rule_seconds:
            rules_timed_out = True
            warnings.append("CodeResources: rule evaluation stopped after %.1f s; extra-file count is partial"
                            % max_rule_seconds)
            break
        if not rule_expects(rules, rel):
            continue
        extra_files.append(rel)

    examples: List[Dict[str, str]] = []
    for kind, items in (("modified", modified), ("missing", missing), ("extra", extra_files)):
        for p in items:
            if len(examples) < MAX_EXAMPLES:
                examples.append({"kind": kind, "path": p})
    return {
        "checked": checked,
        "missing": len(missing),
        "modified": len(modified),
        "extra": len(extra_files),
        "examples": examples,
        "warnings": warnings,
        "details": {
            "table": table_name,
            "entries": len(table),
            "skipped": skipped,
            "unsupported_digest": unsupported,
            "unchecked_budget": unchecked_budget,
            "truncated": truncated,
            "bytes_hashed": bytes_hashed,
            "nested_bundles": len(nested_roots),
            "unevaluated_rules": len(rejected_rules),
            "rules_timed_out": rules_timed_out,
            "rules_incomplete": bool(rejected_rules) or rules_timed_out,
        },
    }
