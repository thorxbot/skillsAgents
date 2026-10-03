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

__all__ = ["parse_code_resources", "verify_code_resources", "compile_rules", "rule_expects",
           "DEFAULT_MAX_BYTES", "DEFAULT_MAX_SECONDS", "MAX_EXAMPLES"]

DEFAULT_MAX_BYTES = 2 * 1024 ** 3
DEFAULT_MAX_SECONDS = 60.0
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
def compile_rules(rules: Any) -> List[Tuple[Pattern[str], float, bool]]:
    """``[(regex, weight, omit)]`` from a ``rules`` / ``rules2`` dict; invalid regexes are skipped."""
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
        try:
            out.append((re.compile(pat), weight, omit))
        except re.error:
            log.debug("skipping invalid CodeResources rule %r", pat)
    return out


def rule_expects(rules: List[Tuple[Pattern[str], float, bool]], rel: str) -> bool:
    """Would the seal cover ``rel``? Highest-weight matching rule decides; ``omit`` -> not covered.

    UNVERIFIED: tie-breaking between equal weights and case sensitivity of the regexes are not
    documented by Apple; ties are resolved towards "covered" and matching is case-sensitive.
    """
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
                          max_seconds: float = DEFAULT_MAX_SECONDS) -> Dict[str, Any]:
    """Compare the seal in ``plist`` against the archive content.

    Returns ``{checked, missing, modified, extra, examples[{kind,path}], details{...}}``;
    ``details.truncated`` is true when the byte / time budget stopped hashing early.
    """
    table_name = "files2" if isinstance(plist.get("files2"), dict) and plist.get("files2") else "files"
    table = plist.get(table_name) if isinstance(plist.get(table_name), dict) else {}
    rules = compile_rules(plist.get("rules2") if plist.get("rules2") else plist.get("rules"))

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
        "details": {
            "table": table_name,
            "entries": len(table),
            "skipped": skipped,
            "unsupported_digest": unsupported,
            "unchecked_budget": unchecked_budget,
            "truncated": truncated,
            "bytes_hashed": bytes_hashed,
            "nested_bundles": len(nested_roots),
        },
    }
