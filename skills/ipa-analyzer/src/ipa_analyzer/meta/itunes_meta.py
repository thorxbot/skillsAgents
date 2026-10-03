"""``iTunesMetadata.plist`` extraction with purchaser-information redaction.

Only an allow-list of store-listing fields is copied. Purchaser fields (Apple ID, name, DSID, purchase
date, ...) are replaced by ``"<redacted>"`` when redaction is on and kept verbatim otherwise. Unknown
keys are never copied (only their names are listed in ``extra.other_keys``).
"""
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Tuple

from ..util.plist_utils import to_jsonable_plist
from .infoplist import as_str, iso_utc

__all__ = ["REDACTED", "SENSITIVE_KEYS", "is_sensitive_key", "parse_itunes_metadata"]

REDACTED = "<redacted>"

# Normalised (lowercase, '-' and '_' removed) names of purchaser-related keys.
# Verified against real App Store iTunesMetadata.plist key names: appleId, com.apple.iTunesStore.downloadInfo
# {accountInfo{AccountStoreFront, AppleID, DSPersonID, DownloaderID, FamilyID, PurchaserID}, purchaseDate},
# purchaseDate, storeCohort. UNVERIFIED: userName / dsid / email variants (seen in other tool outputs).
SENSITIVE_KEYS = frozenset({
    "appleid", "username", "dspersonid", "dsid", "familyid", "purchaserid", "downloaderid",
    "accountstorefront", "accountinfo", "purchasedate", "com.apple.itunesstore.downloadinfo", "downloadinfo",
    "storecohort", "firstname", "lastname", "fullname", "email", "emailaddress", "receipt", "receiptdata",
})

# allow-list: output key -> candidate plist keys (first present wins)
_FIELDS: Tuple[Tuple[str, Tuple[str, ...], str], ...] = (
    ("item_id", ("itemId",), "scalar"),
    ("item_name", ("itemName", "playlistName"), "str"),
    ("artist_name", ("artistName",), "str"),
    ("artist_id", ("artistId",), "scalar"),
    ("genre", ("genre",), "str"),
    ("genre_id", ("genreId",), "scalar"),
    ("genres", ("genres",), "json"),
    ("subgenres", ("subgenres",), "json"),
    ("bundle_display_name", ("bundleDisplayName",), "str"),
    ("software_version_bundle_id", ("softwareVersionBundleId",), "str"),
    ("release_date", ("releaseDate",), "date"),
    ("bundle_version_external_id", ("bundleVersionExternalIdentifier", "softwareVersionExternalIdentifier"),
     "scalar"),
    ("bundle_short_version", ("bundleShortVersionString",), "str"),
    ("bundle_version", ("bundleVersion",), "str"),
    ("kind", ("kind",), "str"),
    ("copyright", ("copyright",), "str"),
    ("game_center_enabled", ("gameCenterEnabled",), "bool"),
    ("vendor_id", ("vendorId",), "scalar"),
)


def _norm(key: Any) -> str:
    return str(key).lower().replace("-", "").replace("_", "")


def is_sensitive_key(key: Any) -> bool:
    k = str(key).lower()
    return k in SENSITIVE_KEYS or _norm(key) in SENSITIVE_KEYS


def _scan_sensitive(obj: Any, prefix: str, found: List[str], depth: int = 0) -> None:
    """Collect dotted key paths of every sensitive key, at any depth (names only, never values)."""
    if depth > 8:
        return
    if isinstance(obj, dict):
        for k in obj:
            path = prefix + str(k)
            if is_sensitive_key(k):
                found.append(path)
            _scan_sensitive(obj[k], path + ".", found, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _scan_sensitive(v, prefix, found, depth + 1)


def _strip_sensitive(obj: Any, depth: int = 0) -> Any:
    """Copy of ``obj`` (JSON-friendly) without any sensitive key (used for allow-listed nested values)."""
    if depth > 8:
        return None
    if isinstance(obj, dict):
        return {str(k): _strip_sensitive(v, depth + 1) for k, v in obj.items() if not is_sensitive_key(k)}
    if isinstance(obj, (list, tuple)):
        return [_strip_sensitive(v, depth + 1) for v in obj]
    return to_jsonable_plist(obj)


def parse_itunes_metadata(plist: Mapping[str, Any], redact: bool = True) -> Tuple[Dict[str, Any], List[str]]:
    """Return ``(itunes_dict, redacted_key_paths)``.

    ``redacted_key_paths`` is non-empty only when ``redact`` is true and something was replaced; it
    contains key *names* (dotted for nested ones), never values.
    """
    out: Dict[str, Any] = {}
    for name, candidates, kind in _FIELDS:
        for key in candidates:
            if key not in plist:
                continue
            v = plist[key]
            if kind == "str":
                val: Any = as_str(v)
            elif kind == "date":
                val = iso_utc(v)
            elif kind == "bool":
                val = v if isinstance(v, bool) else None
            elif kind == "scalar":
                val = v if isinstance(v, (int, str)) and not isinstance(v, bool) else None
            else:
                val = _strip_sensitive(v)
            if val is not None:
                out[name] = val
                break
    if "item_id" in out and isinstance(out["item_id"], str):
        out["item_id"] = out["item_id"].strip()

    paths: List[str] = []
    _scan_sensitive(dict(plist), "", paths)
    top_sensitive = sorted(str(k) for k in plist if is_sensitive_key(k))
    for key in top_sensitive:
        out[key] = REDACTED if redact else to_jsonable_plist(plist[key])
    known = {c for _, cands, _ in _FIELDS for c in cands}
    other = sorted(str(k) for k in plist if str(k) not in known and not is_sensitive_key(k))
    out["extra"] = {"other_keys": other[:100]}
    redacted = sorted(set(paths)) if redact else []
    return out, redacted
