"""Resource hot-update: Addressables / YooAsset / custom manifests, catalogs and CDN host names.

Evidence comes from files (``aa/settings.json``, catalogs, version / filelist / manifest files under
``Data/``) and, secondarily, from URL literals in ``global-metadata.dat`` (string literals live outside the
identifier pool).  Only the *domain* of a URL is ever reported -- never a path, query, port, user-info or
token -- de-duplicated and limited to 20.  Hosts from metadata literals are kept only when they look like
content-delivery hosts or also occur in a manifest/config file, because game binaries embed many
unrelated URLs (SDKs, schemas, licences).

Facts used (observed in a real Addressables IPA, 2026-10-04): ``Data/Raw/aa/settings.json`` carries
``m_AddressablesVersion``, ``m_CatalogLocations`` and ``m_DisableCatalogUpdateOnStart``; Unity BuildPipeline
writes ``<bundle>.manifest`` YAML files starting with ``ManifestFileVersion:``; the YooAsset binary manifest
starts with the magic constant ``0x594F4F`` (tuyoogame/YooAsset PackageManifestConsts.cs; the on-disk
byte order is assumed little-endian -- UNVERIFIED).
"""
from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any, BinaryIO, Dict, Iterable, List, Optional, Set, Tuple

__all__ = ["analyze", "extract_hosts", "scan_metadata_hosts", "is_noise_host"]

MAX_HOSTS = 20
_MAX_READ = 2 * 1024 * 1024
_MAX_CONFIG_FILES = 60
_URL = re.compile(r"https?://(?:[^/\s\"'<>@:]*(?::[^/\s\"'<>@]*)?@)?([A-Za-z0-9](?:(?!https?:)[A-Za-z0-9.-]){0,251})", re.IGNORECASE)
_URL_B = re.compile(rb"https?://(?:[^/\s\"'<>@:\x00-\x1f\x7f-\xff]*(?::[^/\s\"'<>@\x00-\x1f\x7f-\xff]*)?@)?"
                    rb"([A-Za-z0-9](?:(?!https?:)[A-Za-z0-9.-]){0,120})", re.IGNORECASE)
_NOISE = re.compile(
    r"(?:^|\.)(?:w3\.org|schemas\.microsoft\.com|microsoft\.com|openxmlformats\.org|xmlsoap\.org|apple\.com|"
    r"unity3d\.com|unity\.com|google\.com|googleapis\.com|gstatic\.com|googleusercontent\.com|facebook\.com|"
    r"github\.com|example\.(?:com|org)|mozilla\.org|xamarin\.com|ecma-international\.org|iana\.org|nuget\.org|"
    r"adobe\.com|purl\.org|relaxng\.org|dotnet\.microsoft\.com|mono-project\.com|gnu\.org|apache\.org|"
    r"unicode\.org|ietf\.org|mathworks\.com|oracle\.com|sun\.com|openssl\.org|zlib\.net|json\.org|"
    r"playfab\.com|firebaseio\.com|crashlytics\.com|doubleclick\.net|admob\.com)$", re.IGNORECASE)
_CDN_LABEL = re.compile(
    r"^(?:\w*cdn\w*|oss\w*|static\w*|res(?:ource)?s?\w*|assets?\w*|patch\w*|update\w*|download\w*|dl\d*|hotfix\w*|"
    r"bundles?\w*|files?\d*|s3|cloudfront|akamai\w*|qiniu\w*|aliyuncs|myqcloud|bcebos|volces|ksyun|r2|fastly|"
    r"edgekey|cos|storage\w*)$", re.IGNORECASE)
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_TLD = re.compile(r"\.[a-z]{2,24}$", re.IGNORECASE)

_CONFIG_RE = re.compile(
    r"(?:^|/)(?:version|filelist|base_manifest|resource_?list|version_?list|patch_?list|update_?list|"
    r"[A-Za-z0-9._-]*manifest|[A-Za-z0-9._-]*config)[A-Za-z0-9._-]*\.(?:txt|json|bytes|xml|csv)$", re.IGNORECASE)


def looks_like_cdn(host: str) -> bool:
    """True if a label of ``host`` is a content-delivery / static-resource style name (token based, not substring)."""
    return any(_CDN_LABEL.match(lbl) for lbl in host.split("."))


def _clean_host(host: str) -> str:
    """Lower-case, strip dots and cut at a glued-on following URL (string literals are stored back to back)."""
    h = host.lower().rstrip(".")
    cut = h.find("http")
    return h[:cut].rstrip(".") if cut > 0 else h


def is_noise_host(host: str) -> bool:
    h = host.lower().strip(".")
    return (not h or "." not in h or _IPV4.match(h) is not None or not _TLD.search(h) or _NOISE.search(h) is not None
            or h.startswith("localhost"))


def extract_hosts(text: str) -> List[str]:
    """Distinct lower-case host names of the ``http(s)://`` URLs in ``text`` (domain only)."""
    out: List[str] = []
    for m in _URL.finditer(text):
        h = _clean_host(m.group(1))
        if h not in out and not is_noise_host(h):
            out.append(h)
    return out


def _hosts_from_bytes(data: bytes) -> List[str]:
    found: List[str] = []
    for m in _URL_B.finditer(data):
        h = _clean_host(m.group(1).decode("ascii", "ignore"))
        if h not in found and not is_noise_host(h):
            found.append(h)
    return found


def scan_metadata_hosts(fobj: BinaryIO, size: int, *, chunk: int = 4 * 1024 * 1024, limit: int = 60) -> List[str]:
    """URL host names found anywhere in the metadata file (string literals are stored as plain UTF-8)."""
    found: List[str] = []
    pos = 0
    carry = b""
    while pos < size and len(found) < limit:
        fobj.seek(pos)
        buf = fobj.read(min(chunk, size - pos))
        if not buf:
            break
        pos += len(buf)
        data = carry + buf
        for h in _hosts_from_bytes(data):
            if h not in found:
                found.append(h)
        carry = data[-300:]
    return found


def _read(src: Any, path: str, n: int = _MAX_READ) -> bytes:
    try:
        return src.read_head(path, n)
    except (KeyError, OSError, ValueError):
        return b""


def _json(data: bytes) -> Any:
    try:
        return json.loads(data.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError):
        return None


def _catalog_version(name: str) -> Optional[str]:
    m = re.search(r"catalog_([A-Za-z0-9._-]+?)\.(?:json|bin|hash)$", name, re.IGNORECASE)
    return m.group(1) if m else None


def analyze(src: Any, file_rows: Iterable[Dict[str, Any]], rel_fn: Any, *, frameworks: List[Dict[str, Any]],
            metadata_hosts: Iterable[str] = ()) -> Dict[str, Any]:
    """Build the contract's ``resource_update`` block."""
    manifests: List[Dict[str, Any]] = []
    catalogs: List[Dict[str, Any]] = []
    host_src: Dict[str, Set[str]] = {}
    dirs: Counter = Counter()
    unity_manifest_count = 0
    read_count = 0
    addressables_version: Optional[str] = None
    notes: List[str] = []

    def add_hosts(hosts: Iterable[str], source: str) -> None:
        for h in hosts:
            host_src.setdefault(h, set()).add(source)

    for row in sorted((r for r in file_rows if isinstance(r.get("path"), str) and not r["path"].endswith("/")),
                      key=lambda r: r["path"]):
        path = row["path"]
        rel = rel_fn(path)
        if rel is None:
            continue
        low = rel.lower()
        size = int(row.get("size") or 0)
        if re.search(r"\.(?:bundle|ab|unity3d|b)$", low) and "/data/" in "/" + low:
            parts = rel.split("/")
            dirs["/".join(parts[:-1])] += 1
        if low.endswith(".manifest") and "/data/" in "/" + low:
            unity_manifest_count += 1
            continue
        if low.endswith(("/aa/settings.json", "aa/settings.json")) and size <= _MAX_READ:
            doc = _json(_read(src, path))
            rec: Dict[str, Any] = {"path": path, "kind": "addressables_settings", "size": size}
            if isinstance(doc, dict):
                addressables_version = doc.get("m_AddressablesVersion") or addressables_version
                rec["addressables_version"] = doc.get("m_AddressablesVersion")
                rec["build_target"] = doc.get("m_buildTarget")
                rec["catalog_update_on_start_disabled"] = doc.get("m_DisableCatalogUpdateOnStart")
                rec["local_catalog_in_bundle"] = doc.get("m_IsLocalCatalogInBundle")
                add_hosts(extract_hosts(json.dumps(doc)), "aa/settings.json")
            manifests.append(rec)
            continue
        if re.search(r"(?:^|/)catalog[^/]*\.(?:json|bin|hash)$", low):
            ext = low.rsplit(".", 1)[-1]
            catalogs.append({"path": path, "format": ext, "size": size,
                             "kind": "remote_copy" if "remote" in low else "local",
                             "version": _catalog_version(rel.rsplit("/", 1)[-1])})
            if ext in ("json", "bin") and size <= 8 * 1024 * 1024 and read_count < _MAX_CONFIG_FILES:
                read_count += 1
                data = _read(src, path, 8 * 1024 * 1024)
                add_hosts(_hosts_from_bytes(data), os_basename(path))
                add_hosts(_hosts_from_bytes(data.replace(b"\x00", b"")), os_basename(path))   # UTF-16LE strings
            continue
        if "/data/" in "/" + low and _CONFIG_RE.search(low) and size <= _MAX_READ and read_count < _MAX_CONFIG_FILES:
            read_count += 1
            data = _read(src, path)
            rec = _manifest_record(path, size, data)
            add_hosts(_hosts_from_bytes(data), os_basename(path))
            if len(manifests) < 40 and (rec["kind"] not in ("json", "unknown") or re.search(
                    r"manifest|filelist|version|list", os_basename(path), re.IGNORECASE)):
                manifests.append(rec)
            continue

    meta_hosts = list(metadata_hosts)
    for h in meta_hosts:
        if h in host_src or looks_like_cdn(h):
            host_src.setdefault(h, set()).add("metadata")
    other_literal_hosts = sum(1 for h in meta_hosts if h not in host_src)
    hosts = sorted(host_src)[:MAX_HOSTS]
    layout = ["%d bundle file(s) in %s" % (n, d) for d, n in dirs.most_common(6)]
    if unity_manifest_count:
        layout.append("%d Unity BuildPipeline .manifest file(s)" % unity_manifest_count)
    if any("remote" in d.lower() for d in dirs):
        layout.append("a 'remote' directory of bundles is packaged inside the app (pre-seeded remote content)")
    fw_resource = [f for f in frameworks if f.get("kind") == "resource"]
    return {
        "frameworks": [{"id": f["id"], "name": f["name"], "confidence": f["confidence"],
                        "version_hint": f.get("version_hint")} for f in fw_resource],
        "catalogs": catalogs[:20],
        "manifests": manifests[:40],
        "hosts": hosts,
        "hosts_sources": {h: sorted(host_src[h]) for h in hosts},
        "other_literal_hosts_count": other_literal_hosts,
        "addressables_version": addressables_version,
        "bundle_dirs": [{"dir": d, "count": n} for d, n in dirs.most_common(10)],
        "layout_hints": layout,
        "notes": notes,
    }


def os_basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _manifest_record(path: str, size: int, data: bytes) -> Dict[str, Any]:
    name = os_basename(path)
    rec: Dict[str, Any] = {"path": path, "size": size, "kind": "unknown"}
    doc = _json(data)
    if isinstance(doc, dict):
        files = doc.get("files")
        rec["kind"] = "filelist_json" if isinstance(files, list) else "json"
        if isinstance(doc.get("version"), (str, int)):
            rec["version"] = str(doc["version"])
        if isinstance(files, list):
            rec["entries"] = len(files)
        return rec
    if data[:3] == b"OOY" or data[:4] == b"\x4f\x4f\x59\x00":
        rec["kind"] = "yoo_manifest"
        return rec
    text = data[:4096].decode("utf-8", "ignore")
    if text.startswith("ManifestFileVersion:"):
        rec["kind"] = "unity_build_manifest"
    elif text and all(c.isprintable() or c in "\r\n\t" for c in text):
        lines = [ln for ln in data.decode("utf-8", "ignore").splitlines() if ln.strip()]
        if lines and sum(1 for ln in lines if re.search(r"\.(bundle|ab|unity3d|b|json|bin|hash)$", ln.strip())) >= len(lines) * 0.5:
            rec["kind"] = "text_list"
            rec["entries"] = len(lines)
    if name.lower().startswith("version") and rec["kind"] == "unknown":
        rec["kind"] = "version_file"
    return rec
