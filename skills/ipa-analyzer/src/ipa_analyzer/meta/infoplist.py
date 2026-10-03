"""Info.plist field extraction and project-name resolution (pure functions, tolerant of bad types)."""
from __future__ import annotations

import datetime as _dt
from typing import Any, Dict, List, Mapping, Optional

from ..util.plist_utils import load_plist, to_jsonable_plist
from .strings_file import lang_rank

__all__ = [
    "as_str", "iso_utc", "parse_info_plist", "extract_identity", "extract_devices", "extract_url_schemes",
    "extract_query_schemes", "extract_ats", "extract_background_modes", "extract_capabilities",
    "extract_sdk", "extract_scene_manifest", "extract_ns_extension", "build_name_candidates",
    "select_name", "DEVICE_FAMILIES", "TIER1_LANGS",
]

# UIDeviceFamily values. 1/2 (iPhone+iPod touch / iPad) are documented in Apple's Information Property
# List Key Reference; 3 (Apple TV) and 4 (Apple Watch) are the established values.
# UNVERIFIED: 6 (Mac Catalyst) and 7 (visionOS) are from memory.
DEVICE_FAMILIES: Dict[int, str] = {1: "iphone", 2: "ipad", 3: "tv", 4: "watch", 6: "mac", 7: "vision"}

# Languages whose localized CFBundleDisplayName outranks the plain Info.plist value (01-REQUIREMENTS F-META).
TIER1_LANGS = ("zh-Hans", "zh", "zh-Hant", "en", "Base")


def as_str(value: Any) -> Optional[str]:
    """``str``/``int``/``float`` -> stripped ``str`` (empty -> ``None``); anything else -> ``None``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        v = value.strip()
        return v or None
    if isinstance(value, (int, float)):
        return str(value)
    return None


def _str_list(value: Any) -> List[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    out: List[str] = []
    for v in value:
        s = as_str(v)
        if s is not None and s not in out:
            out.append(s)
    return out


def iso_utc(value: Any) -> Optional[str]:
    """Plist date -> ISO-8601 UTC string (``2024-01-02T03:04:05Z``); strings pass through; else ``None``."""
    if isinstance(value, _dt.datetime):
        if value.tzinfo is not None:
            value = value.astimezone(_dt.timezone.utc).replace(tzinfo=None)
        return value.replace(microsecond=0).isoformat() + "Z"
    if isinstance(value, _dt.date):
        return value.isoformat()
    return as_str(value)


def parse_info_plist(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse an Info.plist (binary or XML). ``None`` when corrupt or when the root is not a dict."""
    obj = load_plist(data)
    return obj if isinstance(obj, dict) else None


def extract_devices(info: Mapping[str, Any]) -> Dict[str, Any]:
    raw = info.get("UIDeviceFamily")
    ids: List[int] = []
    if isinstance(raw, int) and not isinstance(raw, bool):
        raw = [raw]
    if isinstance(raw, (list, tuple)):
        for v in raw:
            if isinstance(v, int) and not isinstance(v, bool) and v not in ids:
                ids.append(v)
    return {"devices": [DEVICE_FAMILIES.get(i, "family_%d" % i) for i in ids], "ids": ids}


def extract_url_schemes(info: Mapping[str, Any]) -> List[str]:
    out: List[str] = []
    types = info.get("CFBundleURLTypes")
    if isinstance(types, (list, tuple)):
        for t in types:
            if isinstance(t, dict):
                for s in _str_list(t.get("CFBundleURLSchemes")):
                    if s not in out:
                        out.append(s)
    return out


def extract_query_schemes(info: Mapping[str, Any]) -> List[str]:
    return _str_list(info.get("LSApplicationQueriesSchemes"))


def extract_background_modes(info: Mapping[str, Any]) -> List[str]:
    return _str_list(info.get("UIBackgroundModes"))


def extract_capabilities(info: Mapping[str, Any]) -> List[str]:
    """``UIRequiredDeviceCapabilities`` as a list; a dict form yields ``"cap"`` / ``"!cap"`` (must NOT have)."""
    raw = info.get("UIRequiredDeviceCapabilities")
    if isinstance(raw, dict):
        out = []
        for k in sorted(str(k) for k in raw):
            v = raw.get(k)
            out.append(k if v is True or v is None else "!" + k)
        return out
    return _str_list(raw)


def extract_ats(info: Mapping[str, Any]) -> Dict[str, Any]:
    """App Transport Security summary: ``{allows_arbitrary_loads, exception_domains, extra{...}}``."""
    ats = info.get("NSAppTransportSecurity")
    if not isinstance(ats, dict):
        return {"allows_arbitrary_loads": False, "exception_domains": [], "extra": {"present": False}}
    domains = ats.get("NSExceptionDomains")
    names: List[str] = []
    insecure: List[str] = []
    if isinstance(domains, dict):
        for dom in sorted(str(k) for k in domains):
            names.append(dom)
            cfg = domains.get(dom)
            if isinstance(cfg, dict) and (cfg.get("NSExceptionAllowsInsecureHTTPLoads") is True
                                          or cfg.get("NSTemporaryExceptionAllowsInsecureHTTPLoads") is True):
                insecure.append(dom)
    return {
        "allows_arbitrary_loads": ats.get("NSAllowsArbitraryLoads") is True,
        "exception_domains": names,
        "extra": {
            "present": True,
            "allows_arbitrary_loads_in_web_content": ats.get("NSAllowsArbitraryLoadsInWebContent") is True,
            "allows_arbitrary_loads_for_media": ats.get("NSAllowsArbitraryLoadsForMedia") is True,
            "allows_local_networking": ats.get("NSAllowsLocalNetworking") is True,
            "insecure_http_domains": insecure,
        },
    }


def extract_sdk(info: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "name": as_str(info.get("DTSDKName")),
        "platform_version": as_str(info.get("DTPlatformVersion")),
        "xcode": as_str(info.get("DTXcode")),
        "compiler": as_str(info.get("DTCompiler")),
        "extra": {k: as_str(info.get(src)) for k, src in
                  (("platform_name", "DTPlatformName"), ("sdk_build", "DTSDKBuild"),
                   ("xcode_build", "DTXcodeBuild"), ("platform_build", "DTPlatformBuild"))
                  if as_str(info.get(src)) is not None},
    }


def extract_scene_manifest(info: Mapping[str, Any]) -> Dict[str, Any]:
    man = info.get("UIApplicationSceneManifest")
    if not isinstance(man, dict):
        return {"present": False}
    roles: List[str] = []
    delegates: List[str] = []
    cfgs = man.get("UISceneConfigurations")
    if isinstance(cfgs, dict):
        for role in sorted(str(k) for k in cfgs):
            roles.append(role)
            items = cfgs.get(role)
            if isinstance(items, (list, tuple)):
                for it in items:
                    if isinstance(it, dict):
                        d = as_str(it.get("UISceneDelegateClassName"))
                        if d and d not in delegates:
                            delegates.append(d)
    return {"present": True, "supports_multiple_scenes": man.get("UIApplicationSupportsMultipleScenes") is True,
            "roles": roles, "delegate_classes": delegates}


def extract_ns_extension(info: Mapping[str, Any]) -> Dict[str, Any]:
    """``NSExtension`` (app extensions) / ``WKExtension`` (WatchKit 1/2 extensions) summary."""
    out: Dict[str, Any] = {"point": None, "principal_class": None, "main_storyboard": None}
    ext = info.get("NSExtension")
    if isinstance(ext, dict):
        out["point"] = as_str(ext.get("NSExtensionPointIdentifier"))
        out["principal_class"] = as_str(ext.get("NSExtensionPrincipalClass"))
        out["main_storyboard"] = as_str(ext.get("NSExtensionMainStoryboard"))
        attrs = ext.get("NSExtensionAttributes")
        if isinstance(attrs, dict):
            out["attributes_keys"] = sorted(str(k) for k in attrs)[:20]
    return out


def extract_identity(info: Mapping[str, Any]) -> Dict[str, Any]:
    """Identity fields except ``names`` / ``selected_name`` (see ``build_name_candidates``).

    Contract keys at the top, everything else under ``extra``.
    """
    dev = extract_devices(info)
    orient = _str_list(info.get("UISupportedInterfaceOrientations"))
    extra: Dict[str, Any] = {
        "display_name": as_str(info.get("CFBundleDisplayName")),
        "bundle_name": as_str(info.get("CFBundleName")),
        "category": as_str(info.get("LSApplicationCategoryType")),
        "development_region": as_str(info.get("CFBundleDevelopmentRegion")),
        "device_family_ids": dev["ids"],
        "supported_orientations": orient,
        "scene_manifest": extract_scene_manifest(info),
        "watch_companion_bundle_id": as_str(info.get("WKCompanionAppBundleIdentifier")),
        "package_type": as_str(info.get("CFBundlePackageType")),
        "is_watch_app": bool(info.get("WKWatchKitApp") or info.get("WKApplication")),
        "is_app_clip": isinstance(info.get("NSAppClip"), dict),
        "bundle_localizations": _str_list(info.get("CFBundleLocalizations")),
    }
    ns = extract_ns_extension(info)
    if ns["point"] or ns["principal_class"] or ns["main_storyboard"]:
        extra["ns_extension"] = ns
    return {
        "bundle_id": as_str(info.get("CFBundleIdentifier")),
        "version": as_str(info.get("CFBundleShortVersionString")),
        "build": as_str(info.get("CFBundleVersion")),
        "executable": as_str(info.get("CFBundleExecutable")),
        "min_os": as_str(info.get("MinimumOSVersion")) or as_str(info.get("LSMinimumSystemVersion")),
        "devices": dev["devices"],
        "extra": to_jsonable_plist(extra),
    }


# --- project name -----------------------------------------------------------------------------
def _usable(value: Any) -> Optional[str]:
    s = as_str(value)
    if s is None or s.startswith("$("):    # unresolved build setting such as $(PRODUCT_NAME)
        return None
    return s


def build_name_candidates(info: Optional[Mapping[str, Any]], localized: Mapping[str, Mapping[str, str]],
                          itunes_name: Optional[str], itunes_display_name: Optional[str],
                          executable: Optional[str], input_name: Optional[str]) -> List[Dict[str, str]]:
    """All project-name candidates in priority order (first = selected).

    Priority (01-REQUIREMENTS F-META, plus the lower-priority extras marked *):
      1. localized ``CFBundleDisplayName`` from ``InfoPlist.strings`` for zh-Hans, zh-Hant, en (and Base)
      2. ``Info.plist`` ``CFBundleDisplayName``
      3. ``Info.plist`` ``CFBundleName``
      4. ``iTunesMetadata.plist`` ``itemName``
      5. *``iTunesMetadata.plist`` ``bundleDisplayName``
      6. *other-language localized ``CFBundleDisplayName`` and all localized ``CFBundleName``
      7. ``CFBundleExecutable``
      8. input file name (stem)
    """
    info = info or {}
    out: List[Dict[str, str]] = []

    def add(value: Any, source: str, lang: str = "") -> None:
        v = _usable(value)
        if v is not None:
            out.append({"value": v, "source": source, "lang": lang})

    langs = sorted(localized, key=lang_rank)
    for lang in langs:
        if lang in TIER1_LANGS or lang.startswith("en-"):
            add(localized[lang].get("CFBundleDisplayName"), "InfoPlist.strings:CFBundleDisplayName", lang)
    add(info.get("CFBundleDisplayName"), "Info.plist:CFBundleDisplayName")
    add(info.get("CFBundleName"), "Info.plist:CFBundleName")
    add(itunes_name, "iTunesMetadata.plist:itemName")
    add(itunes_display_name, "iTunesMetadata.plist:bundleDisplayName")
    for lang in langs:
        if not (lang in TIER1_LANGS or lang.startswith("en-")):
            add(localized[lang].get("CFBundleDisplayName"), "InfoPlist.strings:CFBundleDisplayName", lang)
    for lang in langs:
        add(localized[lang].get("CFBundleName"), "InfoPlist.strings:CFBundleName", lang)
    add(executable, "CFBundleExecutable")
    add(input_name, "input_filename")
    return out


def select_name(candidates: List[Dict[str, str]]) -> Optional[str]:
    return candidates[0]["value"] if candidates else None
