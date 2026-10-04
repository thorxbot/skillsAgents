"""``embedded.mobileprovision`` parsing (CMS/PKCS#7 envelope around an XML plist; no signature check).

Device UDIDs are never emitted: only the count and short SHA-256 prefixes (``device_hash_prefixes``).
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ..models import Evidence, Verdict
from ..util.plist_utils import load_plist, to_jsonable_plist
from .infoplist import as_str, iso_utc

log = logging.getLogger(__name__)

__all__ = ["extract_plist_bytes", "parse_provision", "device_hash_prefix", "summarize_provision",
           "provision_kind", "classify_distribution", "MAX_DEVICE_PREFIXES", "HASH_PREFIX_LEN"]

HASH_PREFIX_LEN = 8
MAX_DEVICE_PREFIXES = 50
_XML_START = b"<?xml"
_PLIST_END = b"</plist>"


def extract_plist_bytes(data: bytes) -> Optional[bytes]:
    """Slice the embedded XML plist out of the CMS blob (``<?xml`` ... ``</plist>``).

    Apple's profiles carry the plist as a DER-encoded (definite length) OCTET STRING, so the XML is
    contiguous in the file and no ASN.1 parsing is needed. Also accepts a bare plist.
    """
    start = data.find(_XML_START)
    if start < 0:
        start = data.find(b"<plist")
        if start < 0:
            return None
    end = data.find(_PLIST_END, start)
    if end < 0:
        return None
    return data[start:end + len(_PLIST_END)]


def parse_provision(data: bytes) -> Optional[Dict[str, Any]]:
    """Raw provisioning-profile dictionary, or ``None`` if no valid plist is found inside ``data``."""
    blob = extract_plist_bytes(data)
    if blob is None:
        return None
    obj = load_plist(blob)
    return obj if isinstance(obj, dict) else None


def device_hash_prefix(udid: str, n: int = HASH_PREFIX_LEN) -> str:
    """First ``n`` hex chars of ``sha256(lowercase(strip(udid)))``."""
    return hashlib.sha256(udid.strip().lower().encode("utf-8")).hexdigest()[:n]


def _first(value: Any) -> Optional[str]:
    if isinstance(value, (list, tuple)):
        for v in value:
            s = as_str(v)
            if s:
                return s
        return None
    return as_str(value)


def _str_list(value: Any) -> List[str]:
    if isinstance(value, str):
        value = [value]
    return [s for s in (as_str(v) for v in value) if s] if isinstance(value, (list, tuple)) else []


def summarize_provision(raw: Mapping[str, Any]) -> Dict[str, Any]:
    """Contract ``meta.provision`` dict (``present`` is True) from the raw profile plist."""
    devices = raw.get("ProvisionedDevices")
    udids = [d for d in devices if isinstance(d, str) and d.strip()] if isinstance(devices, (list, tuple)) else []
    prefixes = sorted({device_hash_prefix(u) for u in udids})
    ents = raw.get("Entitlements")
    ents = to_jsonable_plist(ents) if isinstance(ents, dict) else {}
    certs = raw.get("DeveloperCertificates")
    return {
        "present": True,
        "name": as_str(raw.get("Name")),
        "team_name": as_str(raw.get("TeamName")),
        "team_id": _first(raw.get("TeamIdentifier")),
        "app_id_prefix": _first(raw.get("ApplicationIdentifierPrefix")),
        "creation_date": iso_utc(raw.get("CreationDate")),
        "expiration_date": iso_utc(raw.get("ExpirationDate")),
        "provisions_all_devices": raw.get("ProvisionsAllDevices") is True,
        "device_count": len(udids),
        "device_hash_prefixes": prefixes[:MAX_DEVICE_PREFIXES],
        "entitlements": ents,
        "extra": {
            "uuid": as_str(raw.get("UUID")),
            "app_id_name": as_str(raw.get("AppIDName")),
            "platform": _str_list(raw.get("Platform")),
            "team_ids": _str_list(raw.get("TeamIdentifier")),
            "app_id_prefixes": _str_list(raw.get("ApplicationIdentifierPrefix")),
            "is_xcode_managed": raw.get("IsXcodeManaged") is True if "IsXcodeManaged" in raw else None,
            "certificate_count": len(certs) if isinstance(certs, (list, tuple)) else 0,
            "device_hash_prefixes_truncated": len(prefixes) > MAX_DEVICE_PREFIXES,
            "device_hash": "sha256(lowercase UDID)[:%d]" % HASH_PREFIX_LEN,
        },
    }


def provision_kind(prov: Mapping[str, Any]) -> Dict[str, Any]:
    """Classify a summarized profile by Apple's profile-type rules.

    * ``ProvisionsAllDevices`` true -> enterprise (in-house) profile.
    * ``ProvisionedDevices`` present + ``get-task-allow`` true -> development.
    * ``ProvisionedDevices`` present + ``get-task-allow`` false -> ad hoc.
    * no device list, not all-devices -> App Store profile (get-task-allow false).
    # Source: Apple "Maintaining Identifiers, Devices, and Profiles" / TN2407; classification rules
    # are the community-standard reading of those keys, verified only against synthetic profiles.

    Returns ``{kind, confidence, alternatives, get_task_allow}`` where ``kind`` is one of
    ``enterprise|development|adhoc|appstore|unknown`` and ``alternatives`` lists competing kinds.
    """
    ents = prov.get("entitlements") if isinstance(prov.get("entitlements"), dict) else {}
    gta = ents.get("get-task-allow") if isinstance(ents.get("get-task-allow"), bool) else None
    has_devices = int(prov.get("device_count") or 0) > 0
    if prov.get("provisions_all_devices"):
        return {"kind": "enterprise", "confidence": 0.9, "alternatives": [], "get_task_allow": gta}
    if has_devices:
        if gta is True:
            return {"kind": "development", "confidence": 0.9, "alternatives": [], "get_task_allow": gta}
        if gta is False:
            return {"kind": "adhoc", "confidence": 0.9, "alternatives": [], "get_task_allow": gta}
        return {"kind": "unknown", "confidence": 0.4, "alternatives": ["development", "adhoc"],
                "get_task_allow": None}
    if gta is True:
        return {"kind": "development", "confidence": 0.5, "alternatives": ["appstore"], "get_task_allow": gta}
    return {"kind": "appstore", "confidence": 0.75 if gta is False else 0.6,
            "alternatives": [], "get_task_allow": gta}


def classify_distribution(prov: Optional[Mapping[str, Any]], *, prov_unreadable: bool = False,
                          store_markers: Sequence[str] = (), has_code_signature: bool = False,
                          store_names_consistent: bool = False) -> Dict[str, Any]:
    """Decide the distribution type from the profile and App Store container markers.

    ``prov`` is a ``summarize_provision`` dict (``None`` = no profile). ``store_markers`` names the
    App Store container artefacts found (``"iTunesMetadata.plist"``, ``"SC_Info"``).
    ``store_names_consistent`` is true when the SC_Info file names match the main executable.

    Without a profile the App Store verdict rests on container-layer files only. A decrypted and
    repackaged IPA keeps them as well, so the result is never better than ``suspected`` (0.6-0.7).

    Returns ``{type, verdict, confidence, evidence: [Evidence], alternatives: [str], repackaged_hint}``;
    ``type`` is ``appstore|adhoc|enterprise|development|unsigned_or_repackaged|unknown``.
    """
    ev: List[Evidence] = []
    markers = list(store_markers)
    for m in markers:
        ev.append(Evidence("file", m, "App Store download artefact"))

    if prov_unreadable:
        ev.append(Evidence("file", "embedded.mobileprovision", "present but not parseable"))
        return {"type": "unknown", "verdict": Verdict.UNKNOWN, "confidence": 0.2, "evidence": ev,
                "alternatives": ["development", "adhoc", "enterprise", "appstore"], "repackaged_hint": False}

    if prov is not None:
        k = provision_kind(prov)
        kind = k["kind"]
        conf = float(k["confidence"])
        ents = prov.get("entitlements") if isinstance(prov.get("entitlements"), dict) else {}
        ev.append(Evidence("file", "embedded.mobileprovision", "profile team=%s" % (prov.get("team_id") or "?")))
        if "get-task-allow" in ents:
            ev.append(Evidence("plist_key", "embedded.mobileprovision:Entitlements.get-task-allow",
                               str(ents.get("get-task-allow")).lower()))
        if prov.get("provisions_all_devices"):
            ev.append(Evidence("plist_key", "embedded.mobileprovision:ProvisionsAllDevices", "true"))
        if prov.get("device_count"):
            ev.append(Evidence("plist_key", "embedded.mobileprovision:ProvisionedDevices",
                               "%d devices" % int(prov["device_count"])))
        aps = ents.get("aps-environment")
        if isinstance(aps, str):
            ev.append(Evidence("plist_key", "embedded.mobileprovision:Entitlements.aps-environment", aps))
        repack = False
        alternatives = list(k["alternatives"])
        if kind == "appstore" and markers:
            conf = max(conf, 0.9)
        elif kind != "appstore" and markers:
            repack = True
            conf = min(conf, 0.7)
            alternatives.append("appstore")
            ev.append(Evidence("heuristic", "store_artefacts_with_non_store_profile",
                               "App Store artefacts coexist with a %s profile: likely re-signed" % kind))
        verdict = Verdict.YES if conf >= 0.85 and kind != "unknown" else Verdict.SUSPECTED
        return {"type": kind, "verdict": verdict, "confidence": conf, "evidence": ev,
                "alternatives": alternatives, "repackaged_hint": repack}

    if markers:
        if has_code_signature:
            both = len(markers) > 1
            conf = 0.7 if both and store_names_consistent else (0.65 if both else 0.6)
            ev.append(Evidence("heuristic", "container_evidence_only",
                               "Container-layer evidence only: it cannot prove where the package came from "
                               "(decrypted and repackaged IPAs keep these files)"))
            if both and store_names_consistent:
                ev.append(Evidence("heuristic", "store_names_consistent",
                                   "SC_Info file name matches the main executable; no embedded.mobileprovision"))
            return {"type": "appstore", "verdict": Verdict.SUSPECTED, "confidence": conf,
                    "evidence": ev, "alternatives": ["unsigned_or_repackaged"], "repackaged_hint": False}
        ev.append(Evidence("heuristic", "_CodeSignature", "App Store artefacts present but the code signature is missing"))
        return {"type": "appstore", "verdict": Verdict.SUSPECTED, "confidence": 0.5, "evidence": ev,
                "alternatives": ["unsigned_or_repackaged"], "repackaged_hint": True}

    ev.append(Evidence("heuristic", "distribution",
                       "no embedded.mobileprovision, SC_Info or iTunesMetadata.plist found"))
    if has_code_signature:
        ev.append(Evidence("file", "_CodeSignature/CodeResources", "signed, but no profile or store artefacts"))
        return {"type": "unsigned_or_repackaged", "verdict": Verdict.SUSPECTED, "confidence": 0.4,
                "evidence": ev, "alternatives": ["appstore"], "repackaged_hint": True}
    return {"type": "unsigned_or_repackaged", "verdict": Verdict.SUSPECTED, "confidence": 0.6,
            "evidence": ev, "alternatives": [], "repackaged_hint": True}
