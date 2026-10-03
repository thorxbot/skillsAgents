"""Embedded code-signature (SuperBlob) parser.

Layout (all fields big-endian, independent of the Mach-O byte order), Source: xnu ``cs_blobs.h``::

    SuperBlob   {u32 magic=0xFADE0CC0, u32 length, u32 count, BlobIndex[count]{u32 type, u32 offset}}
    CodeDirectory {u32 magic=0xFADE0C02, length, version, flags, hashOffset, identOffset,
                   nSpecialSlots, nCodeSlots, codeLimit, u8 hashSize, hashType, platform, pageSize,
                   u32 spare2, [v>=0x20100 scatterOffset] [v>=0x20200 teamOffset] ...}
    Entitlements  {u32 magic=0xFADE7171, u32 length, <xml plist>}
    DER entitlements 0xFADE7172, requirements 0xFADE0C01, CMS wrapper 0xFADE0B01 (slot 0x10000)

``cdhash`` is the digest of the *whole* CodeDirectory blob (using that directory's hash type),
truncated to 20 bytes. Nothing here verifies signatures; parsing never raises (errors are recorded in
``CodeSignature.parse_error``).
"""
from __future__ import annotations

import hashlib
import plistlib
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import constants as C

_HASHERS = {C.CS_HASHTYPE_SHA1: hashlib.sha1, C.CS_HASHTYPE_SHA256: hashlib.sha256,
            C.CS_HASHTYPE_SHA256_TRUNCATED: hashlib.sha256, C.CS_HASHTYPE_SHA384: hashlib.sha384}
# Preference when several CodeDirectories exist (modern kernels use the strongest one).
_HASH_RANK = {C.CS_HASHTYPE_SHA1: 1, C.CS_HASHTYPE_SHA256_TRUNCATED: 2, C.CS_HASHTYPE_SHA256: 3,
              C.CS_HASHTYPE_SHA384: 4}
_MAX_IDENT = 1024


@dataclass
class CodeDirectoryInfo:
    slot: int
    version: int
    flags: int
    hash_type: int
    hash_name: str
    hash_size: int
    identifier: Optional[str]
    team_id: Optional[str]
    code_slots: int
    special_slots: int
    code_limit: int
    page_size_log2: int
    platform: int
    exec_seg_flags: Optional[int]
    cdhash: Optional[str]      # hex of the first 20 digest bytes; None for unknown hash types

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class CodeSignature:
    identifier: Optional[str] = None
    team_id: Optional[str] = None
    hash_types: List[str] = field(default_factory=list)
    cdhash: Optional[str] = None                      # of the preferred (strongest) CodeDirectory
    cdhashes: Dict[str, str] = field(default_factory=dict)   # hash name -> cdhash hex
    flags: Optional[int] = None                       # CodeDirectory.flags of the primary directory
    code_directories: List[CodeDirectoryInfo] = field(default_factory=list)
    entitlements: Optional[Dict[str, Any]] = None
    entitlements_raw_xml: Optional[str] = None
    has_der_entitlements: bool = False
    requirements_present: bool = False
    cms_present: bool = False
    size: int = 0                                     # SuperBlob length actually parsed
    parse_error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

    @property
    def is_adhoc(self) -> bool:
        return bool(self.flags is not None and self.flags & C.CS_ADHOC)

    @property
    def is_linker_signed(self) -> bool:
        return bool(self.flags is not None and self.flags & C.CS_LINKER_SIGNED)

    @property
    def signature_kind(self) -> str:
        """``linker`` / ``adhoc`` / ``cms`` (signed with a certificate chain) / ``none`` / ``unknown``."""
        if self.parse_error and not self.code_directories:
            return "unknown"
        if not self.code_directories:
            return "none"
        if self.is_linker_signed:
            return "linker"
        if self.cms_present:
            return "cms"
        if self.is_adhoc:
            return "adhoc"
        return "unknown"

    @property
    def entitlement_keys(self) -> List[str]:
        return sorted(str(k) for k in self.entitlements) if isinstance(self.entitlements, dict) else []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identifier": self.identifier, "team_id": self.team_id, "hash_types": list(self.hash_types),
            "cdhash": self.cdhash, "cdhashes": dict(self.cdhashes), "flags": self.flags,
            "adhoc": self.is_adhoc, "linker_signed": self.is_linker_signed,
            "signature_kind": self.signature_kind,
            "entitlement_keys": self.entitlement_keys, "has_der_entitlements": self.has_der_entitlements,
            "requirements_present": self.requirements_present, "cms_present": self.cms_present,
            "size": self.size, "parse_error": self.parse_error,
        }


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from(">I", data, off)[0]


def _cstr(data: bytes, off: int, end: int, limit: int = _MAX_IDENT) -> Optional[str]:
    if off < 0 or off >= end:
        return None
    stop = min(end, off + limit)
    nul = data.find(b"\0", off, stop)
    raw = data[off:nul if nul >= 0 else stop]
    return raw.decode("utf-8", "replace")


def _parse_code_directory(data: bytes, slot: int, warnings: List[str]) -> Optional[CodeDirectoryInfo]:
    if len(data) < 44:
        warnings.append("CodeDirectory (slot 0x%x) too short: %d bytes" % (slot, len(data)))
        return None
    (_, length, version, flags, _hash_off, ident_off, n_special, n_code, code_limit,
     hash_size, hash_type, platform, page_size) = struct.unpack_from(">IIIIIIIIIBBBB", data, 0)
    if length > len(data):
        warnings.append("CodeDirectory (slot 0x%x) length %d exceeds available %d" % (slot, length, len(data)))
    blob = data[:min(length, len(data))] if length >= 44 else data
    identifier = _cstr(blob, ident_off, len(blob))
    team_id = None
    if version >= C.CS_SUPPORTSTEAMID and len(blob) >= 52:
        team_off = _u32(blob, 48)
        if team_off:
            team_id = _cstr(blob, team_off, len(blob), 64)
    exec_flags = None
    if version >= C.CS_SUPPORTSEXECSEG and len(blob) >= 88:
        exec_flags = struct.unpack_from(">Q", blob, 80)[0]
    cdhash = None
    hasher = _HASHERS.get(hash_type)
    if hasher is not None:
        cdhash = hasher(blob).digest()[:C.CS_CDHASH_LEN].hex()
    return CodeDirectoryInfo(
        slot=slot, version=version, flags=flags, hash_type=hash_type,
        hash_name=C.HASH_TYPE_NAMES.get(hash_type, "unknown(%d)" % hash_type), hash_size=hash_size,
        identifier=identifier, team_id=team_id, code_slots=n_code, special_slots=n_special,
        code_limit=code_limit, page_size_log2=page_size, platform=platform,
        exec_seg_flags=exec_flags, cdhash=cdhash)


def _parse_entitlements(blob: bytes, sig: CodeSignature) -> None:
    body = blob[8:]
    sig.entitlements_raw_xml = body.decode("utf-8", "replace")
    try:
        parsed = plistlib.loads(body)
    except Exception as exc:  # noqa: BLE001 - plistlib raises several unrelated exception types
        sig.warnings.append("entitlements plist unparsable: %s" % exc)
        return
    if isinstance(parsed, dict):
        sig.entitlements = parsed
    else:
        sig.warnings.append("entitlements plist is not a dictionary")


def parse_code_signature(data: bytes) -> CodeSignature:
    """Parse the blob referenced by ``LC_CODE_SIGNATURE``; never raises."""
    sig = CodeSignature()
    try:
        _parse_into(bytes(data), sig)
    except Exception as exc:  # noqa: BLE001 - last line of defence for hostile data
        sig.parse_error = sig.parse_error or "unexpected error: %s" % exc
    return sig


def _parse_into(data: bytes, sig: CodeSignature) -> None:
    if len(data) < 8:
        sig.parse_error = "signature blob too short (%d bytes)" % len(data)
        return
    magic = _u32(data, 0)
    if magic == C.CSMAGIC_CODEDIRECTORY:
        entries: List[Tuple[int, int]] = [(C.CSSLOT_CODEDIRECTORY, 0)]
        sig.size = len(data)
    elif magic == C.CSMAGIC_EMBEDDED_SIGNATURE:
        if len(data) < 12:
            sig.parse_error = "SuperBlob header truncated"
            return
        length, count = _u32(data, 4), _u32(data, 8)
        sig.size = min(length, len(data))
        if length > len(data):
            sig.warnings.append("SuperBlob length %d exceeds available %d" % (length, len(data)))
        if count > C.MAX_SUPERBLOB_ENTRIES or 12 + count * 8 > len(data):
            sig.parse_error = "implausible SuperBlob entry count %d" % count
            return
        entries = [struct.unpack_from(">II", data, 12 + i * 8) for i in range(count)]
    else:
        sig.parse_error = "unexpected signature magic 0x%08x" % magic
        return

    directories: List[CodeDirectoryInfo] = []
    for slot, off in entries:
        if off + 8 > len(data):
            sig.warnings.append("blob for slot 0x%x lies outside the signature (offset %d)" % (slot, off))
            continue
        bmagic, blen = _u32(data, off), _u32(data, off + 4)
        if magic == C.CSMAGIC_CODEDIRECTORY:
            blen = len(data)
        end = min(off + blen, len(data))
        if off + blen > len(data):
            sig.warnings.append("blob for slot 0x%x truncated (%d > %d)" % (slot, off + blen, len(data)))
        blob = data[off:end]
        if slot == C.CSSLOT_CODEDIRECTORY or C.CSSLOT_ALTERNATE_CODEDIRECTORIES <= slot < C.CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT:
            if bmagic != C.CSMAGIC_CODEDIRECTORY:
                sig.warnings.append("slot 0x%x does not hold a CodeDirectory (magic 0x%08x)" % (slot, bmagic))
                continue
            cd = _parse_code_directory(blob, slot, sig.warnings)
            if cd is not None:
                directories.append(cd)
        elif slot == C.CSSLOT_ENTITLEMENTS and bmagic == C.CSMAGIC_EMBEDDED_ENTITLEMENTS:
            _parse_entitlements(blob, sig)
        elif slot == C.CSSLOT_DER_ENTITLEMENTS and bmagic == C.CSMAGIC_EMBEDDED_DER_ENTITLEMENTS:
            sig.has_der_entitlements = True
        elif slot == C.CSSLOT_REQUIREMENTS:
            sig.requirements_present = True
        elif slot == C.CSSLOT_SIGNATURESLOT:
            # An ad-hoc signature carries an empty (8 byte) wrapper; a real CMS signature is larger.
            sig.cms_present = bmagic == C.CSMAGIC_BLOBWRAPPER and len(blob) > 8

    if not directories:
        sig.parse_error = sig.parse_error or "no CodeDirectory found"
        return
    sig.code_directories = directories
    primary = next((d for d in directories if d.slot == C.CSSLOT_CODEDIRECTORY), directories[0])
    sig.identifier, sig.flags = primary.identifier, primary.flags
    sig.team_id = next((d.team_id for d in [primary] + directories if d.team_id), None)
    sig.hash_types = [d.hash_name for d in directories]
    for d in directories:
        if d.cdhash:
            sig.cdhashes.setdefault(d.hash_name, d.cdhash)
    best = max((d for d in directories if d.cdhash), key=lambda d: _HASH_RANK.get(d.hash_type, 0), default=None)
    sig.cdhash = best.cdhash if best else None
    if sig.team_id is None and sig.entitlements:
        # Fallback: some signers omit teamOffset (pre-0x20200 directories) but entitle the team.
        val = sig.entitlements.get("com.apple.developer.team-identifier")
        if isinstance(val, str) and val:
            sig.team_id = val
