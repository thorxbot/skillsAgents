"""il2cpp dump pre-conditions (``unity.il2cpp.precheck``).

Pure aggregation of facts the stage already has; nothing is run here.  Error codes are the frozen
``Il2CppErrorCode`` values (as strings).  ``force_dump`` overrides only the *metadata* verdict and the
version-support check; a FairPlay-encrypted binary is never dumped.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

__all__ = ["run_precheck", "IL2CPP_MARKER_PATTERNS"]

# Bytes that every IL2CPP player carries (the C API exports / helper names).  Source: the il2cpp C API is
# exported with the ``il2cpp_`` prefix (e.g. ``il2cpp_init``); on iOS they live in the player binary.
IL2CPP_MARKER_PATTERNS = (rb"il2cpp_[a-z_]{3,40}", rb"UnityFramework")


def run_precheck(*, backend: str, binary: Dict[str, Any], metadata: Dict[str, Any],
                 il2cpp_markers: Optional[int], support: Dict[str, Any], force_dump: bool = False,
                 unity_version: Optional[str] = None) -> Dict[str, Any]:
    """Return ``{ready, error_code, reasons[], warnings[], forced, backends[]}``.

    * ``binary``   ``{path, slice, encrypted}`` (``encrypted`` None = unknown)
    * ``metadata`` the ``metadata`` record of ``ctx.results`` (``present``, ``verdict``, ``version`` ...)
    * ``il2cpp_markers`` count of ``il2cpp_*`` strings found in the binary (None = not scanned)
    * ``support``  ``metadata.backend_support(version)`` output (which backends accept the version)
    """
    reasons: List[str] = []
    warnings: List[str] = []
    out: Dict[str, Any] = {"ready": False, "error_code": None, "reasons": reasons, "warnings": warnings,
                           "forced": False, "backends": list(support.get("supported_by") or [])}
    if backend != "il2cpp":
        reasons.append("backend_not_il2cpp")
        return out
    if not metadata.get("present"):
        reasons.append("metadata_missing")
        return out
    if not binary.get("path"):
        reasons.append("binary_missing")
        return out
    if binary.get("encrypted") is True:
        reasons.append("binary_fairplay")
        out["error_code"] = "E_BINARY_FAIRPLAY"
        return out
    if binary.get("encrypted") is None:
        warnings.append("binary_encryption_unknown")

    verdict = metadata.get("verdict")
    blocked = False
    if verdict in ("yes", "suspected"):
        # a version nobody supports is reported as such, not as encryption
        reasons_meta = metadata.get("reasons") or []
        only_version = reasons_meta and set(reasons_meta) <= {"magic_ok", "version_out_of_range", "layout_unknown"} \
            and "version_out_of_range" in reasons_meta
        out["error_code"] = "E_METADATA_VERSION_UNSUPPORTED" if only_version else "E_METADATA_ENCRYPTED"
        reasons.append("metadata_version_unsupported" if only_version else "metadata_encrypted_%s" % verdict)
        blocked = True
    elif verdict not in ("no",):
        warnings.append("metadata_verdict_%s" % verdict)

    version = metadata.get("version")
    if not blocked and version is not None and not out["backends"]:
        out["error_code"] = "E_METADATA_VERSION_UNSUPPORTED"
        reasons.append("no_backend_supports_version")
        blocked = True
    if not blocked and version is not None and out["backends"] and not unity_version:
        needs = set(support.get("needs_unity_version") or [])
        if needs and needs >= set(out["backends"]):
            out["error_code"] = "E_METADATA_VERSION_UNSUPPORTED"
            reasons.append("backend_needs_unity_version")
            blocked = True

    if il2cpp_markers is not None and il2cpp_markers == 0:
        warnings.append("no_il2cpp_markers_in_binary")

    if blocked and force_dump:
        out["forced"] = True
        warnings.append("forced_past_%s" % out["error_code"])
        out["forced_error_code"] = out["error_code"]
        out["error_code"] = None
        blocked = False
    if blocked:
        return out
    out["ready"] = True
    reasons.append("ok")
    return out
