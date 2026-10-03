"""Tolerant plist loading (binary + XML) and JSON-friendly conversion."""
from __future__ import annotations

import logging
import plistlib
from typing import Any, Optional

log = logging.getLogger(__name__)

_MAX_BYTES_REPR = 64


def load_plist(data: bytes) -> Optional[Any]:
    """Parse a binary or XML plist. Returns ``None`` (and logs) when the data is corrupt.

    Tolerates leading junk before ``bplist00`` / ``<?xml`` / ``<plist`` (e.g. a UTF-8 BOM).
    Never raises for malformed data.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        log.warning("load_plist: expected bytes, got %s", type(data).__name__)
        return None
    data = bytes(data)
    candidates = [data]
    for marker in (b"bplist00", b"<?xml", b"<plist"):
        idx = data.find(marker, 0, 4096)
        if idx > 0:
            candidates.append(data[idx:])
            break
    last: Optional[BaseException] = None
    for blob in candidates:
        try:
            return plistlib.loads(blob)
        except Exception as exc:  # plistlib raises ValueError, InvalidFileException, ExpatError, ...
            last = exc
    log.warning("load_plist: cannot parse plist (%d bytes): %s", len(data), last)
    return None


def to_jsonable_plist(obj: Any) -> Any:
    """Convert plist values to JSON-native types (bytes -> ``"<data N bytes: hexhead>"``, dates -> ISO)."""
    import datetime as _dt

    if isinstance(obj, dict):
        return {str(k): to_jsonable_plist(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable_plist(v) for v in obj]
    if isinstance(obj, (bytes, bytearray)):
        head = bytes(obj[:_MAX_BYTES_REPR]).hex()
        return "<data %d bytes: %s%s>" % (len(obj), head, "..." if len(obj) > _MAX_BYTES_REPR else "")
    if isinstance(obj, (_dt.datetime, _dt.date)):
        return obj.isoformat()
    if isinstance(obj, plistlib.UID):
        return obj.data
    if isinstance(obj, float) and (obj != obj or obj in (float("inf"), float("-inf"))):
        return None
    return obj
