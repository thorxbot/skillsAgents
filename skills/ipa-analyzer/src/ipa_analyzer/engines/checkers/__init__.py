"""Engine checker auto-discovery: importing this package imports every module in it.

A module that fails to import is recorded (``api.checker_import_failures()``) and never crashes the
run. ``RegistryError`` (duplicate checker id) propagates.
"""
from __future__ import annotations

import importlib
import pkgutil
from typing import List

from ...errors import RegistryError
from ..api import _record_checker_import_failure


def discover(package: str = __name__) -> List[str]:
    pkg = importlib.import_module(package)
    failed: List[str] = []
    for info in sorted(pkgutil.iter_modules(pkg.__path__), key=lambda i: i.name):
        try:
            importlib.import_module("%s.%s" % (package, info.name))
        except RegistryError:
            raise
        except Exception as exc:  # noqa: BLE001
            _record_checker_import_failure(info.name, "%s: %s" % (type(exc).__name__, exc))
            failed.append(info.name)
    return failed


discover()
