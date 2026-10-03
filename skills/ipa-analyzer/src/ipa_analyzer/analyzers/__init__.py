"""Stage auto-discovery: importing this package imports every module in it.

Each module registers its stage(s) with ``@register`` (see ``ipa_analyzer.registry``). A module that
fails to import is recorded in ``registry.import_failures`` and shows up in the run as a failed
pseudo-stage ``import:<module>``; it never crashes the program. A ``RegistryError`` (duplicate stage
name, ...) is a programming error and propagates.
"""
from __future__ import annotations

import importlib
import logging
import pkgutil
import traceback
from typing import List, Optional

from ..errors import RegistryError
from ..registry import Registry, get_registry

log = logging.getLogger(__name__)

__all__ = ["discover"]


def discover(registry: Optional[Registry] = None, package: str = __name__) -> List[str]:
    """Import all modules of ``package``; return the names of modules that failed to import."""
    reg = registry if registry is not None else get_registry()
    pkg = importlib.import_module(package)
    failed: List[str] = []
    for info in sorted(pkgutil.iter_modules(pkg.__path__), key=lambda i: i.name):
        full = "%s.%s" % (package, info.name)
        try:
            importlib.import_module(full)
        except RegistryError:
            raise
        except Exception as exc:  # noqa: BLE001 - isolate broken analyzer modules
            log.error("analyzer module %s failed to import: %s", full, exc)
            log.debug("%s", traceback.format_exc())
            reg.record_import_failure(info.name, "%s: %s" % (type(exc).__name__, exc))
            failed.append(info.name)
    return failed


discover()
