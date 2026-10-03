"""Exception hierarchy shared by all modules.

Stage code should raise these (or let unexpected exceptions propagate; the pipeline isolates them).
``InvalidInput`` is special: when a stage raises it, the CLI exits with code 2.
"""
from __future__ import annotations


class IpaAnalyzerError(Exception):
    """Base class for all errors raised deliberately by this package."""


class UsageError(IpaAnalyzerError):
    """Bad command line / configuration (CLI exit code 1)."""


class InvalidInput(IpaAnalyzerError):
    """The input is not a usable IPA / .app / directory, or is corrupt (CLI exit code 2)."""


class LimitExceeded(InvalidInput):
    """A safety limit (total size, file size, file count, compression ratio) was exceeded."""


class UnsafePath(InvalidInput):
    """An archive entry name would escape the output directory (zip-slip, absolute path, ...)."""


class RegistryError(IpaAnalyzerError):
    """Invalid stage registration (duplicate name, unknown dependency, ...)."""


class CycleError(RegistryError):
    """The stage dependency graph contains a cycle."""

    def __init__(self, cycle: "list[str]") -> None:
        self.cycle = list(cycle)
        super().__init__("stage dependency cycle: " + " -> ".join(self.cycle))
