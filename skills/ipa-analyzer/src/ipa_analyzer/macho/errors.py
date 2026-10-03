"""Exceptions raised by the Mach-O reader."""
from __future__ import annotations

from ..errors import IpaAnalyzerError


class MachOError(IpaAnalyzerError):
    """The data is (or claims to be) a Mach-O file but is too malformed to read."""


class NotMachO(MachOError):
    """The data is not a Mach-O / fat file (wrong magic, empty file, Java class file ...)."""
