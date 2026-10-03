"""Pure-Python Mach-O reading: parsing, code signature, encryption flags, streaming scans (WP3)."""
from __future__ import annotations

from .codesign import CodeDirectoryInfo, CodeSignature, parse_code_signature
from .errors import MachOError, NotMachO
from .parser import (BuildTool, BuildVersion, DecodedFlags, DylibRef, EncryptionInfo, LoadCommand, MachOFile,
                     MachOSlice, Section, Segment, Symbol, SymtabInfo, parse)
from .scan import (ScanHit, ScanResult, find_unity_version_hits, find_unity_version_strings, scan_file)
from .writer import write_thin

__all__ = [
    "parse", "MachOFile", "MachOSlice", "Segment", "Section", "DylibRef", "EncryptionInfo", "LoadCommand",
    "SymtabInfo", "BuildVersion", "BuildTool", "DecodedFlags", "Symbol", "CodeSignature", "CodeDirectoryInfo",
    "parse_code_signature", "MachOError", "NotMachO", "write_thin", "scan_file", "ScanHit", "ScanResult",
    "find_unity_version_strings", "find_unity_version_hits",
]
