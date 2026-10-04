"""Library identification: knowledge base, system-framework table and evidence matcher (WP4)."""
from __future__ import annotations

from .kb import KnowledgeBase, LibEntry, load_kb, validate_entry, validate_kb_doc
from .matcher import LibMatcher, Signal
from .sysframeworks import SysFrameworks, load_sysframeworks, normalize_dylib_name

__all__ = ["KnowledgeBase", "LibEntry", "load_kb", "validate_entry", "validate_kb_doc", "LibMatcher", "Signal",
           "SysFrameworks", "load_sysframeworks", "normalize_dylib_name"]
