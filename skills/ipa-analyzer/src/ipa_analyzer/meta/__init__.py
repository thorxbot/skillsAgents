"""Helpers for the ``meta`` stage: Info.plist, strings files, provisioning profile, iTunesMetadata,
CodeResources and permission tables. Pure functions; the stage wiring lives in ``analyzers/meta.py``."""
from __future__ import annotations

from .coderesources import parse_code_resources, verify_code_resources
from .infoplist import build_name_candidates, parse_info_plist, select_name
from .itunes_meta import parse_itunes_metadata
from .permissions import collect_permissions, load_permission_db
from .provision import classify_distribution, parse_provision, summarize_provision
from .strings_file import normalize_lang, parse_strings_file

__all__ = [
    "parse_code_resources", "verify_code_resources", "build_name_candidates", "parse_info_plist",
    "select_name", "parse_itunes_metadata", "collect_permissions", "load_permission_db",
    "classify_distribution", "parse_provision", "summarize_provision", "normalize_lang", "parse_strings_file",
]
