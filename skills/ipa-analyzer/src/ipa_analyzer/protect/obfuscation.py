"""Obfuscation summary. Only evidence produced by other stages is used (the Unity dump identifier statistics);
no commercial protector signature could be verified from public sources, so none is shipped."""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from ..models import Verdict


def summarize_obfuscation(unity: Optional[Dict[str, Any]], rules: Dict[str, Any]) -> Tuple[Verdict, float, str, Dict[str, Any]]:
    """``(verdict, confidence, summary_key, data)``; summary_key is ``dump_obfuscated`` / ``dump_clean`` / ``no_data``."""
    dump = (unity or {}).get("dump") if isinstance((unity or {}).get("dump"), dict) else {}
    summary = dump.get("summary") if isinstance(dump.get("summary"), dict) else {}
    ob = summary.get("obfuscation") if isinstance(summary.get("obfuscation"), dict) else None
    cfg = rules.get("unity_identifier") or {}
    if not dump.get("ok") or ob is None:
        return Verdict.UNKNOWN, 0.2, "no_data", {}
    score = float(ob.get("score") or 0.0)
    level = ob.get("level")
    levels = cfg.get("suspected_level") or ["medium", "high"]
    suspicious = (level in levels) if isinstance(level, str) else score >= float(cfg.get("suspected_score", 0.35))
    data = {"unity_identifiers": {"score": score, "level": level}}
    if suspicious:
        return Verdict.SUSPECTED, 0.5, "dump_obfuscated", data
    return Verdict.NO, 0.4, "dump_clean", data
