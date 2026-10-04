"""Protection / encryption summaries: FairPlay, anti-debug and jailbreak-detection features, obfuscation (WP4)."""
from __future__ import annotations

from .antidebug import Rules, ScanOutcome, load_rules, score_hits, scan_slice
from .fairplay import FairplayInfo, summarize_fairplay
from .obfuscation import summarize_obfuscation

__all__ = ["Rules", "ScanOutcome", "load_rules", "score_hits", "scan_slice", "FairplayInfo", "summarize_fairplay",
           "summarize_obfuscation"]
