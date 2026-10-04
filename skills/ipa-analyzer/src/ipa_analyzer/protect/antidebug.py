"""Anti-debug / jailbreak-detection feature rules (``data/protectors.json``) and their evaluation.

A hit is a *characteristic*, never a conclusion: verdicts stop at ``suspected``. Imported symbol names live
outside the FairPlay-encrypted range, so symbol rules still work on encrypted binaries; string rules need a
readable ``__cstring`` and are skipped (and reported as unreadable) otherwise.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Pattern, Tuple

from ..models import Verdict
from ..util import paths as _paths

log = logging.getLogger(__name__)

MAX_SYMBOLS = 300_000
MAX_STRINGS = 2_000_000


@dataclass
class Rules:
    thresholds: Dict[str, float] = field(default_factory=lambda: {"suspected": 0.4, "weak": 0.1, "max_confidence": 0.8})
    ad_symbols: Dict[str, Tuple[float, str]] = field(default_factory=dict)
    ad_strings: Dict[str, Tuple[float, str]] = field(default_factory=dict)
    jb_strings: Dict[str, Tuple[float, str]] = field(default_factory=dict)
    jb_symbols: Dict[str, Tuple[float, str]] = field(default_factory=dict)
    jb_schemes: Dict[str, float] = field(default_factory=dict)
    obfuscation: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    _string_re: Optional[Pattern[str]] = None

    def string_regex(self) -> Optional[Pattern[str]]:
        if self._string_re is None:
            toks = sorted(set(self.ad_strings) | set(self.jb_strings), key=len, reverse=True)
            if toks:
                self._string_re = re.compile("|".join(re.escape(t) for t in toks))
        return self._string_re


def _rules_of(rows: Any) -> Dict[str, Tuple[float, str]]:
    out: Dict[str, Tuple[float, str]] = {}
    for r in rows or []:
        if isinstance(r, dict) and isinstance(r.get("pattern"), str):
            out[r["pattern"]] = (float(r.get("weight") or 0.0), str(r.get("note") or ""))
    return out


def load_rules(data_dir: Optional[Path] = None) -> Rules:
    path = (Path(data_dir) if data_dir else _paths.resource_dir("data")) / "protectors.json"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        r = Rules()
        r.warnings.append("protectors.json unreadable (%s): anti-debug / jailbreak rules disabled" % exc)
        return r
    ad = doc.get("antidebug") or {}
    jb = doc.get("jailbreak_detect") or {}
    rules = Rules(
        ad_symbols=_rules_of(ad.get("symbols")), ad_strings=_rules_of(ad.get("strings")),
        jb_strings=_rules_of(jb.get("strings")), jb_symbols=_rules_of(jb.get("symbols")),
        jb_schemes={r["pattern"].lower(): float(r.get("weight") or 0.0) for r in jb.get("query_schemes") or []
                    if isinstance(r, dict) and isinstance(r.get("pattern"), str)},
        obfuscation=doc.get("obfuscation") or {})
    th = doc.get("thresholds")
    if isinstance(th, dict):
        rules.thresholds.update({k: float(v) for k, v in th.items() if isinstance(v, (int, float))})
    return rules


@dataclass
class ScanOutcome:
    """Raw hits of one slice. ``strings_readable`` is False when no C string could be read (encrypted code)."""
    ad_hits: List[Dict[str, Any]] = field(default_factory=list)
    jb_hits: List[Dict[str, Any]] = field(default_factory=list)
    strings_readable: bool = False
    symbols_read: bool = False


def scan_slice(sl: Any, ref: str, rules: Rules) -> ScanOutcome:
    """Evaluate symbol and string rules on a ``MachOSlice`` (encrypted ranges are skipped)."""
    out = ScanOutcome()
    seen = set()

    def hit(bucket: List[Dict[str, Any]], kind: str, pattern: str, weight: float) -> None:
        key = (kind, pattern)
        if key not in seen:
            seen.add(key)
            bucket.append({"kind": kind, "ref": ref, "pattern": pattern, "weight": weight})

    if rules.ad_symbols or rules.jb_symbols:
        for n, sym in enumerate(sl.iter_imported_symbols()):
            if n >= MAX_SYMBOLS:
                break
            out.symbols_read = True
            name = sym.name
            if name in rules.ad_symbols:
                hit(out.ad_hits, "symbol", name, rules.ad_symbols[name][0])
            if name in rules.jb_symbols:
                hit(out.jb_hits, "symbol", name, rules.jb_symbols[name][0])
    rx = rules.string_regex()
    if rx is not None:
        for n, s in enumerate(sl.iter_cstrings(4, skip_encrypted=True)):
            if n >= MAX_STRINGS:
                break
            out.strings_readable = True
            for m in rx.finditer(s):
                tok = m.group(0)
                if tok in rules.ad_strings:
                    hit(out.ad_hits, "string", tok, rules.ad_strings[tok][0])
                if tok in rules.jb_strings:
                    hit(out.jb_hits, "string", tok, rules.jb_strings[tok][0])
    return out


def score_hits(hits: Iterable[Dict[str, Any]], rules: Rules, *, readable: bool, scanned: bool) -> Tuple[Verdict, float, float, str]:
    """``(verdict, confidence, score, case)``; ``case`` is ``hit`` / ``weak`` / ``none`` / ``unreadable`` / ``no_data``.

    * strong enough hits -> ``suspected`` (never ``yes``);
    * only weak hits -> ``unknown``;
    * no hits and every scanned binary readable -> ``no`` (low confidence: absence of features is not proof);
    * no hits but code encrypted / not scanned -> ``unknown``.
    """
    best: Dict[Tuple[str, str], float] = {}
    for h in hits:
        best[(h["kind"], h["pattern"])] = max(best.get((h["kind"], h["pattern"]), 0.0), float(h.get("weight") or 0.0))
    score = round(min(1.0, sum(best.values())), 2)
    th = rules.thresholds
    if not scanned:
        return Verdict.UNKNOWN, 0.2, 0.0, "no_data"
    if best and score >= th.get("suspected", 0.4):
        return Verdict.SUSPECTED, round(min(th.get("max_confidence", 0.8), 0.4 + 0.4 * score), 2), score, "hit"
    if best:
        return Verdict.UNKNOWN, 0.3, score, "weak"
    if readable:
        return Verdict.NO, 0.5, 0.0, "none"
    return Verdict.UNKNOWN, 0.3, 0.0, "unreadable"
