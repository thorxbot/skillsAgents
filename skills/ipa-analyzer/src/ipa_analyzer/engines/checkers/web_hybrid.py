"""Web-hybrid checker (Cordova / Capacitor / WebView games): plain vs minified vs obfuscated vs unidentified web assets.

Looks at ``.html`` / ``.js`` / ``.css`` under the web root (``www/``, ``public/`` ... from ``data/engines_checks.json``)
or, when no root is found, anywhere in the app outside SDK frameworks.  Informational: reports the plain-text
ratio, minification (very long lines / ``.min.js`` names) and javascript-obfuscator style identifiers
(``_0x1a2b3c``).  Minified or obfuscated code is still plain text and is not reported as encryption; files that are
neither text nor a known format are ``suspected``.  Detection only.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from ...models import Evidence, Status
from ..api import CheckerResult, DetectResult, register_checker
from ..formats import common
from ..formats.common import FileIndex, FileRec, ScriptTally

_OBFUSCATOR = re.compile(rb"_0x[0-9a-f]{4,6}")


def _web_files(idx: FileIndex, cfg: Dict[str, Any]) -> List[FileRec]:
    rx = re.compile(cfg["web_root_regex"])
    rooted = [r for r in idx.recs if rx.search(r.rel) and r.ext in cfg["web_exts"]]
    if rooted:
        return rooted
    return idx.not_vendor(idx.with_ext(*cfg["web_exts"]))


@register_checker("web_hybrid")
class WebHybridChecker:
    engine_id = "web_hybrid"

    def applies(self, ctx: Any, detect: DetectResult) -> bool:
        cfg = common.checks("web_hybrid")
        if any(detect.has(i) for i in cfg["detect_ids"]):
            return True
        idx = FileIndex(ctx)
        return any(idx.find(rx) for rx in cfg["markers"])

    def run(self, ctx: Any, detect: DetectResult) -> CheckerResult:
        cfg = common.checks("web_hybrid")
        idx = FileIndex(ctx)
        files = _web_files(idx, cfg)
        sample, total = common.evenly_sample(files, cfg["sample_max"])
        tally = ScriptTally()
        minified = obfuscated = 0
        for r in sample:
            blob, head = common.classify_file(ctx, r)
            tally.add(r.rel, r.ext, blob)
            if blob.kind == common.K_PLAIN and r.ext == ".js":
                text = common.read_head(ctx, r.path, cfg["minify_probe_bytes"])
                lines = text.split(b"\n")
                longest = max((len(x) for x in lines), default=0)
                if r.rel.endswith(".min.js") or longest >= cfg["minified_line_length"]:
                    minified += 1
                if _OBFUSCATOR.search(text):
                    obfuscated += 1
        scripts = tally.to_dict(sampled=len(sample), of=total)
        scripts["minified_js"] = minified
        scripts["obfuscator_style_js"] = obfuscated
        scripts["plain_ratio"] = round(tally.count("plain") / float(max(tally.total, 1)), 3)
        verdict, conf, state = common.verdict_from_tally(tally, total)
        ev: List[Evidence] = []
        for kk in (common.K_CUSTOM_HEADER, common.K_HIGH_ENTROPY, common.K_PLAIN):
            ev.extend(common.file_evidence(tally.samples.get(kk, []), kk, 2))
        note = ""
        if minified or obfuscated:
            note = "%d minified and %d obfuscator-style JS file(s) examined; minification / obfuscation is not encryption." % (
                minified, obfuscated)
        f = common.script_finding("web_hybrid", "Web hybrid", scripts, verdict, conf, state, ev, note)
        roots = sorted({r.rel.split("/")[0] + "/" for r in sample})[:5]
        return CheckerResult(findings=[f], data={"scripts": scripts, "web_roots": roots,
                                                 "markers": [m[0].rel for m in (idx.find(rx) for rx in cfg["markers"]) if m]},
                             status=Status.OK)
