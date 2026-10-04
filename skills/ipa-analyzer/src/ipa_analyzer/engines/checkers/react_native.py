"""React Native checker: JS bundle form (Hermes bytecode / plain JS / unidentified) -> ``engine.hermes``,
``engine.script.encrypted``.

Bundles: ``main.jsbundle`` (default iOS name) and any ``*.jsbundle`` / ``*.bundle`` file at the app root or in
``assets``.  Hermes bytecode is recognised by its header (``engines/formats/hermes.py``, facebook/hermes
``BytecodeFileFormat.h``); a text bundle is plain JavaScript (Metro output is minified or not, which is not
encryption).  Bytecode is compiled code, not encryption: ``no`` with the "compiled" label.  A bundle that is
neither text nor Hermes nor a known compression container is ``suspected``.  Detection only.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ...models import Evidence, Status, Verdict
from ..api import CheckerResult, DetectResult, register_checker
from ..formats import common, hermes
from ..formats.common import FileIndex, FileRec, ScriptTally


def _bundles(idx: FileIndex, cfg: Dict[str, Any]) -> List[FileRec]:
    out = [r for r in idx.recs if r.ext in cfg["bundle_exts"] and r.size > 0]
    out += [r for r in idx.recs if r.magic == "hermes_bytecode" and r not in out]
    return idx.not_vendor(sorted(out, key=lambda r: r.rel))


@register_checker("react_native")
class ReactNativeChecker:
    engine_id = "react_native"

    def applies(self, ctx: Any, detect: DetectResult) -> bool:
        if detect.has("react_native") or detect.has("hermes"):
            return True
        idx = FileIndex(ctx)
        return any(idx.exists(n) for n in common.checks("react_native")["default_bundles"]) or \
            bool(idx.with_magic("hermes_bytecode"))

    def run(self, ctx: Any, detect: DetectResult) -> CheckerResult:
        cfg = common.checks("react_native")
        idx = FileIndex(ctx)
        bundles = _bundles(idx, cfg)[:cfg["max_bundles"]]
        tally = ScriptTally()
        items: List[Dict[str, Any]] = []
        hermes_n = plain_n = 0
        versions: List[int] = []
        ev: List[Evidence] = []
        for r in bundles:
            head = common.read_head(ctx, r.path, cfg["head_bytes"])
            blob = common.classify_blob(head, r.size, r.entropy)
            item: Dict[str, Any] = {"path": r.rel, "size": r.size, "kind": blob.kind}
            if blob.kind == common.K_HERMES:
                info = hermes.parse_header(head, r.size)
                item["hermes"] = info.to_dict()
                hermes_n += 1
                if info.version is not None:
                    versions.append(info.version)
                ev.append(Evidence("file", r.rel, "Hermes bytecode v%s%s" % (
                    info.version, "" if info.file_length_matches in (None, True) else " (header length differs from file size)")))
            elif blob.kind == common.K_PLAIN:
                plain_n += 1
                item["metro_prelude"] = b"__BUNDLE_START_TIME__" in head or b"__d(" in head   # UNVERIFIED Metro markers
            tally.add(r.rel, r.ext, blob)
            items.append(item)
        scripts = tally.to_dict(sampled=len(bundles), of=len(bundles))
        data: Dict[str, Any] = {"bundles": items, "hermes_versions": sorted(set(versions)), "scripts": scripts,
                                "rct_frameworks": [r.rel for r in idx.recs if "/React" in r.rel and r.rel.startswith("Frameworks/")][:5]}
        findings = []
        if hermes_n:
            hv, hc = Verdict.YES, 0.95
            hnote = "Hermes bytecode (compiled; not encryption)."
        elif plain_n:
            hv, hc = Verdict.NO, 0.8
            hnote = "Plain JavaScript bundle (JavaScriptCore), no Hermes bytecode."
        elif bundles:
            hv, hc = Verdict.UNKNOWN, 0.2
            hnote = "The bundle is neither Hermes bytecode nor plain text."
        else:
            hv, hc = Verdict.UNKNOWN, 0.1
            hnote = "No JS bundle file was found."
        findings.append(common.make_finding(
            "engine.hermes", hv, hc, "react_native", "Hermes bytecode", "React Native: " + hnote,
            {"engine": "React Native", "hermes": hv.value, "version": ", ".join(str(v) for v in sorted(set(versions))) or "unknown",
             "bundles": len(bundles)}, ev))
        sv, sc, ss = common.verdict_from_tally(tally, len(bundles))
        findings.append(common.script_finding(
            "react_native", "React Native", scripts, sv, sc, ss,
            ev if sv != Verdict.NA else [],
            "Hermes bytecode is compiled code, not encryption." if hermes_n else ""))
        return CheckerResult(findings=findings, data=data, status=Status.OK)
