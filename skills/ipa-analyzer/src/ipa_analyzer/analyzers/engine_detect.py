"""Stage ``engine.detect`` (WP7): known-engine detection, wrapper / host analysis, in-house engine judgement.

Signatures are data (``data/engines/*.json`` plus user definitions); scoring is in ``engines/scoring.py``.
Evidence from Mach-O files is read with ``skip_encrypted=True``; for FairPlay-encrypted binaries the
detection uses files, directories, linked libraries and imported symbols and the stage reports ``partial``.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..context import AnalysisContext
from ..engines.api import DetectResult, FingerprintResult
from ..engines.custom import judge_custom
from ..engines.fingerprint import build_fingerprint
from ..engines.scoring import collect_evidence, detect_engines, infer_languages
from ..engines.signatures import load_signatures
from ..models import Evidence, Finding, StageResult, Verdict
from ..registry import register
from .engine_fingerprint import LIMITED_REMEDIATION, container_limit

NAME = 'engine.detect'


def _findings(det: DetectResult, limited: bool) -> List[Finding]:
    out: List[Finding] = []
    p = det.primary
    if p is not None:
        ev = [Evidence(e.kind, e.ref, e.detail) for e in p.evidence[:8]]
        out.append(Finding("engine.primary", Verdict.YES if p.confirmed else Verdict.SUSPECTED, p.confidence,
                           "Primary engine: %s" % p.name,
                           "%s (%s) confirmed with %d matching signals" % (p.name, p.family or p.id, len(p.signals_matched)),
                           params={"name": p.name, "id": p.id, "family": p.family, "confidence": round(p.confidence, 2),
                                   "signals": len(p.signals_matched), "version": p.extra.get("version_hint", "")},
                           evidence=ev, remediation=LIMITED_REMEDIATION if limited else "", tags=["engine"]))
    else:
        best = det.candidates[0] if det.candidates else None
        out.append(Finding("engine.primary", Verdict.UNKNOWN, 0.3, "No known engine confirmed",
                           "No known engine reached its confirmation threshold" +
                           ("; best candidate: %s (%.2f)" % (best.name, best.confidence) if best else ""),
                           params={"best": best.name if best else "-", "best_confidence": round(best.confidence, 2) if best else 0},
                           evidence=[Evidence(e.kind, e.ref, e.detail) for e in (best.evidence[:4] if best else [])],
                           remediation=LIMITED_REMEDIATION if limited else "", tags=["engine"]))
    langs = det.languages
    out.append(Finding("engine.language", Verdict.YES if langs else Verdict.UNKNOWN, 0.7 if langs else 0.2,
                       "Languages: %s" % (", ".join(l["lang"] for l in langs[:6]) or "unknown"),
                       "Detected languages: %s" % (", ".join("%s (%.2f)" % (l["lang"], l["confidence"]) for l in langs[:6]) or "none"),
                       params={"languages": ", ".join(l["lang"] for l in langs[:6]) or "-"},
                       evidence=[Evidence(e["kind"], e["ref"], e["detail"]) for l in langs[:3] for e in l["evidence"][:1]],
                       tags=["engine", "language"]))
    c = det.custom
    cev = [Evidence(e["kind"], e["ref"], e.get("detail", "")) for e in c.get("evidence", [])][:8]
    cond = c.get("conditions", {})
    ctext = {"yes": "Evidence points to an in-house engine", "suspected": "Possibly an in-house or modified engine",
             "no": "No in-house engine indicated", "unknown": "In-house engine status could not be determined"}[c["verdict"]]
    out.append(Finding("engine.custom", Verdict(c["verdict"]), float(c.get("confidence", 0)), ctext,
                       "%s (score %s; render=%s, script_vm=%s, container=%s, physics=%s, cpp_heavy=%s)" % (
                           ctext, cond.get("score"), cond.get("render_api"), cond.get("script_vm"),
                           cond.get("custom_container"), cond.get("physics_lib"), cond.get("cpp_heavy")),
                       params={"score": cond.get("score"), "kind": c.get("kind", ""), "deviations": "; ".join(c.get("deviations", []))},
                       evidence=cev, remediation=(c["next_steps"][0]["text"] if c.get("next_steps") else ""), tags=["engine", "custom"]))
    w = det.wrapper
    if w:
        out.append(Finding("engine.wrapper", Verdict.YES, 0.7, "Host / embedded engines",
                           "Host: %s; embedded: %s" % (w["host"]["name"], ", ".join(e["name"] for e in w["embedded"])),
                           params={"host": w["host"]["name"], "embedded": ", ".join(e["name"] for e in w["embedded"])},
                           evidence=[Evidence("heuristic", w["host"]["id"], "host framework confirmed")], tags=["engine", "wrapper"]))
    else:
        out.append(Finding("engine.wrapper", Verdict.NA, 0.5, "No host / embedded engine combination",
                           "No wrapper / embedded engine structure found", tags=["engine", "wrapper"]))
    return out


@register(name='engine.detect', requires=('inventory',), after=('macho', 'meta', 'engine.fingerprint'))
class EngineDetectStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        if ctx.source is None:
            return StageResult.skipped(NAME, "no input source is open")
        if not ctx.results.get("inventory"):
            return StageResult.skipped(NAME, "inventory result is not available")
        bundle = collect_evidence(ctx)
        sigset = load_signatures(engines_user_dir=ctx.cfg.engines_user_dir)
        warnings: List[str] = list(sigset.warnings)
        det = detect_engines(bundle, sigset)

        fp_data = ctx.results.get("engine.fingerprint")
        if fp_data:
            fp = FingerprintResult.from_dict(fp_data)
        else:
            fp, _extra, fp_warn = build_fingerprint(ctx, bundle, container_limit=container_limit(ctx))
            warnings += fp_warn
        vis = bundle.visibility
        limited = bool(vis.get("limited"))
        det.custom = judge_custom(fp, det, binary_limited=limited, binaries_scanned=int(vis.get("binaries_scanned") or 0),
                                  sigset=sigset)
        det.languages = infer_languages(bundle, det, sigset, [h.id for h in fp.script_vms])
        det.extra = {"visibility": dict(vis), "signatures_loaded": len(sigset.signatures),
                     "user_signatures": sorted(sigset.user_ids),
                     "profile_source": "engine.fingerprint" if fp_data else "computed"}
        data: Dict[str, Any] = det.to_dict()
        findings = _findings(det, limited)
        for note in bundle.notes[:5]:
            warnings.append("binary evidence: " + note)
        reasons: List[str] = []
        if ctx.results.get("macho") is None:
            reasons.append("macho unavailable: binaries were parsed directly from the inventory")
        if limited:
            warnings.append("binary is FairPlay-encrypted: binary-based detection is limited "
                            "(files, directories, linked libraries and imported symbols were used)")
            reasons.append("binary encrypted: binary-based detection limited")
        if reasons:
            return StageResult.partial(NAME, data, findings, warnings, reason="; ".join(reasons))
        return StageResult.ok(NAME, data, findings, warnings)

