"""Stage ``engine.fingerprint`` (WP7): engine-independent capability profile of the app.

Dimensions: render API, shader formats, script VMs, physics, audio, animation, network, asset formats,
unknown containers and the host shape (see ``engines/fingerprint.py``). Binary-based evidence is read with
``skip_encrypted=True``; when the code is FairPlay-encrypted the profile falls back to linked libraries,
imported symbols, files and directories, the stage becomes ``partial`` and the finding says so.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List

from ..context import AnalysisContext
from ..engines.containers import DEFAULT_DEEP_LIMIT
from ..engines.fingerprint import DIMENSIONS, build_fingerprint
from ..engines.scoring import collect_evidence
from ..models import Evidence, Finding, StageResult, Verdict
from ..registry import register

NAME = 'engine.fingerprint'
ENV_CONTAINER_LIMIT = "IPA_ANALYZER_CONTAINER_LIMIT"
LIMITED_REMEDIATION = ("The main binary is FairPlay-encrypted, so strings / symbols inside it cannot be read. Provide a "
                       "decrypted IPA for binary-based detection; this tool never decrypts.")


def container_limit(ctx: AnalysisContext) -> int:
    v = getattr(ctx.cfg, "container_deep_limit", None)
    if v is None:
        try:
            v = int(os.environ.get(ENV_CONTAINER_LIMIT, ""))
        except ValueError:
            v = None
    return int(v) if isinstance(v, int) and v >= 0 else DEFAULT_DEEP_LIMIT


def profile_findings(fp: Any, extra: Dict[str, Any], limited: bool) -> List[Finding]:
    d = fp.to_dict()
    counts = {k: len(d[k]) for k in DIMENSIONS[1:] + ("containers",)}
    counts["render"] = len(d["render"])
    found = sum(counts.values())
    ev: List[Evidence] = []
    for dim in ("render", *DIMENSIONS[1:]):
        items = list(d["render"].values()) if dim == "render" else d[dim]
        for h in items[:2]:
            if h["evidence"]:
                e = h["evidence"][0]
                ev.append(Evidence(e["kind"], e["ref"], "%s: %s - %s" % (dim, h["name"] or h["id"], e["detail"])))
    ev = ev[:10]
    verdict = Verdict.YES if found else Verdict.UNKNOWN
    conf = (0.7 if found else 0.3)
    if limited:
        conf = min(conf, 0.5)
    fnd = Finding("engine.fingerprint", verdict, conf, "Engine capability profile built", d["summary_text"],
                  params=dict(counts, summary=d["summary_text"], limited=limited,
                              render=", ".join(sorted(d["render"])) or "-"),
                  evidence=ev, remediation=LIMITED_REMEDIATION if limited else "", tags=["engine"])
    out = [fnd]
    conts = d["containers"]
    cinfo = extra.get("containers", {})
    suspicious = [c for c in conts if c["extra"].get("verdict") in ("custom_format", "encrypted_suspected")]
    cev = [Evidence("file", c["id"], "%s (%s)" % (c["extra"].get("verdict"), "; ".join(e["detail"] for e in c["evidence"][:2])))
           for c in suspicious[:6]]
    if not cinfo.get("candidates_total") and not conts:
        cv, cc, text = Verdict.NA, 0.5, "No unknown or custom containers found"
    elif suspicious:
        cv, cc = Verdict.SUSPECTED, max(c["confidence"] for c in suspicious)
        text = ("%d container(s) look custom or encrypted (compressed data is not encrypted data; internal structure "
                "decides)" % len(suspicious))
    elif conts and all(c["extra"].get("verdict") in ("compressed", "plain") for c in conts):
        cv, cc, text = Verdict.NO, 0.5, "Analysed containers are compressed or plain, not encrypted-looking"
    else:
        cv, cc, text = Verdict.UNKNOWN, 0.3, "Unknown containers could not be classified"
    out.append(Finding("engine.container.unknown", cv, cc, "Unknown containers analysed", text,
                       params={"suspicious": len(suspicious), "analyzed": cinfo.get("analyzed", 0),
                               "candidates": cinfo.get("candidates_total", 0), "clusters": cinfo.get("header_clusters", 0)},
                       evidence=cev, tags=["engine", "container"]))
    return out


@register(name='engine.fingerprint', requires=('inventory',), after=('macho', 'meta'))
class EngineFingerprintStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        if ctx.source is None:
            return StageResult.skipped(NAME, "no input source is open")
        if not ctx.results.get("inventory"):
            return StageResult.skipped(NAME, "inventory result is not available")
        bundle = collect_evidence(ctx)
        fp, extra, warnings = build_fingerprint(ctx, bundle, container_limit=container_limit(ctx))
        limited = bool(extra.get("binary_limited"))
        data = fp.to_dict()
        data["extra"] = extra
        findings = profile_findings(fp, extra, limited)
        for note in bundle.notes[:5]:
            warnings.append("binary evidence: " + note)
        reasons: List[str] = []
        if ctx.results.get("macho") is None:
            reasons.append("macho unavailable: binaries were parsed directly from the inventory")
        if limited:
            warnings.append("binary is FairPlay-encrypted: binary-based detection is limited "
                            "(libraries, imported symbols, files and directories were used)")
            reasons.append("binary encrypted: binary-based fingerprint limited")
        if reasons:
            return StageResult.partial(NAME, data, findings, warnings, reason="; ".join(reasons))
        return StageResult.ok(NAME, data, findings, warnings)
