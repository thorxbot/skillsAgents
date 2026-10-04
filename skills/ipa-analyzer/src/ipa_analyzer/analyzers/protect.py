"""Stage ``protect`` (WP4): FairPlay / code-signing / hardening summary plus anti-debug, jailbreak-detection and
obfuscation *characteristics*.

Everything here is derived from the ``macho`` stage records, a second light pass over the binaries (imported
symbols and, where readable, C strings) and references to other stages' findings. Hits are never conclusions:
anti-debug / jailbreak verdicts stop at ``suspected``. Resource-level encryption verdicts of the engine stages are
only *referenced* (``protection_refs``), not re-judged.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from ..context import AnalysisContext
from ..macho import MachOError, parse
from ..models import Evidence, Finding, StageResult, Verdict
from ..protect import load_rules, score_hits, scan_slice, summarize_fairplay, summarize_obfuscation
from ..registry import register

log = logging.getLogger(__name__)

NAME = "protect"
_REF_IDS = ("meta.fairplay_container", "meta.signature_integrity", "unity.metadata.encrypted", "unity.binary.fairplay",
            "unity.assetbundle.encryption", "unity.mono.dll_encrypted", "unity.hotfix.script_protection",
            "engine.pak.encrypted", "engine.script.encrypted", "engine.resource.encrypted")
_MAX_EVIDENCE = 10


def _pref_slice(binary: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    slices = [s for s in binary.get("slices") or [] if isinstance(s, dict)]
    return next((s for s in slices if str(s.get("arch", "")).startswith("arm64")), slices[0] if slices else None)


def _tri(values: List[Optional[bool]]) -> Optional[bool]:
    known = [v for v in values if v is not None]
    if not known:
        return None
    if all(known):
        return True
    if not any(known):
        return False
    return None


def _hardening(binaries: List[Dict[str, Any]]) -> Dict[str, Any]:
    main = next((b for b in binaries if b.get("role") == "main"), None)

    def block(bins: List[Dict[str, Any]]) -> Dict[str, Optional[bool]]:
        sl = [_pref_slice(b) for b in bins]
        sl = [s for s in sl if s]
        return {"pie": _tri([s.get("is_pie") for s in sl]), "stack_canary": _tri([s.get("has_stack_canary") for s in sl]),
                "arc": _tri([s.get("uses_arc") for s in sl]), "stripped": _tri([s.get("stripped") for s in sl])}

    return {"main": block([main]) if main else {"pie": None, "stack_canary": None, "arc": None, "stripped": None},
            "all": block(binaries)}


def _codesign(binaries: List[Dict[str, Any]], meta: Dict[str, Any]) -> Dict[str, Any]:
    main = next((b for b in binaries if b.get("role") == "main"), None)
    sl = _pref_slice(main) if main else None
    out: Dict[str, Any] = {"signed": None, "team_id": None, "signature_type": None, "get_task_allow": None,
                           "entitlements_keys": []}
    if sl is None:
        return out
    out["signed"] = bool(sl.get("signed"))
    out["team_id"] = sl.get("team_id")
    sig = sl.get("signature") if isinstance(sl.get("signature"), dict) else None
    out["signature_type"] = sig.get("signature_kind") if sig else ("none" if not sl.get("signed") else None)
    ents = sl.get("entitlements") if isinstance(sl.get("entitlements"), dict) else None
    if ents is not None:
        gta = ents.get("get-task-allow")
        out["get_task_allow"] = bool(gta) if gta is not None else False
    out["entitlements_keys"] = list(sl.get("entitlements_keys") or [])
    dist = (meta.get("distribution") or {}).get("type") if isinstance(meta.get("distribution"), dict) else None
    if dist:
        out["distribution"] = dist
    return out


def _scan_all(ctx: AnalysisContext, binaries: List[Dict[str, Any]], rules: Any, warnings: List[str]
              ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], int, int, int]:
    """``(ad_hits, jb_hits, scanned, encrypted, failed)`` over all binaries."""
    ad: List[Dict[str, Any]] = []
    jb: List[Dict[str, Any]] = []
    scanned = encrypted = failed = 0
    if ctx.source is None:
        return ad, jb, 0, 0, 0
    for b in binaries:
        path = b.get("path", "")
        local = ctx.extract([path]).get(path)
        if local is None:
            warnings.append("cannot extract %s for protection scanning" % path)
            failed += 1
            continue
        try:
            with parse(local) as mf:
                sl = mf.select_slice() or (mf.slices[0] if mf.slices else None)
                if sl is None:
                    continue
                res = scan_slice(sl, path, rules)
                scanned += 1
                if sl.is_encrypted:
                    encrypted += 1
        except (MachOError, OSError, ValueError, MemoryError) as exc:
            warnings.append("cannot scan %s: %s" % (path, exc))
            failed += 1
            continue
        ad.extend(res.ad_hits)
        jb.extend(res.jb_hits)
    return ad, jb, scanned, encrypted, failed


def _hit_evidence(hits: List[Dict[str, Any]]) -> List[Evidence]:
    best: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for h in hits:
        best.setdefault((h["kind"], h["pattern"]), h)
    ordered = sorted(best.values(), key=lambda h: (-h["weight"], h["pattern"]))
    return [Evidence("symbol" if h["kind"] == "symbol" else "string" if h["kind"] == "string" else "plist_key", h["ref"],
                     "%s %s (weight %.2f)" % (h["kind"], h["pattern"], h["weight"])) for h in ordered[:_MAX_EVIDENCE]]


def _pattern_list(hits: List[Dict[str, Any]]) -> str:
    seen: List[str] = []
    for h in sorted(hits, key=lambda h: (-h["weight"], h["pattern"])):
        if h["pattern"] not in seen:
            seen.append(h["pattern"])
    return ", ".join(seen[:8]) or "-"


@register(name='protect', requires=('inventory',), after=('macho', 'engine.unity', 'engine.unity.hotfix', 'engine.other', 'libs'))
class ProtectStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        macho = ctx.results.get("macho")
        meta = ctx.results.get("meta") or {}
        inv = ctx.results.get("inventory") or {}
        warnings: List[str] = []
        rules = load_rules()
        warnings.extend(rules.warnings)
        binaries = [b for b in (macho or {}).get("binaries") or [] if isinstance(b, dict) and b.get("slices")]

        sc_info: Optional[bool] = None
        fc = meta.get("fairplay_container")
        if isinstance(fc, dict) and fc.get("sc_info_present") is not None:
            sc_info = bool(fc["sc_info_present"])
        elif isinstance((inv.get("structure_hints") or {}).get("has"), dict):
            sc_info = bool(inv["structure_hints"]["has"].get("SC_Info"))
        fp = summarize_fairplay(macho, sc_info)
        codesign = _codesign(binaries, meta)
        hardening = _hardening(binaries)

        ad_hits, jb_hits, scanned, enc_scanned, failed = _scan_all(ctx, binaries, rules, warnings)
        for scheme in (meta.get("query_schemes") or []):
            if isinstance(scheme, str) and scheme.lower() in rules.jb_schemes:
                jb_hits.append({"kind": "query_scheme", "ref": "Info.plist:LSApplicationQueriesSchemes", "pattern": scheme.lower(),
                                "weight": rules.jb_schemes[scheme.lower()]})
        scheme_scan = bool(meta)
        readable = scanned > 0 and enc_scanned == 0
        ad_v, ad_c, ad_score, ad_case = score_hits(ad_hits, rules, readable=readable, scanned=scanned > 0)
        jb_v, jb_c, jb_score, jb_case = score_hits(jb_hits, rules, readable=readable, scanned=scanned > 0 or scheme_scan)

        unity = ctx.results.get("engine.unity")
        ob_v, ob_c, ob_case, ob_data = summarize_obfuscation(unity if isinstance(unity, dict) else None, rules.obfuscation)
        refs = [{"id": f.id, "verdict": f.verdict.value} for f in ctx.findings if f.id in _REF_IDS]

        data: Dict[str, Any] = {
            "fairplay": fp.to_data(), "codesign": codesign, "hardening": hardening,
            "antidebug": {"hits": [{"kind": h["kind"], "ref": h["ref"], "pattern": h["pattern"]} for h in ad_hits],
                          "score": ad_score, "scanned_binaries": scanned, "encrypted_binaries_scanned": enc_scanned},
            "jailbreak_detect": {"hits": [{"kind": h["kind"], "ref": h["ref"], "pattern": h["pattern"]} for h in jb_hits],
                                 "score": jb_score, "scanned_binaries": scanned, "encrypted_binaries_scanned": enc_scanned},
            "obfuscation": ob_data, "packer": {}, "protection_refs": refs}
        findings = [
            self._fairplay_finding(fp),
            self._codesign_finding(codesign),
            self._stripped_finding(hardening, binaries),
            self._hit_finding("protect.antidebug", "Anti-debugging features", ad_v, ad_c, ad_case, ad_hits, scanned, enc_scanned,
                              "ptrace / sysctl / task_get_exception_ports style anti-debug characteristics", "反调试"),
            self._hit_finding("protect.jailbreak_detect", "Jailbreak-detection features", jb_v, jb_c, jb_case, jb_hits, scanned,
                              enc_scanned, "jailbreak path / URL-scheme characteristics", "越狱检测"),
            self._obfuscation_finding(ob_v, ob_c, ob_case, ob_data),
            Finding("protect.packer", Verdict.NA, 0.0, "Commercial packer / protector",
                    "No verified packer or protector signatures are bundled with this version, so none was checked.",
                    {}, [], "", tags=["protect"]),
        ]
        if macho is None:
            return StageResult.partial(NAME, data, findings, warnings, reason="macho results unavailable")
        if failed:
            return StageResult.partial(NAME, data, findings, warnings, reason="%d binary scan(s) failed" % failed)
        return StageResult.ok(NAME, data, findings, warnings)

    # -- findings ----------------------------------------------------------------------------
    @staticmethod
    def _fairplay_finding(fp: Any) -> Finding:
        evidence = [Evidence("macho", p, "cryptid != 0") for p in fp.encrypted_binaries[:_MAX_EVIDENCE]]
        params = {"scope": fp.scope, "encrypted": len(fp.encrypted_binaries), "total": fp.total_binaries,
                  "case": fp.case, "case_en": fp.text_en, "case_zh": fp.text_zh, "sc_info": fp.sc_info_present,
                  "remediation_zh": "请提供已解密的 IPA(由所有者从自己的设备导出);本工具不提供 FairPlay 解密。" if fp.remediation else ""}
        return Finding("protect.fairplay", fp.verdict, fp.confidence, "FairPlay encryption", fp.text_en, params, evidence,
                       fp.remediation, tags=["protect", "fairplay"])

    @staticmethod
    def _codesign_finding(cs: Dict[str, Any]) -> Finding:
        if cs["signed"] is None:
            return Finding("protect.codesign", Verdict.UNKNOWN, 0.2, "Code signature",
                           "The main binary was not analysed, so its code signature is unknown.", {}, [], "", tags=["protect"])
        params = {"signed": cs["signed"], "team_id": cs["team_id"] or "-", "signature_type": cs["signature_type"] or "-",
                  "get_task_allow": cs["get_task_allow"], "distribution": cs.get("distribution", "-")}
        text = "Main binary signed: %s; signature type: %s; team id: %s; get-task-allow: %s." % (
            "yes" if cs["signed"] else "no", params["signature_type"], params["team_id"],
            {True: "true", False: "false", None: "n/a"}[cs["get_task_allow"]])
        ev = [Evidence("macho", "main binary", "signature_kind=%s team_id=%s" % (params["signature_type"], params["team_id"]))]
        return Finding("protect.codesign", Verdict.YES if cs["signed"] else Verdict.NO, 0.9, "Code signature", text, params, ev, "",
                       tags=["protect", "codesign"])

    @staticmethod
    def _stripped_finding(h: Dict[str, Any], binaries: List[Dict[str, Any]]) -> Finding:
        main = h["main"]
        params = {"main_stripped": main["stripped"], "all_stripped": h["all"]["stripped"], "main_pie": main["pie"],
                  "main_stack_canary": main["stack_canary"], "main_arc": main["arc"]}
        if main["stripped"] is None:
            return Finding("protect.stripped", Verdict.UNKNOWN, 0.2, "Symbol stripping",
                           "Symbol stripping of the main binary could not be determined.", params, [], "", tags=["protect"])
        text = "Main binary symbols stripped: %s; PIE: %s; stack protector: %s; ARC: %s." % tuple(
            {True: "yes", False: "no", None: "n/a"}[main[k]] for k in ("stripped", "pie", "stack_canary", "arc"))
        return Finding("protect.stripped", Verdict.YES if main["stripped"] else Verdict.NO, 0.7, "Symbol stripping", text, params,
                       [Evidence("macho", "main binary", "symbol table heuristic")], "", tags=["protect"])

    @staticmethod
    def _hit_finding(fid: str, title: str, verdict: Verdict, conf: float, case: str, hits: List[Dict[str, Any]], scanned: int,
                     enc: int, what: str, what_zh: str = "") -> Finding:
        params = {"case": case, "patterns": _pattern_list(hits), "hits": len({(h["kind"], h["pattern"]) for h in hits}),
                  "scanned": scanned, "encrypted": enc}
        texts = {
            "hit": "Characteristic hits (not a conclusion): %s." % params["patterns"],
            "weak": "Only weak indicators found (%s); not enough to suggest the feature." % params["patterns"],
            "none": "No %s found in the readable code (absence of known features is not proof)." % what,
            "unreadable": "No %s found among imported symbols, but %d of %d scanned binaries are FairPlay-encrypted so "
                          "their strings could not be read." % (what, enc, scanned),
            "no_data": "No binary data available to look for %s." % what}
        zh = {
            "hit": "命中以下特征(特征命中,并非结论):%s。" % params["patterns"],
            "weak": "仅发现弱特征(%s),不足以认为存在该机制。" % params["patterns"],
            "none": "在可读的代码中未发现已知的%s特征(没有特征不等于确认没有)。" % what_zh,
            "unreadable": "导入符号中未发现%s特征,但 %d/%d 个已扫描二进制被 FairPlay 加密,其字符串无法读取。" % (what_zh, enc, scanned),
            "no_data": "没有可用的二进制数据来检查%s特征。" % what_zh}
        params["case_zh"] = zh[case]
        remediation = ""
        params["remediation_zh"] = ""
        if enc:
            remediation = "Provide a decrypted IPA for string-level checks; this tool never decrypts."
            params["remediation_zh"] = "请提供已解密的 IPA 以做字符串级检查;本工具不提供解密。"
        return Finding(fid, verdict, conf, title, texts[case], params, _hit_evidence(hits), remediation, tags=["protect"])

    @staticmethod
    def _obfuscation_finding(verdict: Verdict, conf: float, case: str, data: Dict[str, Any]) -> Finding:
        ids = data.get("unity_identifiers") or {}
        params = {"case": case, "score": ids.get("score", "-"), "level": ids.get("level") or "-"}
        zh = {"dump_obfuscated": "Unity IL2CPP 标识符疑似被混淆(分数 %s,等级 %s)。" % (params["score"], params["level"]),
              "dump_clean": "Unity IL2CPP 标识符看起来没有被混淆(分数 %s)。" % params["score"],
              "no_data": "无数据:标识符混淆只能依据已解密的二进制或 il2cpp dump 判断。"}
        params["case_zh"] = zh[case]
        texts = {"dump_obfuscated": "Unity IL2CPP identifiers look obfuscated (score %s, level %s)." % (params["score"], params["level"]),
                 "dump_clean": "Unity IL2CPP identifiers do not look obfuscated (score %s)." % params["score"],
                 "no_data": "No data: identifier obfuscation can only be assessed from a decrypted binary or an il2cpp dump."}
        return Finding("protect.obfuscation", verdict, conf, "Code obfuscation", texts[case], params,
                       [Evidence("tool_output", "engine.unity:dump", "identifier statistics")] if ids else [], "", tags=["protect"])
