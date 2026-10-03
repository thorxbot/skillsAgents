"""Report view-model: defensive accessors, stage explanations, executive summary, report enrichment.

Everything here works on the *report dict* (``Report.to_dict()`` or a loaded ``report.json``) so a
report can be re-rendered later without the original ``AnalysisContext``. Only ``enrich_report``
needs ``ctx.results`` (to add data the base ``pipeline.build_report`` does not carry over).

Language-specific text is produced through a translate callable ``t(key, default="", **params)``
(``Catalog.t``); the stored ``report["summary"]`` object is language neutral.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

Translate = Callable[..., str]

__all__ = [
    "d_", "l_", "g", "stage_map", "stage_ok", "findings_of", "first_finding", "is_unity_app", "custom_engine",
    "StageNote", "explain_stage", "localize_reason", "build_summary", "enrich_report", "exec_rows",
    "console_text", "exit_code_for", "fmt_conf", "dump_state", "RISK_FINDING_IDS", "PROTECTION_ORDER",
    "UNITY_STAGES", "SECTION_STAGES", "STAGE_ORDER",
]

UNITY_STAGES = ("engine.unity", "engine.unity.hotfix")

STAGE_ORDER = ("ingest", "inventory", "meta", "macho", "engine.fingerprint", "engine.detect", "engine.other",
               "engine.unity", "engine.unity.hotfix", "libs", "protect", "classify", "report")

# Report section -> stages whose data it needs (used for "not run" notices).
SECTION_STAGES: Dict[str, Tuple[str, ...]] = {
    "basic": ("meta",),
    "type": ("classify",),
    "structure_tree": ("inventory",),
    "structure_macho": ("macho",),
    "resources": ("inventory",),
    "libs": ("libs",),
    "protect": ("protect",),
    "engine_fingerprint": ("engine.fingerprint",),
    "engine_detect": ("engine.detect",),
    "unity": ("engine.unity",),
    "hotfix": ("engine.unity.hotfix",),
    "other": ("engine.other",),
    "privacy": ("meta",),
}

# Findings for which verdict ``yes`` means "protected / encrypted / obstacle" (rendered as a warning
# badge). Every other finding is informational ("yes" = detected / succeeded).
RISK_FINDING_IDS = frozenset({
    "protect.fairplay", "protect.stripped", "protect.antidebug", "protect.jailbreak_detect",
    "protect.obfuscation", "protect.packer", "unity.metadata.encrypted", "unity.binary.fairplay",
    "unity.assetbundle.encryption", "unity.mono.dll_encrypted", "unity.il2cpp.names_obfuscated",
    "unity.hotfix.script_protection", "engine.pak.encrypted", "engine.script.encrypted",
    "engine.resource.encrypted",
})

# Display order of protection findings (unlisted ones follow alphabetically).
PROTECTION_ORDER = (
    "protect.fairplay", "unity.binary.fairplay", "meta.fairplay_container", "protect.codesign",
    "meta.signature_integrity", "protect.stripped", "protect.antidebug", "protect.jailbreak_detect",
    "protect.obfuscation", "protect.packer", "unity.metadata.encrypted", "unity.assetbundle.encryption",
    "unity.mono.dll_encrypted", "unity.hotfix.script_protection", "engine.pak.encrypted",
    "engine.script.encrypted", "engine.resource.encrypted",
)

# Protections listed in the "key protections" row of the summary (FairPlay has its own row).
_KEY_PROTECTIONS = tuple(i for i in PROTECTION_ORDER if i not in (
    "protect.fairplay", "unity.binary.fairplay", "meta.fairplay_container", "protect.codesign",
    "meta.signature_integrity"))


# --- accessors -----------------------------------------------------------------------------------
def d_(x: Any) -> Dict[str, Any]:
    return x if isinstance(x, dict) else {}


def l_(x: Any) -> List[Any]:
    return x if isinstance(x, list) else []


def g(obj: Any, *path: Any, default: Any = None) -> Any:
    """Safe nested lookup: ``g(report, "app", "bundle_id")``; ``None`` anywhere yields ``default``."""
    cur = obj
    for p in path:
        if isinstance(cur, dict):
            cur = cur.get(p)
        elif isinstance(cur, list) and isinstance(p, int) and -len(cur) <= p < len(cur):
            cur = cur[p]
        else:
            return default
        if cur is None:
            return default
    return cur


def stage_map(report: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {s["name"]: s for s in l_(report.get("stages")) if isinstance(s, dict) and "name" in s}


def stage_ok(report: Mapping[str, Any], name: str) -> bool:
    s = stage_map(report).get(name)
    return bool(s) and s.get("status") in ("ok", "partial")


def findings_of(report: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """All findings (``findings`` plus anything only present in ``protection.findings``), de-duplicated."""
    seen = set()
    out: List[Dict[str, Any]] = []
    for f in l_(report.get("findings")) + l_(g(report, "protection", "findings", default=[])):
        if not isinstance(f, dict):
            continue
        key = (f.get("id"), f.get("verdict"), f.get("title"), tuple(sorted(f.get("tags") or [])))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def first_finding(report: Mapping[str, Any], fid: str) -> Optional[Dict[str, Any]]:
    for f in findings_of(report):
        if f.get("id") == fid:
            return f
    return None


def fmt_conf(c: Any, t: Translate) -> str:
    """``0.85`` -> ``0.85 high`` with a localised level word."""
    try:
        v = float(c)
    except (TypeError, ValueError):
        return "-"
    level = "high" if v >= 0.8 else "medium" if v >= 0.5 else "low" if v >= 0.25 else "very_low"
    return "%.2f %s" % (v, t("report.conf." + level, level))


# --- engine helpers ------------------------------------------------------------------------------
def is_unity_app(report: Mapping[str, Any]) -> Optional[bool]:
    """``True`` / ``False`` when the engine stages say so, ``None`` when it cannot be told."""
    det = d_(g(report, "engine_details", "detect"))
    prim = det.get("primary") if det else g(report, "structure", "engine", "primary")
    cands = l_(det.get("candidates")) if det else l_(g(report, "structure", "engine", "candidates", default=[]))
    entries = [e for e in ([prim] + cands) if isinstance(e, dict)]
    best = 0.0
    confirmed = False
    for e in entries:
        if e.get("id") == "unity":
            best = max(best, float(e.get("confidence") or 0.0))
            confirmed = confirmed or bool(e.get("confirmed"))
    if confirmed or best >= 0.5:
        return True
    if best > 0:
        return None
    if det and stage_ok(report, "engine.detect"):
        return False
    if stage_ok(report, "engine.unity") and report.get("engine_details", {}).get("unity"):
        return True
    return None


def custom_engine(report: Mapping[str, Any]) -> Dict[str, Any]:
    """``engine.detect.custom`` block (empty dict when absent)."""
    return d_(g(report, "engine_details", "detect", "custom"))


# --- stage explanations --------------------------------------------------------------------------
_DEP_RE = re.compile(r"^dependency (?P<dep>\S+) (?P<what>skipped|failed|not available)$")


@dataclass
class StageNote:
    status: str        # ok | partial | skipped | failed | missing
    kind: str          # ok | partial | failed | missing | not_unity | dep_skipped | dep_failed | dep_unavailable |
    #                    disabled | not_selected | not_implemented | reason
    text: str
    hint: str = ""
    root: Optional[str] = None

    @property
    def ran(self) -> bool:
        return self.status in ("ok", "partial")


def localize_reason(reason: str, name: str, t: Translate) -> Tuple[str, str, str]:
    """``(kind, text, hint)`` for a stage's own (non-dependency) skip reason."""
    r = (reason or "").strip()
    low = r.lower()
    if low == "disabled by --skip":
        return "disabled", t("report.stage.disabled"), t("report.hint.rerun_skip", stage=name)
    if low == "not selected by --stages":
        return "not_selected", t("report.stage.not_selected"), t("report.hint.rerun_stages", stage=name)
    if low == "not implemented":
        return "not_implemented", t("report.stage.not_implemented"), ""
    hint = ""
    if "offline" in low:
        hint = t("report.hint.offline")
    elif "dotnet" in low or ".net" in low:
        hint = t("report.hint.dotnet")
    return "reason", t("report.stage.reason", reason=r or "-"), hint


def _clip(s: Any, n: int = 140) -> str:
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _root_cause(name: str, stages: Mapping[str, Dict[str, Any]]) -> Tuple[str, Optional[Dict[str, Any]]]:
    """Follow ``dependency X skipped`` chains to the stage that actually caused the skip."""
    seen = {name}
    cur = stages.get(name)
    root = name
    while cur is not None and cur.get("status") == "skipped":
        m = _DEP_RE.match(cur.get("reason") or "")
        if not m or m.group("dep") in seen:
            break
        dep = m.group("dep")
        seen.add(dep)
        root = dep
        cur = stages.get(dep)
    return root, cur


def explain_stage(name: str, report: Mapping[str, Any], t: Translate) -> StageNote:
    """Human-readable status of stage ``name`` for "not run" notices and the appendix table.

    Chains of ``dependency X skipped`` are folded to the root cause; Unity-only stages on a non-Unity
    package read "not a Unity app, skipped".
    """
    stages = stage_map(report)
    st = stages.get(name)
    if st is None:
        return StageNote("missing", "missing", t("report.stage.missing"), t("report.hint.missing"))
    status = str(st.get("status"))
    if status == "ok":
        return StageNote("ok", "ok", "")
    if status == "partial":
        why = st.get("reason") or "; ".join(_clip(w, 80) for w in l_(st.get("warnings"))[:2])
        return StageNote("partial", "partial", t("report.stage.partial", reason=why or "-"))
    if status == "failed":
        return StageNote("failed", "failed", t("report.stage.failed", error=_clip(st.get("error") or "-")),
                         t("report.hint.verbose"))
    # skipped
    unity = is_unity_app(report)
    if name in UNITY_STAGES and unity is False:
        return StageNote("skipped", "not_unity", t("report.stage.not_unity"), "", "engine.unity")
    reason = st.get("reason") or ""
    if _DEP_RE.match(reason):
        root, rst = _root_cause(name, stages)
        if root in UNITY_STAGES and unity is False:
            return StageNote("skipped", "not_unity", t("report.stage.not_unity"), "", root)
        if rst is None:
            return StageNote("skipped", "dep_unavailable", t("report.stage.dep_unavailable", root=root),
                             t("report.hint.missing"), root)
        if rst.get("status") == "failed":
            return StageNote("skipped", "dep_failed",
                             t("report.stage.dep_failed", root=root, why=_clip(rst.get("error") or "-", 100)),
                             t("report.hint.fix_upstream", root=root), root)
        rk, rtext, rhint = localize_reason(str(rst.get("reason") or ""), root, t)
        return StageNote("skipped", "dep_skipped", t("report.stage.dep_skipped", root=root, why=rtext),
                         rhint or t("report.hint.see_upstream", root=root), root)
    kind, text, hint = localize_reason(reason, name, t)
    return StageNote("skipped", kind, text, hint)


def not_run_line(note: StageNote, t: Translate) -> str:
    """``Not run: <reason> (<advice>)`` (without Markdown markers)."""
    if note.hint:
        return t("report.not_run_hint", text=note.text, hint=note.hint)
    return t("report.not_run", text=note.text)


# --- dump state ----------------------------------------------------------------------------------
def dump_state(report: Mapping[str, Any]) -> Dict[str, Any]:
    """Can the IL2CPP metadata be dumped? ``{state, verdict, error_code, ok, reasons}``.

    states: dumped | failed | ready | blocked | disabled | not_unity | unknown
    """
    unity_data = d_(g(report, "engine_details", "unity"))
    if not unity_data:
        st = "not_unity" if is_unity_app(report) is False else "unknown"
        return {"state": st, "verdict": "n/a" if st == "not_unity" else "unknown", "error_code": None,
                "ok": None, "reasons": []}
    if unity_data.get("backend") == "mono":
        return {"state": "not_unity", "verdict": "n/a", "error_code": None, "ok": None, "reasons": ["mono"]}
    dump, pre = d_(unity_data.get("dump")), d_(unity_data.get("precheck"))
    enabled = g(report, "config", "il2cpp", "enabled", default=True)
    if dump.get("ran"):
        if dump.get("ok"):
            return {"state": "dumped", "verdict": "yes", "error_code": None, "ok": True, "reasons": []}
        return {"state": "failed", "verdict": "no", "error_code": dump.get("error_code"), "ok": False,
                "reasons": []}
    if pre.get("ready") is True:
        if enabled is False:
            return {"state": "disabled", "verdict": "unknown", "error_code": None, "ok": None, "reasons": []}
        return {"state": "ready", "verdict": "yes", "error_code": None, "ok": None, "reasons": []}
    if pre.get("ready") is False:
        return {"state": "blocked", "verdict": "no", "error_code": pre.get("error_code"), "ok": False,
                "reasons": [str(r) for r in l_(pre.get("reasons"))]}
    return {"state": "unknown", "verdict": "unknown", "error_code": None, "ok": None, "reasons": []}


# --- summary -------------------------------------------------------------------------------------
_RISK_ORDER = ("fairplay_encrypted", "metadata_encrypted", "assetbundle_encrypted", "script_protection",
               "resource_encrypted", "custom_engine", "unsigned_or_repackaged", "antidebug", "jailbreak_detect",
               "stage_failed", "unknown_libs", "trackers", "high_permissions")


def _verdict_of(report: Mapping[str, Any], fid: str) -> Optional[str]:
    f = first_finding(report, fid)
    return str(f.get("verdict")) if f else None


def _engine_summary(report: Mapping[str, Any]) -> Dict[str, Any]:
    det = d_(g(report, "engine_details", "detect"))
    prim = det.get("primary") if det else g(report, "structure", "engine", "primary")
    prim = prim if isinstance(prim, dict) else None
    cands = [c for c in (l_(det.get("candidates")) if det else l_(g(report, "structure", "engine", "candidates",
                                                                       default=[]))) if isinstance(c, dict)]
    wrapper = d_(det.get("wrapper")) if det else {}
    cust = d_(det.get("custom"))
    return {
        "primary": ({"id": prim.get("id"), "name": prim.get("name") or prim.get("id"),
                     "confidence": prim.get("confidence"), "confirmed": bool(prim.get("confirmed"))}
                    if prim else None),
        "candidates": [c.get("id") for c in cands if c.get("id") and c.get("id") != (prim or {}).get("id")][:5],
        "wrapper_host": g(wrapper, "host", "id"),
        "wrapper_embedded": [e.get("id") for e in l_(wrapper.get("embedded")) if isinstance(e, dict)],
        "custom": ({"verdict": cust.get("verdict"), "confidence": cust.get("confidence")} if cust else None),
        "is_game_engine": det.get("is_game_engine") if det else None,
        "known": bool(det) or bool(prim),
    }


def build_summary(report: Mapping[str, Any], results: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Language-neutral executive-summary data derived from the report dict."""
    results = results or {}
    app, cls = d_(report.get("app")), d_(report.get("classification"))
    dist = app.get("distribution")
    dist = dist if isinstance(dist, dict) else ({"type": dist} if isinstance(dist, str) else {})
    codesign = d_(g(report, "protection", "codesign"))
    fp_find, fp = first_finding(report, "protect.fairplay"), d_(g(report, "protection", "fairplay"))
    fairplay: Optional[Dict[str, Any]] = None
    if fp or fp_find:
        fairplay = {"verdict": fp.get("verdict") or (fp_find or {}).get("verdict") or "unknown",
                    "scope": fp.get("scope"), "confidence": (fp_find or {}).get("confidence"), "source": "protect",
                    "encrypted": len(l_(fp.get("encrypted_binaries"))), "total": fp.get("total_binaries")}
    else:
        ms = d_(g(report, "structure", "macho_summary"))
        if ms.get("any_encrypted") is not None:
            fairplay = {"verdict": "yes" if ms.get("any_encrypted") else "no",
                        "scope": "all" if ms.get("all_encrypted") else ("partial" if ms.get("any_encrypted") else "none"),
                        "confidence": None, "encrypted": None, "total": None, "source": "macho"}
    protections = []
    for fid in _KEY_PROTECTIONS:
        for f in findings_of(report):
            if f.get("id") == fid and f.get("verdict") in ("yes", "suspected"):
                protections.append({"id": fid, "verdict": f.get("verdict"), "confidence": f.get("confidence")})
                break
    unity = is_unity_app(report)
    ud = d_(g(report, "engine_details", "unity"))
    hot = d_(ud.get("hotfix"))
    unity_sum: Optional[Dict[str, Any]] = None
    if unity is not False and (ud or unity):
        unity_sum = {
            "detected": unity,
            "version": g(ud, "version", "value"),
            "backend": ud.get("backend"),
            "metadata_verdict": g(ud, "metadata", "verdict"),
            "assetbundle_verdict": _verdict_of(report, "unity.assetbundle.encryption"),
            "hotfix_frameworks": [f.get("name") or f.get("id") for f in l_(hot.get("frameworks"))
                                  if isinstance(f, dict)][:6],
            "script_protection": d_(hot.get("script_protection")),
            "has_unity_data": bool(ud),
        }
    dump = dump_state(report)
    stages = l_(report.get("stages"))
    problem = [{"name": s.get("name"), "status": s.get("status"), "reason": s.get("reason") or s.get("error")}
               for s in stages if isinstance(s, dict) and s.get("status") in ("skipped", "failed")]
    libs = d_(results.get("libs"))
    libs_unknown = [u for u in l_(libs.get("unknown")) if isinstance(u, dict)]
    trackers = l_(g(report, "privacy", "trackers", default=[]))
    perms_high = [p.get("key") for p in l_(g(report, "privacy", "permissions", default=[]))
                  if isinstance(p, dict) and p.get("level") == "high"]

    risks: Dict[str, Dict[str, Any]] = {}
    if fairplay and fairplay.get("verdict") in ("yes", "suspected"):
        risks["fairplay_encrypted"] = {"scope": fairplay.get("scope"), "verdict": fairplay.get("verdict")}
    for key, fid in (("metadata_encrypted", "unity.metadata.encrypted"),
                     ("assetbundle_encrypted", "unity.assetbundle.encryption"),
                     ("antidebug", "protect.antidebug"), ("jailbreak_detect", "protect.jailbreak_detect")):
        v = _verdict_of(report, fid)
        if v in ("yes", "suspected"):
            risks[key] = {"verdict": v}
    sp = [k for k, v in sorted(d_(hot.get("script_protection")).items()) if v in ("yes", "suspected")]
    if _verdict_of(report, "engine.script.encrypted") in ("yes", "suspected"):
        sp.append("engine")
    if sp:
        risks["script_protection"] = {"which": sp}
    if any(_verdict_of(report, i) in ("yes", "suspected") for i in ("engine.pak.encrypted", "engine.resource.encrypted")):
        risks["resource_encrypted"] = {}
    cust = custom_engine(report)
    if cust.get("verdict") in ("yes", "suspected"):
        risks["custom_engine"] = {"verdict": cust.get("verdict")}
    if dist.get("type") == "unsigned_or_repackaged":
        risks["unsigned_or_repackaged"] = {}
    failed = [s["name"] for s in problem if s["status"] == "failed"]
    if failed:
        risks["stage_failed"] = {"stages": failed}
    if libs_unknown:
        risks["unknown_libs"] = {"count": len(libs_unknown)}
    if trackers:
        risks["trackers"] = {"count": len(trackers)}
    if perms_high:
        risks["high_permissions"] = {"count": len(perms_high)}

    return {
        "name": app.get("selected_name") or app.get("bundle_id"),
        "bundle_id": app.get("bundle_id"),
        "version": app.get("version"),
        "build": app.get("build"),
        "category": {"id": cls.get("category"), "subcategory": cls.get("subcategory"),
                     "confidence": cls.get("confidence")} if cls else None,
        "engine": _engine_summary(report),
        "languages": [{"lang": x.get("lang"), "confidence": x.get("confidence")}
                      for x in l_(g(report, "structure", "languages", default=[])) if isinstance(x, dict)][:6],
        "fairplay": fairplay,
        "signing": {"distribution": dist.get("type"), "distribution_verdict": dist.get("verdict"),
                    "distribution_confidence": dist.get("confidence"), "signed": codesign.get("signed"),
                    "signature_type": codesign.get("signature_type"), "team_id": codesign.get("team_id")},
        "protections": protections,
        "unity": unity_sum,
        "unity_state": "unity" if unity else ("not_unity" if unity is False else "unknown"),
        "dump": dump,
        "risks": [{"key": k, "params": risks[k]} for k in _RISK_ORDER if k in risks][:8],
        "problem_stages": problem,
        "libs": {"unknown": libs_unknown, "by_category": d_(libs.get("by_category")),
                 "privacy_tags": d_(libs.get("privacy_tags"))} if libs else None,
    }


# --- enrichment ----------------------------------------------------------------------------------
def enrich_report(report: Any, results: Mapping[str, Any]) -> None:
    """Add data to a ``Report`` (from ``pipeline.build_report``) that renderers need but the base
    mapping omits. Only adds keys inside free-form objects, never renames or removes anything."""
    meta, inv, macho = d_(results.get("meta")), d_(results.get("inventory")), d_(results.get("macho"))
    for k, v in d_(results.get("protect")).items():
        if k != "findings":
            report.protection.setdefault(k, v)
    for k in ("provision", "signature_integrity", "fairplay_container"):
        if meta.get(k) is not None:
            prov = meta[k]
            if k == "provision" and isinstance(prov, dict):
                prov = {x: prov.get(x) for x in ("present", "name", "team_id", "team_name", "app_id_prefix",
                                                 "creation_date", "expiration_date", "provisions_all_devices",
                                                 "device_count") if x in prov}
            report.app.setdefault(k, prov)
    if macho.get("summary") is not None:
        report.structure.setdefault("macho_summary", macho["summary"])
    for k in ("files_total", "files_truncated", "inventory_file", "structure_hints"):
        if inv.get(k) is not None:
            report.resources.setdefault(k, inv[k])
    cls = d_(results.get("classify"))
    for k in ("runner_up", "scores"):
        if cls.get(k) is not None and report.classification:
            report.classification.setdefault(k, cls[k])
    checkers = d_(d_(results.get("engine.other")).get("_checkers"))
    if checkers:
        report.engine_details.setdefault("_checkers", checkers)
    report.summary = build_summary(report.to_dict(), results)


# --- executive summary rows ----------------------------------------------------------------------
def _join(items: Iterable[str], t: Translate) -> str:
    return t("report.sep").join(i for i in items if i)


def _lang_name(lang: Any, t: Translate) -> str:
    return t("report.lang." + str(lang), str(lang))


def exec_rows(report: Mapping[str, Any], summary: Mapping[str, Any], t: Translate) -> List[Tuple[str, str]]:
    """The executive summary as ``(label, plain text)`` rows (at most 15)."""
    rows: List[Tuple[str, str]] = []

    def need(stage: str) -> Optional[str]:
        return None if stage_ok(report, stage) else t("report.exec.unavailable", stage=stage)

    rows.append((t("report.exec.label.name"), str(summary.get("name") or need("meta") or "-")))
    rows.append((t("report.exec.label.bundle_id"), str(summary.get("bundle_id") or need("meta") or "-")))
    ver, build = summary.get("version"), summary.get("build")
    if ver and build:
        vtxt = t("report.exec.version", version=ver, build=build)
    else:
        vtxt = str(ver or need("meta") or "-")
    rows.append((t("report.exec.label.version"), vtxt))

    cat = summary.get("category")
    if cat and cat.get("id"):
        txt = t("report.category." + str(cat["id"]), str(cat["id"]))
        if cat.get("subcategory"):
            txt += " / %s" % cat["subcategory"]
        txt += t("report.exec.conf_suffix", conf=fmt_conf(cat.get("confidence"), t))
    else:
        txt = need("classify") or "-"
    rows.append((t("report.exec.label.type"), txt))

    eng = d_(summary.get("engine"))
    prim = eng.get("primary")
    parts: List[str] = []
    if prim:
        parts.append(t("report.exec.engine.primary", name=prim.get("name"),
                       conf=fmt_conf(prim.get("confidence"), t),
                       confirmed=t("report.exec.confirmed") if prim.get("confirmed") else t("report.exec.unconfirmed")))
        if eng.get("candidates"):
            parts.append(t("report.exec.engine.also", names=", ".join(map(str, eng["candidates"]))))
        if eng.get("wrapper_host") or eng.get("wrapper_embedded"):
            parts.append(t("report.exec.engine.wrapper", host=eng.get("wrapper_host") or "-",
                           embedded=", ".join(map(str, eng.get("wrapper_embedded") or [])) or "-"))
    cust = eng.get("custom")
    if cust and cust.get("verdict") in ("yes", "suspected"):
        parts.append(t("report.exec.engine.custom", verdict=t("report.verdict." + str(cust["verdict"])),
                       conf=fmt_conf(cust.get("confidence"), t)))
    if not parts:
        parts.append(t("report.exec.engine.none") if eng.get("known") else (need("engine.detect") or "-"))
    rows.append((t("report.exec.label.engine"), _join(parts, t)))

    langs = [x for x in l_(summary.get("languages")) if x.get("lang")]
    rows.append((t("report.exec.label.languages"),
                 ", ".join("%s (%.2f)" % (_lang_name(x["lang"], t), float(x.get("confidence") or 0)) for x in langs[:4])
                 if langs else (need("engine.detect") or t("report.exec.none_found"))))

    fp = summary.get("fairplay")
    if fp:
        txt = t("report.badge.risk." + _vkey(fp.get("verdict")))
        if fp.get("scope"):
            txt += t("report.exec.scope", scope=t("report.scope." + str(fp["scope"]), str(fp["scope"])))
        if fp.get("encrypted") is not None and fp.get("total"):
            txt += t("report.exec.fp_count", n=fp["encrypted"], total=fp["total"])
        if fp.get("source") == "macho":
            txt += t("report.exec.from_macho")
    else:
        txt = need("protect") or t("report.badge.risk.unknown")
    rows.append((t("report.exec.label.fairplay"), txt))

    sg = d_(summary.get("signing"))
    sparts = []
    if sg.get("distribution"):
        sparts.append(t("report.dist." + str(sg["distribution"]), str(sg["distribution"])))
    if sg.get("signed") is not None:
        sparts.append(t("report.exec.signed") if sg["signed"] else t("report.exec.unsigned"))
    if sg.get("signature_type"):
        sparts.append(str(sg["signature_type"]))
    if sg.get("team_id"):
        sparts.append("Team ID %s" % sg["team_id"])
    rows.append((t("report.exec.label.signing"), _join(sparts, t) or need("meta") or "-"))

    prots = l_(summary.get("protections"))
    if prots:
        ptxt = _join((t("report.prot." + p["id"], p["id"]) + t("report.exec.colon") + t("report.verdict." + p["verdict"])
                      for p in prots[:5]), t)
    elif stage_ok(report, "protect"):
        ptxt = t("report.exec.no_protection")
    else:
        ptxt = need("protect") or "-"
    rows.append((t("report.exec.label.protections"), ptxt))

    un = summary.get("unity")
    if un and (un.get("has_unity_data") or un.get("detected")):
        uparts = ["Unity %s" % (un.get("version") or t("report.exec.version_unknown"))]
        if un.get("backend"):
            uparts[0] += " / %s" % un["backend"]
        if un.get("metadata_verdict"):
            uparts.append(t("report.exec.metadata", v=t("report.verdict." + str(un["metadata_verdict"]))))
        if un.get("assetbundle_verdict"):
            uparts.append(t("report.exec.assetbundle", v=t("report.verdict." + str(un["assetbundle_verdict"]))))
        if stage_ok(report, "engine.unity.hotfix"):
            hf = un.get("hotfix_frameworks") or []
            uparts.append(t("report.exec.hotfix", names=", ".join(map(str, hf))) if hf else t("report.exec.hotfix_none"))
        utxt = _join(uparts, t)
    elif summary.get("unity_state") == "not_unity":
        utxt = t("report.stage.not_unity")
    else:
        utxt = need("engine.detect") or t("report.exec.unity_unknown")
    rows.append((t("report.exec.label.unity"), utxt))

    dp = d_(summary.get("dump"))
    dtxt = t("report.dump." + str(dp.get("state", "unknown")), error=dp.get("error_code") or "-",
             reasons="; ".join(map(str, dp.get("reasons") or [])) or "-")
    rows.append((t("report.exec.label.dump"), dtxt))

    risks = l_(summary.get("risks"))
    if risks:
        def _risk(r: Mapping[str, Any]) -> str:
            params = _flat(r.get("params"))
            if params.get("scope"):
                params["scope"] = t("report.scope." + str(params["scope"]), str(params["scope"]))
            return t("report.risk." + r["key"], r["key"], **params)

        rtxt = _join((_risk(r) for r in risks[:6]), t)
    else:
        rtxt = t("report.exec.no_risks")
    rows.append((t("report.exec.label.risks"), rtxt))

    prob = l_(summary.get("problem_stages"))
    if prob:
        ptxt = t("report.exec.skipped_n", n=len(prob)) + _join(
            ("%s (%s)" % (p["name"], t("report.status." + str(p["status"]))) for p in prob[:8]), t)
        if len(prob) > 8:
            ptxt += t("report.exec.more", n=len(prob) - 8)
    else:
        ptxt = t("report.exec.skipped_none")
    rows.append((t("report.exec.label.skipped"), ptxt))
    return rows[:15]


def _vkey(v: Any) -> str:
    v = str(v)
    return "na" if v == "n/a" else (v if v in ("yes", "no", "suspected", "unknown") else "unknown")


def _flat(p: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in d_(p).items():
        out[k] = ", ".join(map(str, v)) if isinstance(v, list) else v
    return out


def console_text(report: Mapping[str, Any], summary: Mapping[str, Any], t: Translate) -> str:
    """Plain-text executive summary for the console (no Markdown, no emoji needed)."""
    lines = [t("report.console.title")]
    width = max([len(k) for k, _ in exec_rows(report, summary, t)] + [4])
    for label, text in exec_rows(report, summary, t):
        lines.append("  %s  %s" % (label.ljust(width), text))
    return "\n".join(lines)


def exit_code_for(stages: Iterable[Any]) -> int:
    """Exit-code decision input for the CLI: 3 if any stage failed, else 0.

    Accepts ``StageResult`` objects or stage summary dicts. (Invalid input -> 2 is the CLI's call.)
    """
    for s in stages:
        status = s.get("status") if isinstance(s, dict) else getattr(s, "status", None)
        status = getattr(status, "value", status)
        if status == "failed":
            return 3
    return 0
