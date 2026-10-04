"""Stage ``meta`` (WP2): app identity, distribution type, permissions, provisioning profile and seal check.

Reads Info.plist, ``*.lproj/InfoPlist.strings``, ``embedded.mobileprovision``, ``iTunesMetadata.plist``,
``SC_Info/`` and ``_CodeSignature/CodeResources`` straight from the archive (nothing is extracted).
Every sub-step is isolated: a broken file produces a warning and the stage ends ``partial``.
Purchaser data from iTunesMetadata.plist is redacted unless ``Config.redact`` is false; device UDIDs
are never emitted (count + hash prefixes only).
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar

from ..context import AnalysisContext
from ..ingest import EntryInfo
from ..meta.coderesources import parse_code_resources, verify_code_resources
from ..meta.infoplist import (as_str, build_name_candidates, extract_ats, extract_background_modes,
                              extract_capabilities, extract_identity, extract_ns_extension,
                              extract_query_schemes, extract_sdk, extract_url_schemes, parse_info_plist,
                              select_name)
from ..meta.itunes_meta import parse_itunes_metadata
from ..meta.permissions import collect_permissions, load_permission_db, summarize_permissions
from ..meta.provision import classify_distribution, parse_provision, summarize_provision
from ..meta.strings_file import lang_from_lproj, parse_strings_file
from ..models import Evidence, Finding, StageResult, Verdict
from ..registry import register
from ..util.plist_utils import load_plist

log = logging.getLogger(__name__)

NAME = "meta"

_MAX_PLIST_BYTES = 8 * 1024 * 1024
_MAX_STRINGS_BYTES = 2 * 1024 * 1024
_MAX_PROFILE_BYTES = 4 * 1024 * 1024
_MAX_LPROJ = 200
_MAX_EXTENSIONS = 100
_MAX_SC_INFO_LISTED = 50
# Observed in real App Store packages: .sinf (SINF box), .supp / .supf / .supx (supplement files).
_SC_INFO_EXTS = (".sinf", ".supp", ".supf", ".supx")

_LPROJ_STRINGS_RE = re.compile(r"^([^/]+\.lproj)/InfoPlist\.strings$")
# Extension locations. UNVERIFIED: ``Extensions/`` (ExtensionKit appex bundles on iOS 16+) is from memory.
_APPEX_RE = re.compile(r"^((?:PlugIns|Extensions)/[^/]+\.appex)/Info\.plist$")
_WATCH_RE = re.compile(r"^(Watch/[^/]+\.app)/Info\.plist$")
_CLIP_RE = re.compile(r"^(AppClips/[^/]+\.app)/Info\.plist$")
_NESTED_APPEX_RE = re.compile(r"^((?:Watch|AppClips)/[^/]+\.app)/((?:PlugIns|Extensions)/[^/]+\.appex)/Info\.plist$")

T = TypeVar("T")


class _Run:
    """Per-run scratch state: archive index, warnings and degradation flag."""

    def __init__(self, ctx: AnalysisContext) -> None:
        self.ctx = ctx
        self.source = ctx.source
        self.warnings: List[str] = []
        self.degraded = False
        self.entries: Dict[str, EntryInfo] = {e.name: e for e in self.source.namelist()}   # type: ignore[union-attr]

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)
        self.degraded = True

    def read(self, name: str, limit: int, label: str) -> Optional[bytes]:
        info = self.entries.get(name)
        if info is None or info.is_dir:
            return None
        if info.size > limit:
            self.warn("%s is too large to parse (%d bytes > %d)" % (label, info.size, limit))
            return None
        try:
            with self.source.open(name) as fh:      # type: ignore[union-attr]
                return fh.read(limit + 1)
        except Exception as exc:  # noqa: BLE001 - corrupt entry: warn, continue
            self.warn("cannot read %s: %s" % (label, exc))
            return None

    def guard(self, label: str, fn: Callable[[], T], default: T) -> T:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - isolate every sub-step
            log.debug("meta step %s failed", label, exc_info=True)
            self.warn("%s failed: %s: %s" % (label, type(exc).__name__, exc))
            return default


# --- sub-steps --------------------------------------------------------------------------------
def _localized_strings(run: _Run, root: str) -> Tuple[Dict[str, Dict[str, str]], List[str]]:
    """``({lang: {key: text}}, [lang])`` from ``*.lproj/InfoPlist.strings``."""
    result: Dict[str, Dict[str, str]] = {}
    seen = 0
    for name in sorted(run.entries):
        if not name.startswith(root):
            continue
        m = _LPROJ_STRINGS_RE.match(name[len(root):])
        if not m:
            continue
        seen += 1
        if seen > _MAX_LPROJ:
            run.warn("more than %d InfoPlist.strings files; the rest were ignored" % _MAX_LPROJ)
            break
        lang = lang_from_lproj(m.group(1))
        data = run.read(name, _MAX_STRINGS_BYTES, name)
        if data is None:
            continue
        parsed = parse_strings_file(data)
        if not parsed and data.strip():
            run.warn("InfoPlist.strings for %s could not be parsed" % (lang or m.group(1)))
        bucket = result.setdefault(lang, {})
        for k, v in parsed.items():
            bucket.setdefault(k, v)
    return result, sorted(result)


def _container_prefixes(app_root: str) -> List[str]:
    """Places where ``iTunesMetadata.plist`` can sit: next to ``Payload/`` (IPA root), then the archive root."""
    out: List[str] = []
    idx = app_root.find("Payload/")
    if idx >= 0:
        out.append(app_root[:idx])
    if "" not in out:
        out.append("")
    return out


def _sc_info(run: _Run, root: str) -> Dict[str, Any]:
    prefix = root + "SC_Info/"
    files: List[str] = []
    present = False
    nested_units = set()
    for name, e in run.entries.items():
        if not name.startswith(root):
            continue
        rel = name[len(root):]
        if rel.startswith("SC_Info/"):
            present = True
            if not e.is_dir and name != prefix:
                files.append(rel)
        elif "/SC_Info/" in rel:
            nested_units.add(rel.split("/SC_Info/", 1)[0])
    files.sort()
    sinf = [f for f in files if f.lower().endswith(_SC_INFO_EXTS)]
    return {
        "sc_info_present": present,
        "files": files[:_MAX_SC_INFO_LISTED],
        "extra": {"file_count": len(files), "fairplay_files": len(sinf),
                  "has_manifest": any(f.endswith("/Manifest.plist") for f in files),
                  "nested_units_with_sc_info": len(nested_units)},
    }


def _extensions(run: _Run, root: str) -> List[Dict[str, Any]]:
    found: List[Tuple[str, str, Optional[str]]] = []     # (bundle dir rel, kind, parent)
    for name in run.entries:
        if not name.startswith(root):
            continue
        rel = name[len(root):]
        for rx, kind in ((_APPEX_RE, "appex"), (_WATCH_RE, "watch"), (_CLIP_RE, "app_clip")):
            m = rx.match(rel)
            if m:
                found.append((m.group(1), kind, None))
        m = _NESTED_APPEX_RE.match(rel)
        if m:
            found.append((m.group(1) + "/" + m.group(2), "appex", m.group(1)))
    found.sort()
    out: List[Dict[str, Any]] = []
    for bundle, kind, parent in found[:_MAX_EXTENSIONS]:
        plist_name = root + bundle + "/Info.plist"
        data = run.read(plist_name, _MAX_PLIST_BYTES, plist_name)
        info = parse_info_plist(data) if data is not None else None
        if info is None:
            run.warn("cannot parse %s" % plist_name)
        info = info or {}
        ns = extract_ns_extension(info)
        point = ns["point"]
        out.append({
            "path": root + bundle,
            "bundle_id": as_str(info.get("CFBundleIdentifier")),
            "kind": kind,
            "point": point,
            "extra": {
                "name": as_str(info.get("CFBundleDisplayName")) or as_str(info.get("CFBundleName")),
                "version": as_str(info.get("CFBundleShortVersionString")),
                "build": as_str(info.get("CFBundleVersion")),
                "min_os": as_str(info.get("MinimumOSVersion")),
                "parent": (root + parent) if parent else None,
                "companion_bundle_id": as_str(info.get("WKCompanionAppBundleIdentifier")),
                "principal_class": ns["principal_class"],
            },
        })
    if len(found) > _MAX_EXTENSIONS:
        run.warn("more than %d app extensions; the list was truncated" % _MAX_EXTENSIONS)
    return out


def _evidence_dicts(evs: List[Evidence]) -> List[Dict[str, str]]:
    return [e.to_dict() for e in evs]


# --- stage ------------------------------------------------------------------------------------
@register(name="meta", requires=("ingest",))
class MetaStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        if ctx.source is None:
            return StageResult.skipped(NAME, "no input archive is open")
        run = _Run(ctx)
        root = ctx.app_root
        cfg = ctx.cfg
        findings: List[Finding] = []

        # 1. Info.plist ---------------------------------------------------------------------
        info_name = ctx.app_path("Info.plist")
        info_bytes = run.guard("read Info.plist", lambda: run.read(info_name, _MAX_PLIST_BYTES, "Info.plist"), None)
        info: Optional[Dict[str, Any]] = None
        if info_bytes is None:
            if info_name not in run.entries:
                run.warn("Info.plist not found at %s" % info_name)
        else:
            info = parse_info_plist(info_bytes)
            if info is None:
                run.warn("Info.plist is not a valid plist (%d bytes)" % len(info_bytes))

        # 2. localized strings --------------------------------------------------------------
        localized, loc_langs = run.guard("InfoPlist.strings", lambda: _localized_strings(run, root), ({}, []))

        # 3. iTunesMetadata.plist ----------------------------------------------------------
        itunes: Dict[str, Any] = {}
        redacted_keys: List[str] = []
        itunes_name = ""
        for pre in _container_prefixes(root):
            cand = pre + "iTunesMetadata.plist"
            if cand in run.entries:
                itunes_name = cand
                break
        if itunes_name:
            raw = run.guard("read iTunesMetadata.plist", lambda: run.read(itunes_name, _MAX_PLIST_BYTES, "iTunesMetadata.plist"), None)
            if raw is not None:
                plist = load_plist(raw)
                if isinstance(plist, dict):
                    itunes, redacted_keys = run.guard("iTunesMetadata.plist", lambda: parse_itunes_metadata(plist, cfg.redact), ({}, []))
                else:
                    run.warn("iTunesMetadata.plist is not a valid plist")

        # 4. provisioning profile -----------------------------------------------------------
        prov_name = ctx.app_path("embedded.mobileprovision")
        provision: Dict[str, Any] = {"present": False}
        prov_unreadable = False
        if prov_name in run.entries:
            raw = run.guard("read embedded.mobileprovision", lambda: run.read(prov_name, _MAX_PROFILE_BYTES, "embedded.mobileprovision"), None)
            parsed = parse_provision(raw) if raw is not None else None
            if parsed is None:
                prov_unreadable = True
                run.warn("embedded.mobileprovision could not be parsed")
            else:
                provision = run.guard("provisioning profile", lambda: summarize_provision(parsed), {"present": False})
                prov_unreadable = not provision.get("present")

        # 5. containers / signature presence -------------------------------------------------
        fair = run.guard("SC_Info", lambda: _sc_info(run, root), {"sc_info_present": False, "files": [], "extra": {}})
        has_code_sig = ctx.app_path("_CodeSignature/CodeResources") in run.entries
        markers: List[str] = []
        if itunes_name:
            markers.append("iTunesMetadata.plist")
        if fair["extra"].get("fairplay_files"):
            markers.append("SC_Info")

        # 6. extensions -------------------------------------------------------------------
        extensions = run.guard("app extensions", lambda: _extensions(run, root), [])

        # 7. identity / names -------------------------------------------------------------
        info_d = info or {}
        identity = extract_identity(info_d)
        input_stem = Path(str(ctx.input_path)).stem or ctx.input_name
        names = build_name_candidates(info_d, localized, itunes.get("item_name"), itunes.get("bundle_display_name"),
                                      identity.get("executable"), input_stem)
        identity_out: Dict[str, Any] = {"names": names, "selected_name": select_name(names)}
        identity_out.update(identity)
        identity_out["extra"]["localizations"] = loc_langs

        # 8. permissions ------------------------------------------------------------------
        perms = run.guard("permissions", lambda: collect_permissions(info_d, localized, load_permission_db()), [])
        perm_sum = summarize_permissions(perms)

        # 9. distribution -----------------------------------------------------------------
        exe_name = identity.get("executable")
        names_consistent = bool(exe_name) and ("SC_Info/%s.sinf" % exe_name) in set(fair["files"])
        dist = classify_distribution(provision if provision.get("present") else None,
                                     prov_unreadable=prov_unreadable, store_markers=markers,
                                     has_code_signature=has_code_sig, store_names_consistent=names_consistent)
        distribution = {
            "type": dist["type"], "verdict": dist["verdict"].value, "confidence": dist["confidence"],
            "evidence": _evidence_dicts(dist["evidence"]),
            "extra": {"alternatives": dist["alternatives"], "repackaged_hint": dist["repackaged_hint"]},
        }

        # 10. seal integrity (P1) -----------------------------------------------------------
        integrity: Optional[Dict[str, Any]] = None
        integrity_skip = ""
        cr_name = ctx.app_path("_CodeSignature/CodeResources")
        if not cfg.signature_integrity:
            integrity_skip = "disabled"
        elif cr_name not in run.entries:
            integrity_skip = "no_code_resources"
        else:
            raw = run.guard("read CodeResources", lambda: run.read(cr_name, _MAX_PLIST_BYTES * 4, "CodeResources"), None)
            seal = parse_code_resources(raw) if raw is not None else None
            if seal is None:
                integrity_skip = "unreadable"
                if raw is not None:
                    run.warn("CodeResources is not a valid seal plist")
            else:
                integrity = run.guard(
                    "signature integrity",
                    lambda: verify_code_resources(run.source, root, seal, run.source.namelist(),  # type: ignore[union-attr]
                                                  executable=identity.get("executable")), None)
                if integrity is None:
                    integrity_skip = "failed"
                else:
                    for w in integrity.get("warnings") or []:
                        run.warn(w)

        # --- data ------------------------------------------------------------------------
        data: Dict[str, Any] = {
            "identity": identity_out,
            "distribution": distribution,
            "provision": provision,
            "itunes": itunes,
            "fairplay_container": {"sc_info_present": fair["sc_info_present"], "files": fair["files"],
                                   "extra": fair["extra"]},
            "permissions": perms,
            "url_schemes": extract_url_schemes(info_d),
            "query_schemes": extract_query_schemes(info_d),
            "ats": extract_ats(info_d),
            "extensions": extensions,
            "background_modes": extract_background_modes(info_d),
            "capabilities": extract_capabilities(info_d),
            "sdk": extract_sdk(info_d),
            "redaction": {"applied": bool(cfg.redact and redacted_keys), "keys": redacted_keys},
            "warnings": run.warnings,
        }
        if integrity is not None:
            data["signature_integrity"] = integrity

        # --- findings --------------------------------------------------------------------
        findings.append(_identity_finding(info, identity_out, info_name))
        findings.append(_distribution_finding(distribution, dist))
        findings.append(_permissions_finding(info is not None, perms, perm_sum))
        findings.append(_fairplay_finding(fair))
        findings.append(_integrity_finding(integrity, integrity_skip, cr_name))

        if run.degraded:
            return StageResult.partial(NAME, data, findings, run.warnings,
                                       reason="some metadata files were missing or could not be parsed")
        return StageResult.ok(NAME, data, findings, run.warnings)


# --- findings ---------------------------------------------------------------------------------
def _identity_finding(info: Optional[Dict[str, Any]], ident: Dict[str, Any], info_name: str) -> Finding:
    bundle_id = ident.get("bundle_id")
    params = {"name": ident.get("selected_name") or "", "bundle_id": bundle_id or "",
              "version": ident.get("version") or "", "build": ident.get("build") or ""}
    if info is None or not bundle_id:
        return Finding("meta.identity", Verdict.UNKNOWN, 0.1, "App identity could not be resolved",
                       "Info.plist is missing, unreadable or has no CFBundleIdentifier.", params,
                       [Evidence("file", info_name, "missing or unreadable")])
    ev = [Evidence("plist_key", "Info.plist:CFBundleIdentifier", bundle_id)]
    if ident.get("version"):
        ev.append(Evidence("plist_key", "Info.plist:CFBundleShortVersionString", ident["version"]))
    return Finding("meta.identity", Verdict.YES, 0.95, "App identity resolved",
                   "%s (%s) %s (%s)" % (params["name"], bundle_id, params["version"], params["build"]),
                   params, ev)


def _distribution_finding(dist: Dict[str, Any], raw: Dict[str, Any]) -> Finding:
    alts = ", ".join(raw["alternatives"])
    summary = "Distribution type: %s." % dist["type"]
    if alts:
        summary += " Competing hypotheses: %s." % alts
    summary += " Container-layer evidence only; it cannot prove where the package came from."
    return Finding("meta.distribution", raw["verdict"], raw["confidence"], "Distribution type", summary,
                   {"type": dist["type"], "alternatives": raw["alternatives"],
                    "alternatives_text": alts or "-"}, list(raw["evidence"]),
                   tags=["repackaged_hint"] if raw["repackaged_hint"] else [])


def _permissions_finding(info_ok: bool, perms: List[Dict[str, Any]], summ: Dict[str, Any]) -> Finding:
    params = {"count": summ["count"], "high_count": summ["by_level"]["high"],
              "high_keys": ", ".join(summ["high_keys"]) or "-"}
    if not info_ok:
        return Finding("meta.permissions", Verdict.UNKNOWN, 0.1, "Permission declarations unknown",
                       "Info.plist could not be read.", params)
    ev = [Evidence("plist_key", "Info.plist:" + p["key"]) for p in perms[:20]]
    if perms:
        return Finding("meta.permissions", Verdict.YES, 0.95, "Privacy permissions declared",
                       "%d usage descriptions declared, %d high sensitivity." % (summ["count"], params["high_count"]),
                       params, ev)
    return Finding("meta.permissions", Verdict.NO, 0.8, "No privacy permissions declared",
                   "Info.plist declares no *UsageDescription keys.", params)


def _fairplay_finding(fair: Dict[str, Any]) -> Finding:
    ex = fair["extra"]
    n = int(ex.get("fairplay_files", 0))
    params = {"count": n, "nested_units": int(ex.get("nested_units_with_sc_info", 0))}
    ev = [Evidence("file", "SC_Info/" + f.split("/", 1)[-1]) for f in fair["files"][:10]]
    note = "Container-level evidence only; the binary encryption state is decided by Mach-O cryptid."
    if n:
        return Finding("meta.fairplay_container", Verdict.YES, 0.85, "App Store FairPlay container present",
                       "%d SC_Info supplement files. %s" % (n, note), params, ev)
    if fair["sc_info_present"] or params["nested_units"]:
        return Finding("meta.fairplay_container", Verdict.SUSPECTED, 0.4, "SC_Info present without FairPlay files",
                       "SC_Info exists but holds no .sinf/.supp files at the top level. " + note, params, ev)
    return Finding("meta.fairplay_container", Verdict.NO, 0.6, "No App Store FairPlay container found",
                   "No SC_Info directory. " + note, params)


def _integrity_finding(res: Optional[Dict[str, Any]], skip: str, cr_name: str) -> Finding:
    if res is None:
        return Finding("meta.signature_integrity", Verdict.NA if skip in ("disabled", "no_code_resources")
                       else Verdict.UNKNOWN, 0.5 if skip in ("disabled", "no_code_resources") else 0.1,
                       "Signature seal not checked", "Resource seal check skipped: %s." % (skip or "unknown"),
                       {"reason": skip or "unknown", "checked": 0, "missing": 0, "modified": 0, "extra": 0})
    det = res["details"]
    params = {"checked": res["checked"], "missing": res["missing"], "modified": res["modified"],
              "extra": res["extra"], "reason": ""}
    ev = [Evidence("file", cr_name + ":" + x["path"], x["kind"]) for x in res["examples"]]
    complete = not det["truncated"] and det["unsupported_digest"] == 0 and not det.get("rules_incomplete")
    summary = ("%d files checked: %d missing, %d modified, %d extra. A consistent seal does not prove "
               "authenticity (re-signed packages carry a fresh seal). The extra-file count interprets the seal's "
               "path rules heuristically." % (res["checked"], res["missing"], res["modified"], res["extra"]))
    if res["modified"] or res["missing"]:
        return Finding("meta.signature_integrity", Verdict.YES, 0.85, "Resources differ from the code-signature seal",
                       summary, params, ev, tags=["tampered"])
    if res["extra"]:
        return Finding("meta.signature_integrity", Verdict.SUSPECTED, 0.4, "Files outside the code-signature seal",
                       summary, params, ev, tags=["extra_files"])
    if complete and res["checked"] > 0:
        return Finding("meta.signature_integrity", Verdict.NO, 0.8, "Resources match the code-signature seal",
                       summary, params, ev)
    return Finding("meta.signature_integrity", Verdict.UNKNOWN, 0.3, "Seal check incomplete",
                   summary + " Not every listed file could be verified.", params, ev)
