"""Stage ``macho`` (WP3): parse every Mach-O file in the app and summarise architecture, platform,
FairPlay encryption, signing and hardening per slice.

Reads ``inventory`` (hard dependency) and, lazily, the archive through ``ctx.extract``; it never
executes anything. Per-binary failures only add a warning and make the stage ``partial``. The
``protect.fairplay`` verdict is produced later by the ``protect`` stage from the per-slice
``encrypted`` flags recorded here.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..context import AnalysisContext
from ..macho import MachOError, MachOFile, MachOSlice, NotMachO, parse
from ..macho import constants as MC
from ..models import Evidence, Finding, StageResult, Verdict
from ..registry import register
from ..util.plist_utils import load_plist, to_jsonable_plist

log = logging.getLogger(__name__)

NAME = "macho"
_MAGIC_HEADS = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf", b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca")
_MACHO_MAGIC_IDS = frozenset({"macho", "macho_fat", "fat_macho", "macho_universal", "universal_macho", "fat"})
_MAX_EVIDENCE = 10


# --- helpers (pure, unit-tested) ---------------------------------------------------------------
def is_macho_magic_id(magic: Any) -> bool:
    """Whether an inventory ``magic`` id denotes a Mach-O (thin or fat) file."""
    return isinstance(magic, str) and (magic.lower() in _MACHO_MAGIC_IDS or magic.lower().startswith("macho"))


def classify_role(rel: str, main_rel: Optional[str]) -> str:
    """Positional role of a Mach-O at ``rel`` (path relative to the .app root)."""
    if main_rel is not None and rel == main_rel:
        return "main"
    if rel.startswith("Watch/") or "/Watch/" in rel:
        return "watch"
    if rel.lower().endswith(".dylib"):
        return "dylib"
    if ".framework/" in rel:
        return "framework"
    if rel.startswith(("PlugIns/", "Extensions/")) or ".appex/" in rel:
        return "appex"
    return "other"


def _read_main_executable(ctx: AnalysisContext) -> Optional[str]:
    """``CFBundleExecutable`` from the app's Info.plist (None if unreadable)."""
    src = ctx.source
    if src is None:
        return None
    try:
        with src.open(ctx.app_path("Info.plist")) as fh:
            data = fh.read(8 * 1024 * 1024)
    except (KeyError, OSError):
        return None
    plist = load_plist(data)
    if isinstance(plist, dict):
        exe = plist.get("CFBundleExecutable")
        if isinstance(exe, str) and exe and "/" not in exe:
            return exe
    return None


def _app_dir_stem(ctx: AnalysisContext) -> Optional[str]:
    root = ctx.app_root.rstrip("/")
    if root:
        leaf = root.rsplit("/", 1)[-1]
        if leaf.lower().endswith(".app"):
            return leaf[:-4]
    return None


def pick_main(top_level: List[Tuple[str, Optional[str]]], bundle_exec: Optional[str],
              app_stem: Optional[str]) -> Optional[str]:
    """Choose the main executable among top-level Mach-O files ``[(rel, first_filetype_name)]``.

    Preference: ``CFBundleExecutable``; the app directory's stem; the only top-level executable.
    """
    rels = [r for r, _ in top_level]
    for want in (bundle_exec, app_stem):
        if want and want in rels:
            return want
    execs = [r for r, ft in top_level if ft == "execute"]
    return execs[0] if len(execs) == 1 else None


# --- discovery ---------------------------------------------------------------------------------
def _inventory_files(ctx: AnalysisContext, inv: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], bool]:
    """Inventory rows (full table if the in-memory one was truncated) and whether they are complete."""
    files = [f for f in inv.get("files") or [] if isinstance(f, dict)]
    if not inv.get("files_truncated"):
        return files, True
    rel = inv.get("inventory_file")
    if isinstance(rel, str) and ctx.is_bound:
        try:
            raw = json.loads((ctx.out_dir / rel).read_text(encoding="utf-8"))
            rows = raw.get("files") if isinstance(raw, dict) else raw
            if isinstance(rows, list):
                return [f for f in rows if isinstance(f, dict)], True
        except (OSError, ValueError) as exc:
            ctx.add_warning("macho: cannot read %s (%s); falling back to header sniffing" % (rel, exc))
    return files, False


def _sniff_candidates(ctx: AnalysisContext, known: Iterable[str]) -> List[Dict[str, Any]]:
    """Header-sniff app files that could be Mach-O (used when the inventory table is incomplete)."""
    src = ctx.source
    out: List[Dict[str, Any]] = []
    if src is None:
        return out
    seen = set(known)
    for ent in src.namelist():
        if ent.is_dir or ent.is_symlink or ent.size < MC.MACH_HEADER_SIZE or ent.name in seen:
            continue
        rel = ctx.rel(ent.name)
        if rel is None:
            continue
        leaf = rel.rsplit("/", 1)[-1]
        ext = "." + leaf.rsplit(".", 1)[1].lower() if "." in leaf else ""
        if ext not in ("", ".dylib"):
            continue
        try:
            if src.read_head(ent.name, 4) in _MAGIC_HEADS:
                out.append({"path": ent.name, "size": ent.size, "magic": "macho"})
        except (KeyError, OSError):
            continue
    return out


def _candidates(ctx: AnalysisContext, inv: Dict[str, Any]) -> List[Dict[str, Any]]:
    files, complete = _inventory_files(ctx, inv)
    cands = [f for f in files if is_macho_magic_id(f.get("magic")) and isinstance(f.get("path"), str)]
    if not complete or not files:
        cands += _sniff_candidates(ctx, (f["path"] for f in cands))
    uniq: Dict[str, Dict[str, Any]] = {}
    for f in cands:
        uniq.setdefault(f["path"], f)
    return [uniq[k] for k in sorted(uniq)]


# --- records -----------------------------------------------------------------------------------
def _slice_record(sl: MachOSlice) -> Dict[str, Any]:
    enc = next((e for e in sl.encryption if e.encrypted), sl.encryption[0] if sl.encryption else None)
    sig = sl.code_signature
    rec: Dict[str, Any] = {
        "arch": sl.arch_name, "filetype": sl.filetype_name, "platform": sl.platform, "min_os": sl.min_os,
        "sdk": sl.sdk, "uuid": sl.uuid, "encrypted": sl.is_encrypted,
        "cryptid": enc.cryptid if enc else None, "cryptsize": enc.cryptsize if enc else None,
        "is_pie": sl.is_pie, "stripped": sl.stripped, "has_swift": sl.has_swift, "has_objc": sl.has_objc,
        "has_cpp": sl.has_cpp, "signed": sl.has_code_signature,
        "team_id": sig.team_id if sig else None,
        "entitlements_keys": sig.entitlement_keys if sig else [],
        # additive fields (not part of the frozen minimum)
        "symbol_level": sl.symbol_level, "has_stack_canary": sl.has_stack_canary, "uses_arc": sl.uses_arc,
        "simulator": sl.is_simulator, "offset": sl.offset, "size": sl.size,
        "signature": None, "entitlements": None,
    }
    if sig is not None:
        sd = sig.to_dict()
        sd.pop("entitlement_keys", None)
        rec["signature"] = sd
        if isinstance(sig.entitlements, dict):
            rec["entitlements"] = to_jsonable_plist(sig.entitlements)
    return rec


def _binary_record(name: str, rel: str, role: str, size: int, mf: MachOFile) -> Dict[str, Any]:
    ordered = list(mf.slices)
    pref = mf.select_slice()
    if pref is not None:
        ordered.remove(pref)
        ordered.insert(0, pref)
    dylibs: List[Dict[str, Any]] = []
    seen: set = set()
    rpaths: List[str] = []
    for sl in ordered:
        for d in sl.dylibs:
            key = (d.path, d.load_kind)
            if key not in seen:
                seen.add(key)
                dylibs.append(d.to_dict())
        for rp in sl.rpaths:
            if rp not in rpaths:
                rpaths.append(rp)
    warnings: List[str] = []
    for w in mf.all_warnings:
        if w not in warnings:
            warnings.append(w)
    return {
        "path": name, "rel": rel, "role": role,
        "kind": mf.slices[0].filetype_name if mf.slices else "unknown",
        "size": size, "is_fat": mf.is_fat,
        "slices": [_slice_record(sl) for sl in mf.slices],
        "dylibs": dylibs, "rpaths": rpaths, "parse_warnings": warnings,
    }


def _summarise(binaries: List[Dict[str, Any]]) -> Dict[str, Any]:
    main = next((b for b in binaries if b["role"] == "main"), None)
    all_slices = [s for b in binaries for s in b["slices"]]
    scope = main["slices"] if main else all_slices
    archs: List[str] = []
    for s in scope:
        if s["arch"] not in archs:
            archs.append(s["arch"])
    if not main:
        archs.sort()
    min_os = None
    if main and main["slices"]:
        arm = next((s for s in main["slices"] if s["arch"].startswith("arm64")), main["slices"][0])
        min_os = arm["min_os"]
    hints = []
    for key, label in (("has_objc", "objc"), ("has_swift", "swift"), ("has_cpp", "cpp")):
        if any(s[key] for s in scope):
            hints.append(label)
    return {
        "main_binary": main["path"] if main else None,
        "any_encrypted": any(s["encrypted"] for s in all_slices),
        "all_encrypted": bool(all_slices) and all(s["encrypted"] for s in all_slices),
        "archs": archs, "min_os": min_os, "languages_hint": hints,
        "encrypted_binaries": [b["path"] for b in binaries if any(s["encrypted"] for s in b["slices"])],
        "binaries_total": len(binaries),
        "main_encrypted": any(s["encrypted"] for s in main["slices"]) if main else None,
    }


def _finding(summary: Dict[str, Any], binaries: List[Dict[str, Any]], total: int) -> Finding:
    parsed = len(binaries)
    main = summary["main_binary"]
    enc = summary["encrypted_binaries"]
    evidence: List[Evidence] = []
    if main:
        mb = next(b for b in binaries if b["path"] == main)
        evidence.append(Evidence("macho", main, ", ".join(
            "%s %s encrypted=%s" % (s["arch"], s["filetype"], "yes" if s["encrypted"] else "no")
            for s in mb["slices"])))
    for path in enc[:_MAX_EVIDENCE]:
        if path == main:
            continue
        b = next(x for x in binaries if x["path"] == path)
        s = next(x for x in b["slices"] if x["encrypted"])
        evidence.append(Evidence("macho", path, "cryptid=%s cryptsize=%s" % (s["cryptid"], s["cryptsize"])))
    if parsed:
        verdict, conf = Verdict.YES, (0.95 if main else 0.7)
    else:
        verdict, conf = Verdict.UNKNOWN, 0.3
    params = {"parsed": parsed, "total": total, "main": main or "-", "archs": ", ".join(summary["archs"]) or "-",
              "encrypted_binaries": len(enc), "any_encrypted": summary["any_encrypted"]}
    text = "Parsed %d of %d Mach-O file(s); main binary: %s; architectures: %s; binaries with FairPlay " \
           "encryption: %d." % (parsed, total, params["main"], params["archs"], len(enc))
    remediation = ""
    if summary["any_encrypted"]:
        remediation = ("Some binaries are FairPlay-encrypted; static analysis of their code needs a decrypted IPA "
                       "supplied by the user. This tool never decrypts.")
    return Finding("macho.summary", verdict, conf, "Mach-O binaries analysed", text, params, evidence,
                   remediation, tags=["macho"])


# --- stage -------------------------------------------------------------------------------------
@register(name='macho', requires=('inventory',))
class MachoStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        inv = ctx.results.get("inventory") or {}
        cands = _candidates(ctx, inv)
        warnings: List[str] = []
        failed: List[str] = []
        records: List[Dict[str, Any]] = []

        # Parse each candidate once and keep only plain records (the mmap is closed right away).
        for cand in cands:
            name = cand["path"]
            rel = ctx.rel(name) or name
            size = int(cand.get("size") or 0)
            local = ctx.extract([name]).get(name)
            if local is None:
                warnings.append("cannot extract %s" % name)
                failed.append(name)
                continue
            try:
                with parse(local) as mf:
                    rec = _binary_record(name, rel, "other", size or mf.size, mf)
            except NotMachO as exc:
                warnings.append("%s is not a Mach-O file: %s" % (name, exc))
                failed.append(name)
                continue
            except MachOError as exc:
                warnings.append("%s is a malformed Mach-O file: %s" % (name, exc))
                failed.append(name)
                continue
            except OSError as exc:
                warnings.append("cannot read %s: %s" % (name, exc))
                failed.append(name)
                continue
            records.append(rec)

        top_level = [(r["rel"], r["kind"]) for r in records if "/" not in r["rel"]]
        main_rel = pick_main(top_level, _read_main_executable(ctx), _app_dir_stem(ctx))
        for rec in records:
            rec["role"] = classify_role(rec["rel"], main_rel)
        if records and main_rel is None:
            warnings.append("main executable could not be identified")

        binaries = sorted(records, key=lambda b: b["path"])
        summary = _summarise(binaries)
        data: Dict[str, Any] = {"binaries": binaries, "summary": summary}
        if failed:
            data["failed"] = sorted(failed)
        findings = [_finding(summary, binaries, len(cands))]
        if not cands:
            warnings.append("no Mach-O files found in the inventory")
        if failed:
            return StageResult.partial(NAME, data, findings, warnings,
                                       reason="%d of %d Mach-O file(s) could not be parsed" % (len(failed), len(cands)))
        return StageResult.ok(NAME, data, findings, warnings)
