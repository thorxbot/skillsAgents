"""Godot checker: ``.pck`` header / directory, compiled and encrypted scripts.

* ``.pck``: "GDPC" magic, pack format, engine version, directory-encryption flag, and (when the directory is not
  encrypted) per-file encryption flags and script file names.  Layout and sources: ``engines/formats/pck_godot.py``.
* loose ``.gd`` (plain), ``.gdc`` ("GDSC" compiled) and ``.gde`` ("GDEC" encrypted container).

Verdicts: encrypted directory / flagged files / ``GDEC`` files -> ``yes`` (documented by the engine source);
compiled scripts are labelled compiled, not encrypted.  Detection only.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ...models import Evidence, Status, Verdict
from ..api import CheckerResult, DetectResult, register_checker
from ..formats import common, pck_godot
from ..formats.common import FileIndex, FileRec, ScriptTally


def _pcks(idx: FileIndex) -> List[FileRec]:
    seen = {}
    for r in idx.with_ext(".pck") + idx.with_magic("gdpc"):
        seen[r.rel] = r
    return [seen[k] for k in sorted(seen)]


@register_checker("godot")
class GodotChecker:
    engine_id = "godot"

    def applies(self, ctx: Any, detect: DetectResult) -> bool:
        if detect.has("godot"):
            return True
        idx = FileIndex(ctx)
        return bool(idx.with_magic("gdpc") or idx.with_ext(".gdc", ".gde"))

    def run(self, ctx: Any, detect: DetectResult) -> CheckerResult:
        cfg = common.checks("godot")
        idx = FileIndex(ctx)
        packs: List[Dict[str, Any]] = []
        enc_packs = flagged = unknown = clear = 0
        ev: List[Evidence] = []
        script_ext_total: Dict[str, int] = {}
        for r in _pcks(idx)[:cfg["max_packs"]]:
            head = common.read_head(ctx, r.path, 128)
            info = pck_godot.parse_header(head)
            if info.valid:
                pck_godot.read_directory(info, lambda off, n, p=r.path: common.read_at(ctx, p, off, n), r.size,
                                         max_entries=cfg["max_entries"])
            packs.append({"path": r.rel, "size": r.size, **info.to_dict()})
            for k, v in info.script_files.items():
                script_ext_total[k] = script_ext_total.get(k, 0) + v
            if not info.valid:
                unknown += 1
                ev.append(Evidence("file", r.rel, "not a recognised Godot pack (%s)" % ("; ".join(info.warnings) or "bad header")))
            elif info.dir_encrypted:
                enc_packs += 1
                ev.append(Evidence("file", r.rel, "pack format %s: directory-encrypted flag set (engine %s)" % (
                    info.pack_format, info.engine_version)))
            elif info.file_encrypted_count:
                flagged += 1
                ev.append(Evidence("file", r.rel, "%d of %d read entries have the file-encrypted flag" % (
                    info.file_encrypted_count, info.entries_read)))
            elif info.directory_status == "read":
                clear += 1
            else:
                unknown += 1
                ev.append(Evidence("file", r.rel, "directory %s" % info.directory_status))
        total = len(packs)
        if enc_packs or flagged:
            pv, pc = Verdict.YES, 0.95
            pnote = "Encryption flags are set in the pack (the key is not looked for)."
        elif total == 0:
            pv, pc = Verdict.UNKNOWN, 0.1
            pnote = "No .pck file in the bundle (the pack may be embedded in the executable, which is not searched)."
        elif unknown:
            pv, pc = Verdict.UNKNOWN, 0.3
            pnote = "Some packs could not be read."
        else:
            pv, pc = Verdict.NO, 0.8
            pnote = "Directory and examined entries carry no encryption flag."
        findings = [common.pak_finding("godot", "Godot", pv, pc, total, enc_packs + flagged, unknown, ev, pnote,
                                       "Encrypted packs need the 256-bit script key embedded in the app; not extracted."
                                       if pv == Verdict.YES else "")]
        # scripts: loose files + names seen in the pack directory
        tally = ScriptTally()
        loose = idx.not_vendor(idx.with_ext(".gd", ".gdc", ".gde"))
        sample, ltotal = common.evenly_sample(loose, cfg["script_sample_max"])
        gdc = gde = 0
        for r in sample:
            head = common.read_head(ctx, r.path, 16)
            kind = pck_godot.classify_script_head(head)
            if kind == "gde":
                gde += 1
                tally.add(r.rel, r.ext, common.BlobInfo(common.K_HIGH_ENTROPY, {"gdec": True}))
            elif kind == "gdc":
                gdc += 1
                tally.add(r.rel, r.ext, common.BlobInfo(common.K_LUA_BC, {}))   # bucket "bytecode" (compiled)
            else:
                blob, _ = common.classify_file(ctx, r)
                tally.add(r.rel, r.ext, blob)
        scripts = tally.to_dict(sampled=len(sample), of=ltotal)
        scripts["in_pack_names"] = dict(sorted(script_ext_total.items()))
        in_pack_gde = script_ext_total.get("gde", 0)
        sev: List[Evidence] = []
        if gde or in_pack_gde or flagged:
            sv, sc, ss = Verdict.YES, 0.9, "suspected"
            note = "Encrypted GDScript (.gde / GDEC container) is present; the engine encrypts it with a key held by the app."
            sev.extend(common.file_evidence(tally.samples.get(common.K_HIGH_ENTROPY, []), "GDEC encrypted script", 3))
        else:
            sv, sc, ss = common.verdict_from_tally(tally, ltotal)
            if not tally.total and (script_ext_total.get("gdc") or script_ext_total.get("gd")):
                sv, sc, ss = (Verdict.NO, 0.6, "mixed")
                note = "Scripts exist only inside the pack (names read from its unencrypted directory): %s." % scripts["in_pack_names"]
            else:
                note = "Compiled GDScript (GDSC) is not encryption." if gdc else ""
        findings.append(common.script_finding("godot", "Godot", scripts, sv, sc, ss, sev, note))
        data = {"packs": packs, "scripts": scripts,
                "counts": {"packs": total, "encrypted_packs": enc_packs, "packs_with_flagged_files": flagged,
                           "unknown": unknown, "clear": clear}}
        return CheckerResult(findings=findings, data=data, status=Status.OK)
