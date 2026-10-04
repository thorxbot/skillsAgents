"""Unreal Engine checker: ``.pak`` footer and IoStore ``.utoc`` header -> ``engine.pak.encrypted``.

Only the *index* encryption flag (pak version >= 4) and the IoStore container ``Encrypted`` flag are read; a pak
whose index is not encrypted may still hold encrypted entries, which would need the index to be parsed -- not done,
the summary says so.  Truncated / unrecognisable containers give ``unknown``.  Footer layout and sources:
``engines/formats/pak_ue.py``.  Detection only: no key is looked for, nothing is decrypted.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ...models import Evidence, Status, Verdict
from ..api import CheckerResult, DetectResult, register_checker
from ..formats import common, pak_ue
from ..formats.common import FileIndex, FileRec


def _pak_candidates(idx: FileIndex) -> List[FileRec]:
    seen = {}
    for r in idx.with_ext(".pak") + idx.with_magic("ue_pak"):
        seen[r.rel] = r
    return [seen[k] for k in sorted(seen)]


@register_checker("unreal")
class UnrealChecker:
    engine_id = "unreal"

    def applies(self, ctx: Any, detect: DetectResult) -> bool:
        if detect.has("unreal"):
            return True
        idx = FileIndex(ctx)
        if idx.with_ext(".utoc"):
            return True
        cfg = common.checks("unreal")
        for r in _pak_candidates(idx)[:cfg["applies_probe_max"]]:
            if pak_ue.parse_footer(common.read_tail(ctx, r.path, r.size, pak_ue.TAIL_BYTES), r.size).valid:
                return True
        return False

    def run(self, ctx: Any, detect: DetectResult) -> CheckerResult:
        cfg = common.checks("unreal")
        idx = FileIndex(ctx)
        containers: List[Dict[str, Any]] = []
        enc = unknown = ok_plain = 0
        ev: List[Evidence] = []
        for r in _pak_candidates(idx)[:cfg["max_containers"]]:
            info = pak_ue.parse_footer(common.read_tail(ctx, r.path, r.size, pak_ue.TAIL_BYTES), r.size)
            item = {"path": r.rel, "kind": "pak", "size": r.size, **info.to_dict()}
            containers.append(item)
            if info.valid and info.index_encrypted:
                enc += 1
                ev.append(Evidence("file", r.rel, "pak v%s footer: index encrypted flag set" % info.version))
            elif info.valid and info.index_in_bounds and info.index_encrypted is False:
                ok_plain += 1
            elif info.valid and info.index_encrypted is None and info.index_in_bounds:
                ok_plain += 1       # version < 4 has no index encryption
            else:
                unknown += 1
                ev.append(Evidence("file", r.rel, info.note or "pak footer not usable"))
        for r in idx.with_ext(".utoc")[:cfg["max_containers"]]:
            head = common.read_head(ctx, r.path, 160)
            t = pak_ue.parse_utoc_header(head)
            item = {"path": r.rel, "kind": "iostore_utoc", "size": r.size, **t.to_dict()}
            partner = r.rel[:-5] + ".ucas"
            item["ucas_present"] = idx.exists(partner)
            containers.append(item)
            if t.valid and t.encrypted:
                enc += 1
                ev.append(Evidence("file", r.rel, "IoStore container flags: %s" % ", ".join(t.flag_names or [])))
            elif t.valid:
                ok_plain += 1
            else:
                unknown += 1
                ev.append(Evidence("file", r.rel, "IoStore header not recognised"))
        crypto = [r.rel for r in idx.find(cfg["crypto_config_regex"])][:5]
        data = {"containers": containers, "counts": {"total": len(containers), "encrypted": enc,
                                                     "not_encrypted": ok_plain, "unknown": unknown},
                "crypto_config_files": crypto, "engine_hint": "unreal"}
        total = len(containers)
        if enc:
            verdict, conf = Verdict.YES, 0.95
            note = "Encryption flag set in the container header (the key is not looked for)."
        elif total == 0:
            verdict, conf = Verdict.UNKNOWN, 0.1
            note = "No .pak / .utoc container was found (content may be loose files or downloaded later)."
        elif unknown:
            verdict, conf = Verdict.UNKNOWN, 0.3
            note = "Some containers are truncated or unrecognised, so they could not be judged."
        else:
            verdict, conf = Verdict.NO, 0.6
            note = ("No index / container encryption flag. Individual entries can still be encrypted inside an "
                    "unencrypted index (entries were not parsed), and compression is not encryption.")
        if crypto:
            ev.append(Evidence("file", crypto[0], "crypto configuration file present (contents not read)"))
        f = common.pak_finding("unreal", "Unreal Engine", verdict, conf, total, enc, unknown, ev, note,
                               "Encrypted paks need the AES key from the app; this tool does not extract keys."
                               if enc else "")
        return CheckerResult(findings=[f], data=data, status=Status.OK)
