"""GameMaker checker: the ``FORM`` data file (``game.ios`` / ``data.win`` ...) -> ``engine.pak.encrypted``.

The data file is an IFF-style container: ``FORM`` + u32 LE length, followed by chunks (4 byte id + u32 LE length +
payload) starting with ``GEN8``.  If the chunk headers tile the whole file the container is structurally intact,
which is evidence against whole-file encryption (individual assets could still be transformed).
UNVERIFIED: the container layout (taken from the community-documented ``data.win`` format; the official
documentation could not be fetched) and the iOS file name ``game.ios``.  Detection only.
"""
from __future__ import annotations

import struct
from typing import Any, Dict, List

from ...models import Evidence, Status, Verdict
from ..api import CheckerResult, DetectResult, register_checker
from ..formats import common
from ..formats.common import FileIndex


def walk_form(read_at, size: int, max_chunks: int) -> Dict[str, Any]:
    """Walk the chunk headers of a FORM file.  Returns ``{valid, chunks, tiled, first, stopped}``."""
    head = read_at(0, 8)
    out: Dict[str, Any] = {"valid": False, "chunks": 0, "tiled": False, "first": None, "stopped": None}
    if head[:4] != b"FORM" or len(head) < 8:
        return out
    length = struct.unpack_from("<I", head, 4)[0]
    out["declared_length_matches"] = length + 8 == size
    pos = 8
    names: List[str] = []
    while pos + 8 <= size and len(names) < max_chunks:
        h = read_at(pos, 8)
        if len(h) < 8:
            break
        cid = h[:4]
        clen = struct.unpack_from("<I", h, 4)[0]
        if not all(65 <= b <= 90 or 48 <= b <= 57 for b in cid) or pos + 8 + clen > size:
            out["stopped"] = "bad_chunk@%d" % pos
            break
        names.append(cid.decode("ascii"))
        pos += 8 + clen
    out["chunks"] = len(names)
    out["first"] = names[0] if names else None
    out["names"] = names[:12]
    out["tiled"] = pos == size and bool(names)
    out["valid"] = bool(names) and names[0] == "GEN8"
    return out


@register_checker("gamemaker")
class GameMakerChecker:
    engine_id = "gamemaker"

    def applies(self, ctx: Any, detect: DetectResult) -> bool:
        if detect.has("gamemaker"):
            return True
        return bool(FileIndex(ctx).find(common.checks("gamemaker")["data_file_regex"]))

    def run(self, ctx: Any, detect: DetectResult) -> CheckerResult:
        cfg = common.checks("gamemaker")
        idx = FileIndex(ctx)
        files = idx.find(cfg["data_file_regex"])[:cfg["max_files"]]
        items: List[Dict[str, Any]] = []
        intact = unknown = 0
        ev: List[Evidence] = []
        for r in files:
            info = walk_form(lambda off, n, p=r.path: common.read_at(ctx, p, off, n), r.size, cfg["max_chunks"])
            items.append({"path": r.rel, "size": r.size, **info})
            if info["valid"] and info["tiled"]:
                intact += 1
                ev.append(Evidence("file", r.rel, "FORM container, %d chunks tile the file, first chunk GEN8" % info["chunks"]))
            else:
                unknown += 1
                ev.append(Evidence("file", r.rel, "FORM structure not intact (%s)" % (info.get("stopped") or "header")))
        total = len(items)
        if total == 0:
            verdict, conf, note = Verdict.UNKNOWN, 0.1, "No GameMaker data file found."
        elif unknown:
            verdict, conf = Verdict.SUSPECTED, 0.5
            note = ("The data file does not parse as an intact FORM / GEN8 container; this fits encryption or a changed "
                    "format but can also be a different version of the format.")
        else:
            verdict, conf = Verdict.NO, 0.6
            note = ("The data file is an intact FORM container (chunk headers tile the file); asset payloads were not "
                    "inspected.")
        f = common.pak_finding("gamemaker", "GameMaker", verdict, conf, total, 0, unknown, ev, note)
        return CheckerResult(findings=[f], data={"data_files": items}, status=Status.OK)
