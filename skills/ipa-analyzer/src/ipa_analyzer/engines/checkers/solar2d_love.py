"""Solar2D / Corona and LOVE checker -> ``engine.resource.encrypted``.

* Solar2D: ``resource.car`` (compiled Lua 5.1 bytecode in one archive; the decompiler site documenting it states
  that the container is neither compressed nor encrypted -- single source, UNVERIFIED).  The file is scanned for
  Lua chunk headers (``formats.lua_bytecode``) to report the bytecode version profile; valid Lua 5.1 headers
  inside are evidence that the payload is not encrypted.
* LOVE: ``*.love`` files are ZIP archives; the zip "encrypted" flag of each entry is counted (names and flags are
  read from the central directory only), and the first bytes of ``.lua`` entries are classified.
Detection only.
"""
from __future__ import annotations

import zipfile
from typing import Any, Dict, List

from ...formats import lua_bytecode, magic_scan
from ...models import Evidence, Status, Verdict
from ..api import CheckerResult, DetectResult, register_checker
from ..formats import common, lua_profile
from ..formats.common import FileIndex, ScriptTally


def _scan_car(ctx: Any, path: str, size: int, cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Count Lua chunk headers in ``resource.car`` (bounded read)."""
    limit = min(size, cfg["car_scan_max_bytes"])
    prof = lua_profile.LuaProfiler()
    found = 0
    with ctx.source.open(path) as fh:
        def chunks():
            remaining = limit
            while remaining > 0:
                b = fh.read(min(1 << 20, remaining))
                if not b:
                    break
                remaining -= len(b)
                yield b
        pats = (magic_scan.literal("lua", lua_bytecode.LUA_SIGNATURE), magic_scan.literal("luajit", lua_bytecode.LUAJIT_SIGNATURE))
        res = magic_scan.scan_stream(chunks(), pats, max_hits=cfg["car_max_hits"], context_after=64)
    for h in res.hits:
        info = lua_bytecode.parse_header(h.match + _after(h))
        blob = common.BlobInfo(common.K_LUA_BC if info.valid else common.K_LUA_BC_TAMPERED, {"lua": info})
        prof.add(blob)
        found += 1
    return {"scanned_bytes": limit, "of": size, "headers_found": found, "profile": prof.to_dict()}


def _after(hit: Any) -> bytes:
    """Bytes following the match inside the hit context (the context window starts a little before the match)."""
    ctx_b = hit.context
    i = ctx_b.find(hit.match)
    return ctx_b[i + len(hit.match):] if i >= 0 else b""


@register_checker("solar2d_love")
class Solar2dLoveChecker:
    engine_id = "solar2d_love"

    def applies(self, ctx: Any, detect: DetectResult) -> bool:
        if detect.has("solar2d") or detect.has("love2d"):
            return True
        idx = FileIndex(ctx)
        return bool(idx.find(common.checks("solar2d_love")["markers_regex"]))

    def run(self, ctx: Any, detect: DetectResult) -> CheckerResult:
        cfg = common.checks("solar2d_love")
        idx = FileIndex(ctx)
        data: Dict[str, Any] = {"solar2d": None, "love": []}
        ev: List[Evidence] = []
        enc_entries = 0
        unknown = 0
        clear = 0
        warnings: List[str] = []
        cars = idx.find(r"(^|/)resource\.car$")
        if cars:
            r = cars[0]
            try:
                scan = _scan_car(ctx, r.path, r.size, cfg)
            except Exception as exc:  # noqa: BLE001 - report as unreadable
                scan = {"error": "%s: %s" % (type(exc).__name__, exc), "headers_found": 0}
                warnings.append("resource.car could not be scanned: %s" % type(exc).__name__)
            data["solar2d"] = {"path": r.rel, "size": r.size, **scan}
            valid51 = (scan.get("profile") or {}).get("bytecode", {}).get("by_version", {}).get("5.1", 0)
            if valid51:
                clear += 1
                ev.append(Evidence("file", r.rel, "%d valid Lua 5.1 bytecode headers inside" % valid51))
            else:
                unknown += 1
                ev.append(Evidence("file", r.rel, "no Lua bytecode header found inside (encrypted, other layout or unreadable)"))
        for r in idx.with_ext(".love")[:cfg["max_love"]]:
            item: Dict[str, Any] = {"path": r.rel, "size": r.size}
            try:
                with ctx.source.open(r.path) as fh:
                    zf = zipfile.ZipFile(fh)
                    infos = zf.infolist()
                    enc = sum(1 for i in infos if i.flag_bits & 0x1)
                    item.update(entries=len(infos), encrypted_entries=enc,
                                has_main_lua=any(i.filename == "main.lua" for i in infos))
                    tally = ScriptTally()
                    for i in [x for x in infos if x.filename.endswith(".lua")][:cfg["love_lua_sample"]]:
                        if i.flag_bits & 0x1:
                            continue
                        head = zf.open(i).read(cfg["head_bytes"])
                        tally.add(i.filename, ".lua", common.classify_blob(head, i.file_size))
                    item["lua"] = tally.to_dict()
                    if enc:
                        enc_entries += enc
                        ev.append(Evidence("file", r.rel, "%d zip entries have the encryption flag" % enc))
                    else:
                        clear += 1
            except (zipfile.BadZipFile, OSError, NotImplementedError, RuntimeError) as exc:
                item["error"] = type(exc).__name__
                unknown += 1
            data["love"].append(item)
        total = (1 if data["solar2d"] else 0) + len(data["love"])
        if enc_entries:
            verdict, conf, note = Verdict.YES, 0.95, "Zip entries carry the encryption flag."
        elif total == 0:
            verdict, conf, note = Verdict.UNKNOWN, 0.1, "No resource.car / .love archive found."
        elif unknown:
            verdict, conf, note = Verdict.UNKNOWN, 0.3, "Some archives could not be judged."
        else:
            verdict, conf = Verdict.NO, 0.6
            note = "Archive contents look unencrypted (valid Lua bytecode headers / no zip encryption flags); bytecode is not encryption."
        tally_d = {"total": total, "plain": clear, "suspected_encrypted": 0, "counts": {"sampled": total}}
        f = common.resource_finding("solar2d_love", "Solar2D / LOVE", tally_d, verdict, conf,
                                    "encrypted" if verdict == Verdict.YES else ("plain" if verdict == Verdict.NO else "unknown"),
                                    ev, note, encrypted=enc_entries)
        return CheckerResult(findings=[f], data=data, status=Status.OK, warnings=warnings)
