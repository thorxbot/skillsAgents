"""Defold checker: ``game.arci`` / ``game.arcd`` resource archive -> ``engine.resource.encrypted``.

Archive index layout (Source: defold/defold ``engine/resource/src/resource_archive.h`` + ``resource_archive.cpp``,
all integers big-endian on disk -- the code converts with ``dmEndian::ToNetwork``)::

    u32 version (6)  | u32 pad | u64 userdata | u32 entry count | u32 entry offset | u32 hash offset |
    u32 hash length  | u8 md5[16]                                   (header = 48 bytes)
    entry (16 bytes): u64 offset-and-flags (flags = high 4 bits: 1 encrypted, 2 compressed, 4 live-update data),
                      u32 size, u32 compressed size (0xFFFFFFFF = not compressed)

The names ``game.arci`` / ``game.arcd`` (index / data) appear in the header comments; ``game.projectc`` and
``game.dmanifest`` are UNVERIFIED as bundle file names.  Versions other than 6 are reported as unknown.
Detection only; nothing is decrypted.
"""
from __future__ import annotations

import struct
from typing import Any, Dict, List

from ...models import Evidence, Status, Verdict
from ..api import CheckerResult, DetectResult, register_checker
from ..formats import common
from ..formats.common import FileIndex

ENTRY_SIZE = 16
HEADER_SIZE = 48
FLAG_ENCRYPTED = 1
FLAG_COMPRESSED = 2
FLAG_SHIFT = 60
KNOWN_VERSION = 6


@register_checker("defold")
class DefoldChecker:
    engine_id = "defold"

    def applies(self, ctx: Any, detect: DetectResult) -> bool:
        if detect.has("defold"):
            return True
        idx = FileIndex(ctx)
        return any(idx.find(rx) for rx in common.checks("defold")["markers"])

    def run(self, ctx: Any, detect: DetectResult) -> CheckerResult:
        cfg = common.checks("defold")
        idx = FileIndex(ctx)
        archives: List[Dict[str, Any]] = []
        enc = unknown = clear = 0
        ev: List[Evidence] = []
        for r in idx.find(r"(^|/)[^/]+\.arci$")[:cfg["max_archives"]]:
            item: Dict[str, Any] = {"path": r.rel, "size": r.size, "data_present": idx.exists(r.rel[:-1] + "d")}
            head = common.read_head(ctx, r.path, HEADER_SIZE)
            if len(head) < HEADER_SIZE:
                item["status"] = "truncated"
                unknown += 1
                archives.append(item)
                continue
            version, = struct.unpack_from(">I", head, 0)
            count, entry_off = struct.unpack_from(">II", head, 16)
            item.update(version=version, entries=count)
            if version != KNOWN_VERSION:
                item["status"] = "unsupported_version"
                unknown += 1
                archives.append(item)
                continue
            n = min(count, cfg["max_entries"])
            if entry_off + n * ENTRY_SIZE > r.size or count == 0:
                item["status"] = "inconsistent"
                unknown += 1
                archives.append(item)
                continue
            raw = common.read_at(ctx, r.path, entry_off, n * ENTRY_SIZE)
            if len(raw) < n * ENTRY_SIZE:
                item["status"] = "truncated"
                unknown += 1
                archives.append(item)
                continue
            e = c = 0
            for i in range(n):
                (off_flags,) = struct.unpack_from(">Q", raw, i * ENTRY_SIZE)
                flags = off_flags >> FLAG_SHIFT
                e += 1 if flags & FLAG_ENCRYPTED else 0
                c += 1 if flags & FLAG_COMPRESSED else 0
            item.update(status="read", entries_read=n, encrypted_entries=e, compressed_entries=c)
            if e:
                enc += 1
                ev.append(Evidence("file", r.rel, "%d of %d entries have the encrypted flag" % (e, n)))
            else:
                clear += 1
            archives.append(item)
        total = len(archives)
        if enc:
            verdict, conf = Verdict.YES, 0.95
            note = "Entries carry the archive's encrypted flag (the key is not looked for)."
        elif total == 0:
            verdict, conf = Verdict.UNKNOWN, 0.1
            note = "No game.arci archive index found."
        elif unknown:
            verdict, conf = Verdict.UNKNOWN, 0.3
            note = "Some archive indexes could not be read."
        else:
            verdict, conf = Verdict.NO, 0.8
            note = "No entry is flagged encrypted (compression is not encryption)."
        markers = [r.rel for rx in cfg["markers"] for r in idx.find(rx)][:8]
        f = common.pak_finding("defold", "Defold", verdict, conf, total, enc, unknown, ev, note)
        return CheckerResult(findings=[f], data={"archives": archives, "markers": markers}, status=Status.OK)
