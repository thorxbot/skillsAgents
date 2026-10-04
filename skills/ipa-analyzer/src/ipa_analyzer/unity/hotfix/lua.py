"""Lua profile: classify every candidate script and aggregate a version picture.

Per candidate (loose file or chunk found in a container) the head decides between ``plain``,
``bytecode`` (with version / bit width / stripped flag via ``formats.lua_bytecode``), ``compressed``
(``formats.compress_sniff``), ``encrypted_suspected`` (a short XOR key that turns the head into a valid
Lua header, base64-looking text, or high entropy without structure) and ``unknown``.  Compressed is not
encrypted and bytecode is not encrypted; high entropy alone is only ``suspected``.

The aggregate adds the runtime version strings found in native code, cross-checks them against the
bytecode versions (a Lua 5.1 chunk cannot run on a 5.3 VM; LuaJIT bytecode needs LuaJIT) and raises
``custom_lua_suspected`` for tampered headers.  A clean header never proves stock Lua: opcode re-mapping is
invisible from the header, which the summary says explicitly.

Known documented header variant: xLua builds with ``LUAC_COMPATIBLE_FORMAT`` omit the ``sizeof(size_t)``
byte from the Lua 5.3 header (Tencent/xLua build/lua-5.3.5/src/ldump.c and lundump.c, fetched 2026-10-04);
such chunks are reported as 5.3 with ``variants.xlua_compat_header`` instead of as tampered.
"""
from __future__ import annotations

import re
import struct
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from ...formats import compress_sniff, lua_bytecode, lua_source
from ...util.entropy import shannon
from .storage import Blob

__all__ = ["LuaClass", "classify_blob", "analyze", "protection_verdict"]

_B64 = re.compile(rb"^[A-Za-z0-9+/=\r\n]+$")
_HIGH_ENTROPY = 7.2
_MAX_SAMPLES = 20


@dataclass
class LuaClass:
    cls: str                            # plain | bytecode | compressed | encrypted_suspected | unknown
    version_key: Optional[str] = None   # "5.3" / "luajit_2.1"
    bits: Optional[int] = None
    stripped: Optional[bool] = None
    tampered: bool = False
    tamper_signals: List[str] = field(default_factory=list)
    variant: str = ""
    reason: str = ""
    dialect: Optional[lua_source.DialectHints] = None


def _xlua_compat_53(head: bytes) -> bool:
    """5.3 header without the ``sizeof(size_t)`` byte (xLua ``LUAC_COMPATIBLE_FORMAT``)."""
    if len(head) < 32 or head[:4] != lua_bytecode.LUA_SIGNATURE or head[4] != 0x53 or head[5] != 0:
        return False
    if head[6:12] != lua_bytecode.LUAC_DATA:
        return False
    sz_int, sz_instr, sz_integer, sz_number = head[12], head[13], head[14], head[15]
    if sz_int not in (4, 8) or sz_instr != 4 or sz_integer not in (4, 8) or sz_number not in (4, 8):
        return False
    pos = 16
    raw_int = head[pos:pos + sz_integer]
    pos += sz_integer
    raw_num = head[pos:pos + sz_number]
    if len(raw_int) != sz_integer or len(raw_num) != sz_number:
        return False
    ok_int = any(int.from_bytes(raw_int, e) == lua_bytecode.LUAC_INT for e in ("little", "big"))
    fmt = {4: "f", 8: "d"}[sz_number]
    ok_num = any(struct.unpack(o + fmt, raw_num)[0] == lua_bytecode.LUAC_NUM for o in ("<", ">"))
    return ok_int and ok_num


def _looks_text(sample: bytes) -> bool:
    if not sample:
        return False
    s = sample[:8192]
    if s.startswith(b"\xef\xbb\xbf"):
        s = s[3:]
    bad = sum(1 for b in s if b < 9 or (13 < b < 32 and b != 27) or b == 0x7F)
    if bad / max(1, len(s)) > 0.01:
        return False
    try:
        s.decode("utf-8")
    except UnicodeDecodeError as exc:
        if exc.start < len(s) - 4:       # a multi-byte character cut at the end is fine
            return False
    return True


def classify_blob(blob: Blob) -> LuaClass:
    head = blob.head
    info = lua_bytecode.parse_header(head)
    if info.signature_ok:
        if info.valid:
            return LuaClass("bytecode", info.version_key, info.bits, info.stripped)
        if _xlua_compat_53(head):
            return LuaClass("bytecode", "5.3", None, None, variant="xlua_compat_header")
        return LuaClass("bytecode", info.version_key, info.bits, info.stripped, tampered=True,
                        tamper_signals=list(info.tamper_signals), reason="header deviates from the official layout")
    guess = compress_sniff.sniff(head)
    if guess.kind != "none" and guess.confidence >= 0.6:
        return LuaClass("compressed", reason=guess.kind)
    xor = lua_bytecode.looks_like_lua_after_xor(head)
    if xor is not None:
        return LuaClass("encrypted_suspected", xor.info.version_key, xor.info.bits, xor.info.stripped, tampered=True,
                        variant="xor_lua_header", reason="xor key hypothesis %s" % xor.key.hex())
    sample = blob.sample or head
    if _looks_text(sample):
        if _B64.match(sample[:4096].strip()) and len(sample) >= 64 and b" " not in sample[:4096]:
            return LuaClass("encrypted_suspected", reason="base64-looking text without Lua syntax")
        return LuaClass("plain", dialect=lua_source.infer_dialect(sample))
    if len(sample) >= 256 and shannon(sample[:SAMPLE_ENTROPY_BYTES]) >= _HIGH_ENTROPY:
        return LuaClass("encrypted_suspected", reason="high entropy, no known magic")
    return LuaClass("unknown", reason="binary data with unknown structure")


SAMPLE_ENTROPY_BYTES = 16384


def _series(version_key: str) -> str:
    return version_key.replace("luajit_", "")


def analyze(blobs: Iterable[Blob], runtime_versions: List[Dict[str, Any]], *,
            framework_hints: Optional[Dict[str, List[Dict[str, Any]]]] = None,
            named_only: int = 0, text_hint_containers: int = 0, native_limited: bool = False) -> Dict[str, Any]:
    """Aggregate classified Lua candidates into the contract's ``lua`` block."""
    classes = Counter()
    by_version: Counter = Counter()
    bits: Counter = Counter()
    variants: Counter = Counter()
    tamper: Counter = Counter()
    stripped = invalid = 0
    where: Counter = Counter()
    samples: List[Dict[str, Any]] = []
    min_versions: Counter = Counter()
    lj_signals: set = set()
    style_hints: Counter = Counter()
    xor_keys: List[str] = []
    total = 0
    for blob in blobs:
        c = classify_blob(blob)
        total += 1
        classes[c.cls] += 1
        where[blob.source] += 1
        if c.cls == "bytecode":
            if c.tampered:
                invalid += 1
                tamper.update(c.tamper_signals or ["unspecified"])
            else:
                by_version[c.version_key or "unknown"] += 1
                if c.bits:
                    bits[str(c.bits)] += 1
                if c.stripped:
                    stripped += 1
            if c.variant:
                variants[c.variant] += 1
        elif c.cls == "encrypted_suspected" and c.variant == "xor_lua_header":
            variants[c.variant] += 1
            if c.reason not in xor_keys:
                xor_keys.append(c.reason)
        if c.dialect is not None:
            if c.dialect.min_version:
                min_versions[c.dialect.min_version] += 1
            lj_signals.update(c.dialect.luajit_signals)
            style_hints.update(c.dialect.style_hints)
        if len(samples) < _MAX_SAMPLES:
            samples.append({"path": blob.container, "name": blob.name, "source": blob.source, "class": c.cls,
                            "version": c.version_key, "tampered": c.tampered or None, "reason": c.reason or None})

    rts = sorted((dict(r) for r in runtime_versions), key=lambda r: (-float(r.get("confidence", 0)), r.get("version", "")))
    dialect_hints: List[str] = []
    if min_versions:
        top = max(min_versions, key=lambda v: (v, min_versions[v]))
        dialect_hints.append("plain source needs Lua >= %s (%d file(s) with version-specific syntax; %s)" % (
            top, sum(min_versions.values()), ", ".join("%s:%d" % kv for kv in sorted(min_versions.items()))))
    if lj_signals:
        dialect_hints.append("LuaJIT-specific constructs in plain source: %s" % ", ".join(sorted(lj_signals)))
    if style_hints:
        dialect_hints.append("Lua 5.1-style API usage (%s): consistent with 5.1 or LuaJIT, not conclusive"
                             % ", ".join(sorted(style_hints)))

    consistency = _consistency(by_version, rts, framework_hints or {}, native_limited)
    custom = bool(invalid or variants.get("xor_lua_header"))
    notes: List[str] = ["a standard header does not rule out a customised VM (opcode re-mapping is not visible from the header)"]
    if invalid:
        notes.append("%d bytecode chunk(s) have a header that deviates from the official layout" % invalid)
    if variants.get("xor_lua_header"):
        notes.append("%d chunk(s) become valid Lua headers under a short XOR key hypothesis (evidence only)" % variants["xor_lua_header"])
    return {
        "runtime_versions": [{k: r.get(k) for k in ("flavor", "version", "source", "confidence", "series", "ref") if r.get(k) is not None}
                             for r in rts],
        "bytecode": {"by_version": dict(sorted(by_version.items())), "invalid": invalid, "stripped_count": stripped,
                     "arch_bits": dict(sorted(bits.items())), "variants": dict(sorted(variants.items())),
                     "tamper_signals": dict(sorted(tamper.items()))},
        "files": {"plain": classes["plain"], "bytecode": classes["bytecode"], "compressed": classes["compressed"],
                  "encrypted_suspected": classes["encrypted_suspected"], "unknown": classes["unknown"], "total": total},
        "dialect_hints": dialect_hints,
        "consistency": consistency,
        "custom_lua_suspected": custom,
        "notes": notes,
        "storage": {"loose": where["loose"], "in_bundles": where["bundle"], "in_serialized": where["serialized"],
                    "named_in_containers_unclassified": named_only,
                    "containers_with_plain_text_hints": text_hint_containers},
        "samples": samples,
    }


def _consistency(by_version: Counter, runtimes: List[Dict[str, Any]],
                 fw_hints: Dict[str, List[Dict[str, Any]]], native_limited: bool) -> Dict[str, Any]:
    notes: List[str] = []
    ok = True
    strong = [r for r in runtimes if float(r.get("confidence", 0)) >= 0.6]
    rt_puc = {r.get("series") or str(r.get("version", ""))[:3] for r in strong if r.get("flavor") == "puc"}
    rt_lj = [r for r in strong if r.get("flavor") == "luajit"]
    if len(by_version) > 1:
        ok = False
        notes.append("bytecode of several Lua versions is present (%s): possibly several VMs"
                     % ", ".join("%s x%d" % kv for kv in sorted(by_version.items())))
    checked = bool(by_version) and bool(strong)
    if by_version and strong:
        for vk in by_version:
            if vk.startswith("luajit_"):
                if not rt_lj:
                    ok = False
                    notes.append("%s bytecode found but no LuaJIT runtime string/symbol (runtime reports PUC Lua %s)"
                                 % (vk, ", ".join(sorted(rt_puc)) or "?"))
            else:
                if vk not in rt_puc:
                    # LuaJIT also reports "Lua 5.1" as LUA_VERSION; PUC 5.1 bytecode still cannot run on LuaJIT
                    ok = False
                    notes.append("Lua %s bytecode found but the native runtime reports %s: mismatch (multiple VMs or a modified runtime)"
                                 % (vk, ", ".join(sorted(rt_puc) + ["LuaJIT " + r["version"] for r in rt_lj]) or "?"))
    elif by_version and not strong:
        notes.append("no runtime Lua version string found in the (unencrypted part of the) native code%s: cross-check not possible"
                     % ("; the binary is encrypted" if native_limited else ""))
    elif strong and not by_version:
        notes.append("runtime version known but no bytecode sample to compare against")
    for fw, hints in fw_hints.items():
        want = {("luajit" if h.get("flavor") == "luajit" else "puc"): h for h in hints if h.get("verified")}
        if by_version and want:
            has_lj = any(v.startswith("luajit_") for v in by_version)
            has_puc = any(not v.startswith("luajit_") for v in by_version)
            if "luajit" in want and "puc" not in want and has_puc and not has_lj:
                notes.append("%s defaults to LuaJIT on iOS but only PUC Lua bytecode was found: measured data wins" % fw)
    return {"ok": ok, "checked": checked, "notes": notes}


def protection_verdict(lua: Dict[str, Any], *, containers_unreadable: int, any_lua_signal: bool,
                       coverage_limited: bool = False) -> Dict[str, Any]:
    """Tri-state protection verdict for Lua scripts (never ``yes``: encryption is not provable here)."""
    f = lua["files"]
    if f["total"] == 0:
        if any_lua_signal:
            return {"verdict": "unknown", "confidence": 0.3,
                    "reason": "Lua is in use but no script could be inspected%s" % (
                        " (%d container(s) unreadable)" % containers_unreadable if containers_unreadable else "")}
        if coverage_limited:
            return {"verdict": "unknown", "confidence": 0.3,
                    "reason": "no scripts observed, but coverage is limited (unreadable containers / encrypted binary)"}
        return {"verdict": "n/a", "confidence": 0.5, "reason": "no Lua scripts observed"}
    if lua["custom_lua_suspected"] or f["encrypted_suspected"]:
        return {"verdict": "suspected", "confidence": 0.8 if lua["bytecode"]["variants"].get("xor_lua_header") else 0.65,
                "reason": "scripts with tampered headers, XOR-able headers or high entropy"}
    if f["plain"] or f["bytecode"]:
        return {"verdict": "no", "confidence": 0.7,
                "reason": "plain source and/or standard bytecode (compiled is not encrypted); only a sample was inspected"}
    return {"verdict": "unknown", "confidence": 0.3, "reason": "scripts are compressed or of unknown format"}
