"""Evidence gathering, signal matching and engine scoring (WP7).

``EvidenceBundle`` is a read-only, indexed view of one app: the file table (from ``inventory``), the
``Info.plist`` keys and what could be read from the Mach-O files (linked libraries, symbols, ObjC class
names, C strings, sections). Everything that lives inside a FairPlay encrypted range is ignored
(``skip_encrypted=True``) and the bundle remembers how much of the binaries was visible so that callers
can report "binary-based detection limited" instead of drawing conclusions from missing data.

Scoring model (explainable): every matching signal adds its weight once; ``score = sum(weights)``.
An engine is *confirmed* when a verified ``strong`` signal matched or ``score >= confirm_threshold``;
``confidence = min(0.99, score)`` (at least 0.9 for a strong hit). Pairs listed in ``exclusive_with`` are
resolved by keeping the better-supported engine and marking the other ``suppressed_by``.
"""
from __future__ import annotations

import bisect
import logging
import re
import time
import weakref
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ..models import Evidence
from .api import DetectResult, EngineMatch, EngineSignature, SignalSpec
from .signatures import ParsedPattern, SignatureSet, parse_pattern

log = logging.getLogger(__name__)

# --- limits (heuristic budgets, no external source) ------------------------------------------------
MAX_BINARIES = 24                      # Mach-O files whose contents are examined
MAX_SYMBOLS_PER_BINARY = 300_000
MAX_STRING_LEN = 200                   # longer C strings are data blobs, not identifiers
MAX_BLOB_PER_BINARY = 16 * 1024 * 1024
MAX_BLOB_TOTAL = 64 * 1024 * 1024
MAX_SECTION_BYTES_TOTAL = 256 * 1024 * 1024
BINARY_TIME_BUDGET_S = 40.0
HEAD_BYTES = 16
MAX_HEAD_FILES = 30_000
HEAD_TIME_BUDGET_S = 15.0
_EVIDENCE_REFS = 3

KIND_RANK = {"game_engine": 0, "cross_platform_ui": 0, "web_hybrid": 0, "open_source_lib": 1, "native": 2}
_SKIP_CSTRING_SECTIONS = {"__objc_methname", "__objc_methtype", "__objc_classname"}
_EVIDENCE_KIND = {"file": "file", "dir": "file", "string": "string", "symbol": "symbol", "objc_prefix": "symbol",
                  "dylib": "macho", "plist_key": "plist_key", "binary_section": "macho"}


# --- data holders -----------------------------------------------------------------------------------
@dataclass
class FileRec:
    path: str                  # archive name
    rel: str                   # relative to the .app root
    size: int = 0
    magic: str = "unknown"
    ext: str = ""
    category: str = "other"
    entropy: Optional[float] = None

    @property
    def lrel(self) -> str:
        return self.rel.lower()


@dataclass
class BinaryRec:
    """What was learned from one Mach-O file."""

    rel: str
    path: str = ""
    role: str = "other"
    size: int = 0
    encrypted: bool = False
    dylibs: List[str] = field(default_factory=list)
    symbols: Iterable[str] = field(default_factory=list)       # names without the Mach-O leading underscore
    classes: List[str] = field(default_factory=list)
    strings: List[bytes] = field(default_factory=list)
    sections: List[str] = field(default_factory=list)          # "SEG,sect"
    defined_symbols: int = 0
    defined_cpp: int = 0
    defined_objc_swift: int = 0
    own_classes: int = 0
    strings_skipped_encrypted: int = 0
    has_swift: bool = False
    has_objc: bool = False
    has_cpp: bool = False
    error: Optional[str] = None


@dataclass
class SignalMatch:
    spec: SignalSpec
    refs: List[str]
    count: int = 1
    detail: str = ""


@dataclass
class EngineScore:
    sig: EngineSignature
    matches: List[SignalMatch]
    score: float
    strong: bool
    confirmed: bool
    code_score: float = 0.0       # symbol/string/objc/dylib/section signals
    layout_score: float = 0.0     # file/dir/plist signals

    @property
    def confidence(self) -> float:
        if not self.matches:
            return 0.0
        c = min(0.99, self.score)
        return max(c, 0.9) if self.strong else c


# --- glob handling ----------------------------------------------------------------------------------
_GLOB_CACHE: Dict[str, "re.Pattern[str]"] = {}


def glob_to_regex(pat: str) -> "re.Pattern[str]":
    """Compile a lower-case glob (``*`` within a segment, ``**`` across segments, ``?``) to a regex."""
    rx = _GLOB_CACHE.get(pat)
    if rx is not None:
        return rx
    out: List[str] = []
    i, n = 0, len(pat)
    while i < n:
        c = pat[i]
        if c == "*":
            if pat.startswith("**/", i):
                out.append("(?:.*/)?")
                i += 3
                continue
            if pat.startswith("**", i):
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    rx = re.compile("".join(out) + r"\Z", re.DOTALL)
    _GLOB_CACHE[pat] = rx
    return rx


def _has_wild(p: str) -> bool:
    return "*" in p or "?" in p


def _literal_prefix(p: str) -> str:
    for i, c in enumerate(p):
        if c in "*?":
            return p[:i]
    return p


_EXT_ONLY_RE = re.compile(r"^\*(\.[a-z0-9_]+)$")


# --- the bundle ---------------------------------------------------------------------------------------
class EvidenceBundle:
    """Indexed evidence of one app (see module docstring)."""

    def __init__(self, files: Sequence[FileRec] = (), *, plist: Optional[Dict[str, str]] = None,
                 binaries: Sequence[BinaryRec] = (), heads: Optional[Dict[str, bytes]] = None,
                 head_loader: Optional[Callable[[], Dict[str, bytes]]] = None) -> None:
        self.files: List[FileRec] = list(files)
        self.plist: Dict[str, str] = dict(plist or {})
        self.binaries: List[BinaryRec] = []
        self.notes: List[str] = []
        self._heads: Optional[Dict[str, bytes]] = dict(heads) if heads is not None else None
        self._head_loader = head_loader
        # file indexes
        self._by_lrel: Dict[str, FileRec] = {}
        self._by_base: Dict[str, List[FileRec]] = {}
        self._by_ext: Dict[str, List[FileRec]] = {}
        self._by_magic: Dict[str, List[FileRec]] = {}
        self._sorted_lrel: List[str] = []
        self._dirs: Dict[str, int] = {}
        self._dir_by_base: Dict[str, List[str]] = {}
        self._index_files()
        # binary indexes
        self._sym_owner: Dict[str, str] = {}
        self._sym_sorted: List[str] = []
        self._cls_owner: Dict[str, str] = {}
        self._cls_sorted: List[str] = []
        self._dylibs: List[Tuple[str, str, str]] = []        # (lower, original, owner)
        self._sections: Dict[str, str] = {}
        self._blob = b""
        self._blob_starts: List[int] = []
        self._blob_owners: List[str] = []
        self._pending_strings: List[Tuple[str, List[bytes]]] = []
        for b in binaries:
            self.add_binary(b)
        self._finalised = False
        self.visibility: Dict[str, Any] = {}
        self.inv_header_clusters: Optional[List[Dict[str, Any]]] = None   # inventory.header_clusters when present

    # -- construction ------------------------------------------------------------------------------
    def _index_files(self) -> None:
        for f in self.files:
            lrel = f.lrel
            self._by_lrel.setdefault(lrel, f)
            base = lrel.rsplit("/", 1)[-1]
            self._by_base.setdefault(base, []).append(f)
            if f.ext:
                self._by_ext.setdefault(f.ext.lower(), []).append(f)
            self._by_magic.setdefault(f.magic, []).append(f)
            parts = lrel.split("/")
            for i in range(1, len(parts)):
                d = "/".join(parts[:i])
                if d not in self._dirs:
                    self._dirs[d] = 0
                    self._dir_by_base.setdefault(parts[i - 1], []).append(d)
                self._dirs[d] += 1
        self._sorted_lrel = sorted(self._by_lrel)

    def add_binary(self, rec: BinaryRec) -> None:
        self.binaries.append(rec)
        self._finalised = False
        for s in rec.symbols:
            self._sym_owner.setdefault(s, rec.rel)
        for c in rec.classes:
            self._cls_owner.setdefault(c, rec.rel)
        for d in rec.dylibs:
            self._dylibs.append((d.lower(), d, rec.rel))
        for sec in rec.sections:
            self._sections.setdefault(sec, rec.rel)
        if rec.strings:
            self._pending_strings.append((rec.rel, rec.strings))

    def _finalise(self) -> None:
        if self._finalised:
            return
        self._sym_sorted = sorted(self._sym_owner)
        self._cls_sorted = sorted(self._cls_owner)
        starts: List[int] = []
        owners: List[str] = []
        parts: List[bytes] = []
        pos = 0
        for owner, strings in self._pending_strings:
            starts.append(pos)
            owners.append(owner)
            chunk = b"\n".join(strings) + b"\n"
            parts.append(chunk)
            pos += len(chunk)
        self._blob = b"".join(parts)
        self._blob_starts = starts
        self._blob_owners = owners
        self._finalised = True

    # -- file queries --------------------------------------------------------------------------------
    def heads(self) -> Dict[str, bytes]:
        if self._heads is None:
            self._heads = self._head_loader() if self._head_loader else {}
        return self._heads

    def match_files(self, pp: ParsedPattern) -> List[FileRec]:
        if pp.kind == "magic":
            return list(self._by_magic.get(pp.value, ()))
        if pp.kind == "head":
            want = pp.value.encode("utf-8")
            by_path = {f.path: f for f in self.files}
            return [by_path[p] for p, h in self.heads().items() if h.startswith(want) and p in by_path]
        pat = pp.value
        anchored = "/" in pat
        pat = pat.lstrip("/")
        if not anchored:
            if not _has_wild(pat):
                return list(self._by_base.get(pat, ()))
            m = _EXT_ONLY_RE.match(pat)
            if m:
                return list(self._by_ext.get(m.group(1), ()))
            rx = glob_to_regex(pat)
            return [f for base, lst in self._by_base.items() if rx.match(base) for f in lst]
        if not _has_wild(pat):
            f = self._by_lrel.get(pat)
            return [f] if f else []
        rx = glob_to_regex(pat)
        prefix = _literal_prefix(pat)
        if prefix:
            lo = bisect.bisect_left(self._sorted_lrel, prefix)
            hi = bisect.bisect_left(self._sorted_lrel, prefix + "\U0010ffff")
            cands: Iterable[str] = self._sorted_lrel[lo:hi]
        else:
            cands = self._sorted_lrel
        return [self._by_lrel[p] for p in cands if rx.match(p)]

    def match_dirs(self, pp: ParsedPattern) -> List[str]:
        pat = pp.value.rstrip("/")
        anchored = "/" in pat
        pat = pat.lstrip("/")
        if not anchored:
            if not _has_wild(pat):
                return list(self._dir_by_base.get(pat, ()))
            rx = glob_to_regex(pat)
            return [d for base, lst in self._dir_by_base.items() if rx.match(base) for d in lst]
        if not _has_wild(pat):
            return [pat] if pat in self._dirs else []
        rx = glob_to_regex(pat)
        return [d for d in self._dirs if rx.match(d)]

    # -- binary queries -------------------------------------------------------------------------------
    def find_string(self, pp: ParsedPattern) -> Optional[Tuple[str, str]]:
        """First blob match as ``(binary rel, matched text)``."""
        self._finalise()
        if not self._blob:
            return None
        if pp.kind == "regex":
            m = pp.regex.search(self._blob) if pp.regex else None
            if not m:
                return None
            pos, text = m.start(), m.group(0)[:80]
        else:
            lit = pp.value.encode("utf-8")
            pos = self._blob.find(lit)
            if pos < 0:
                return None
            text = pp.value[:80]
        idx = max(0, bisect.bisect_right(self._blob_starts, pos) - 1)
        return self._blob_owners[idx], text.decode("utf-8", "replace") if isinstance(text, bytes) else text

    def find_symbol(self, pp: ParsedPattern) -> Optional[Tuple[str, str]]:
        self._finalise()
        v = pp.value
        if pp.kind == "exact":
            o = self._sym_owner.get(v)
            return (o, v) if o is not None else None
        if pp.kind == "prefix":
            i = bisect.bisect_left(self._sym_sorted, v)
            if i < len(self._sym_sorted) and self._sym_sorted[i].startswith(v):
                n = self._sym_sorted[i]
                return self._sym_owner[n], n
            return None
        if pp.kind == "contains":
            for n in self._sym_sorted:
                if v in n:
                    return self._sym_owner[n], n
            return None
        if pp.kind == "regex" and pp.regex is not None:
            rx = re.compile(pp.value)
            for n in self._sym_sorted:
                if rx.search(n):
                    return self._sym_owner[n], n
        return None

    def find_class(self, prefix: str) -> Optional[Tuple[str, str]]:
        self._finalise()
        i = bisect.bisect_left(self._cls_sorted, prefix)
        if i < len(self._cls_sorted) and self._cls_sorted[i].startswith(prefix):
            n = self._cls_sorted[i]
            return self._cls_owner[n], n
        return None

    def find_dylib(self, needle_lower: str) -> Optional[Tuple[str, str]]:
        for low, orig, owner in self._dylibs:
            if needle_lower in low:
                return owner, orig
        return None

    def find_section(self, name: str) -> Optional[str]:
        return self._sections.get(name)

    # -- summaries -------------------------------------------------------------------------------------
    @property
    def has_binary_data(self) -> bool:
        return bool(self.binaries)

    @property
    def strings_available(self) -> bool:
        self._finalise()
        return bool(self._blob)

    def count_magic(self, magic: str) -> int:
        return len(self._by_magic.get(magic, ()))

    def files_with_ext(self, ext: str) -> List[FileRec]:
        return list(self._by_ext.get(ext.lower(), ()))


# --- signal matching --------------------------------------------------------------------------------------
_PARSE_CACHE: Dict[Tuple[str, str], ParsedPattern] = {}


def _parsed(spec: SignalSpec) -> ParsedPattern:
    key = (spec.type, spec.pattern)
    pp = _PARSE_CACHE.get(key)
    if pp is None:
        pp = parse_pattern(spec.type, spec.pattern)
        _PARSE_CACHE[key] = pp
    return pp


def match_signal(bundle: EvidenceBundle, spec: SignalSpec) -> Optional[SignalMatch]:
    """Evaluate one signal against ``bundle``; ``None`` when it does not match."""
    try:
        pp = _parsed(spec)
    except ValueError:
        return None
    t = spec.type
    if t == "file":
        files = bundle.match_files(pp)
        if len(files) < pp.min_count:
            return None
        return SignalMatch(spec, [f.path for f in files[:_EVIDENCE_REFS]], len(files),
                           "%d matching file(s)" % len(files))
    if t == "dir":
        dirs = bundle.match_dirs(pp)
        if len(dirs) < pp.min_count:
            return None
        return SignalMatch(spec, dirs[:_EVIDENCE_REFS], len(dirs), "%d matching director(ies)" % len(dirs))
    if t == "string":
        r = bundle.find_string(pp)
        return SignalMatch(spec, [r[0]], 1, "string %r" % r[1]) if r else None
    if t == "symbol":
        r = bundle.find_symbol(pp)
        return SignalMatch(spec, [r[0]], 1, "symbol %s" % r[1]) if r else None
    if t == "objc_prefix":
        r = bundle.find_class(pp.value)
        return SignalMatch(spec, [r[0]], 1, "ObjC class %s" % r[1]) if r else None
    if t == "dylib":
        r = bundle.find_dylib(pp.value)
        return SignalMatch(spec, [r[0]], 1, "links %s" % r[1]) if r else None
    if t == "plist_key":
        if pp.kind == "keyvalue":
            k, v = pp.value.split("=", 1)
            return SignalMatch(spec, ["Info.plist"], 1, "%s=%s" % (k, v)) if bundle.plist.get(k) == v else None
        return SignalMatch(spec, ["Info.plist"], 1, "key %s" % pp.value) if pp.value in bundle.plist else None
    if t == "binary_section":
        owner = bundle.find_section(pp.value)
        return SignalMatch(spec, [owner], 1, "section %s" % pp.value) if owner else None
    return None


_CODE_TYPES = ("string", "symbol", "objc_prefix", "dylib", "binary_section")


def score_signature(bundle: EvidenceBundle, sig: EngineSignature) -> EngineScore:
    matches: List[SignalMatch] = []
    score = code = layout = 0.0
    strong = False
    for spec in sig.signals:
        m = match_signal(bundle, spec)
        if m is None:
            continue
        matches.append(m)
        score += spec.weight
        if spec.type in _CODE_TYPES:
            code += spec.weight
        else:
            layout += spec.weight
        strong = strong or spec.strong
    confirmed = bool(matches) and (strong or score >= sig.confirm_threshold - 1e-9)
    return EngineScore(sig, matches, score, strong, confirmed, code, layout)


def to_evidence(matches: Sequence[SignalMatch]) -> List[Evidence]:
    out: List[Evidence] = []
    for m in matches:
        kind = _EVIDENCE_KIND.get(m.spec.type, "heuristic")
        ref = m.refs[0] if m.refs else m.spec.pattern
        detail = "%s %s (weight %.2f%s)" % (m.spec.type, m.detail, m.spec.weight,
                                              ", unverified signal" if m.spec.unverified else "")
        out.append(Evidence(kind, ref, detail))
    return out


def signals_matched(matches: Sequence[SignalMatch]) -> List[Dict[str, Any]]:
    return [{"type": m.spec.type, "pattern": m.spec.pattern, "weight": round(m.spec.weight, 3),
             "ref": m.refs[0] if m.refs else "", "strong": m.spec.strong} for m in matches]


# --- detection --------------------------------------------------------------------------------------------
def _version_hint(bundle: EvidenceBundle, rx_src: Optional[str]) -> Optional[str]:
    if not rx_src:
        return None
    try:
        rx = re.compile(rx_src.encode("utf-8"))
    except re.error:
        return None
    bundle._finalise()
    m = rx.search(bundle._blob) if bundle._blob else None
    if not m:
        return None
    return (m.group(1) if m.groups() else m.group(0)).decode("utf-8", "replace")[:40]


def detect_engines(bundle: EvidenceBundle, sigset: SignatureSet) -> DetectResult:
    """Score every signature and assemble ``primary`` / ``candidates`` / ``wrapper``."""
    scores = {sid: score_signature(bundle, sig) for sid, sig in sigset.signatures.items()}
    matched = {sid: s for sid, s in scores.items() if s.matches}

    def order(sid: str) -> Tuple[float, int, str]:
        s = matched[sid]
        return (-s.confidence, -len(s.matches), sid)

    suppressed: Dict[str, str] = {}
    confirmed_ids = sorted((sid for sid, s in matched.items() if s.confirmed), key=order)
    families = [sid for sid in confirmed_ids if sigset.extras.get(sid, {}).get("role") == "family"]
    for fam in families:                           # a family-level entry yields to any confirmed variant
        fam_name = sigset.signatures[fam].family
        for other in confirmed_ids:
            if other != fam and sigset.signatures[other].family == fam_name \
                    and sigset.extras.get(other, {}).get("role") != "family":
                suppressed[fam] = other
                break
    for sid in confirmed_ids:                      # best first
        if sid in suppressed or sigset.extras.get(sid, {}).get("role") == "family":
            continue
        for other in sigset.signatures[sid].exclusive_with:
            if other in matched and matched[other].confirmed and other not in suppressed and other != sid:
                suppressed[other] = sid
    for sid, s in list(matched.items()):           # reverse declarations (A excludes B, only A lists it)
        if not s.confirmed:
            continue
        for other in confirmed_ids:
            if other != sid and sid in sigset.signatures[other].exclusive_with and sid not in suppressed \
                    and other not in suppressed and order(other) < order(sid):
                suppressed[sid] = other

    real = [sid for sid in confirmed_ids if sid not in suppressed and sigset.extras.get(sid, {}).get("role") != "fallback"]
    if real:                                       # fallback classifications (native UI) yield to any real engine
        for sid in confirmed_ids:
            if sigset.extras.get(sid, {}).get("role") == "fallback" and sid not in suppressed:
                suppressed[sid] = real[0]

    candidates: List[EngineMatch] = []
    for sid in sorted(matched, key=order):
        s = matched[sid]
        sig = sigset.signatures[sid]
        extra: Dict[str, Any] = {"score": round(s.score, 3), "threshold": sig.confirm_threshold,
                                 "strong": s.strong, "code_score": round(s.code_score, 3),
                                 "layout_score": round(s.layout_score, 3)}
        if sid in suppressed:
            extra["suppressed_by"] = suppressed[sid]
        vh = _version_hint(bundle, sigset.extras.get(sid, {}).get("version_regex")) if s.confirmed else None
        if vh:
            extra["version_hint"] = vh
        candidates.append(EngineMatch(
            id=sid, name=sig.name, confidence=s.confidence, family=sig.family, kind=sig.kind,
            confirmed=s.confirmed and sid not in suppressed, signals_matched=signals_matched(s.matches),
            evidence=to_evidence(s.matches), extra=extra))

    live = [c for c in candidates if c.confirmed]
    primary: Optional[EngineMatch] = None
    if live:
        primary = min(live, key=lambda c: (KIND_RANK.get(c.kind, 1), -c.confidence, -len(c.signals_matched), c.id))
    res = DetectResult(primary=primary, candidates=candidates,
                       is_game_engine=bool(primary and primary.kind == "game_engine"))
    res.wrapper = _wrapper(live, primary, sigset)
    return res


def _wrapper(live: Sequence[EngineMatch], primary: Optional[EngineMatch], sigset: SignatureSet) -> Optional[Dict[str, Any]]:
    """Host + embedded engines (e.g. Cordova shell with a game engine, SwiftUI shell with Unity)."""
    if primary is None or len(live) < 2:
        return None
    hosts = [c for c in live if sigset.extras.get(c.id, {}).get("wrapper_host")]
    if not hosts:
        return None
    host = max(hosts, key=lambda c: (c.confidence, c.id))
    embedded = [c for c in live if c.id != host.id and c.kind != "native"
                and (host.kind == "web_hybrid" or sigset.extras.get(c.id, {}).get("embeddable"))]
    if not embedded:
        return None

    def brief(c: EngineMatch) -> Dict[str, Any]:
        return {"id": c.id, "name": c.name, "confidence": round(c.confidence, 4)}

    return {"host": brief(host), "embedded": [brief(c) for c in embedded]}


# --- cache shared by the two stages ---------------------------------------------------------------------
_BUNDLE_CACHE: "weakref.WeakKeyDictionary[Any, EvidenceBundle]" = weakref.WeakKeyDictionary()


def cached_bundle(ctx: Any) -> Optional[EvidenceBundle]:
    try:
        return _BUNDLE_CACHE.get(ctx)
    except TypeError:
        return None


def remember_bundle(ctx: Any, bundle: EvidenceBundle) -> None:
    try:
        _BUNDLE_CACHE[ctx] = bundle
    except TypeError:
        pass


# --- evidence collection from an AnalysisContext ----------------------------------------------------------
def _plist_values(source: Any, name: str) -> Dict[str, str]:
    from ..util.plist_utils import load_plist
    try:
        with source.open(name) as fh:
            data = fh.read(8 * 1024 * 1024)
    except (KeyError, OSError):
        return {}
    plist = load_plist(data)
    out: Dict[str, str] = {}
    if isinstance(plist, dict):
        for k, v in plist.items():
            if isinstance(k, str):
                out[k] = v if isinstance(v, str) else ("" if isinstance(v, (dict, list, bytes)) else str(v))
    return out


def _load_heads(ctx: Any, files: Sequence[FileRec]) -> Dict[str, bytes]:
    """First ``HEAD_BYTES`` of every file whose magic is unknown (cheap: one small read each)."""
    out: Dict[str, bytes] = {}
    src = ctx.source
    if src is None:
        return out
    deadline = time.monotonic() + HEAD_TIME_BUDGET_S
    for f in files:
        if f.magic != "unknown" or f.size < 4:
            continue
        if len(out) >= MAX_HEAD_FILES or time.monotonic() > deadline:
            ctx.add_warning("engine evidence: header sampling stopped early (budget reached)")
            break
        try:
            out[f.path] = src.read_head(f.path, HEAD_BYTES)
        except (KeyError, OSError, ValueError):
            continue
        except Exception as exc:  # noqa: BLE001 - malformed archive entry
            log.debug("read_head failed for %s: %s", f.path, exc)
    return out


def _strip_underscore(name: str) -> str:
    return name[1:] if name.startswith("_") else name


def _read_binary(local: Any, rel: str, path: str, role: str, size: int, budget: List[int]) -> BinaryRec:
    """Parse one Mach-O file into a ``BinaryRec`` (never raises for malformed input)."""
    from ..macho import MachOError, parse
    rec = BinaryRec(rel=rel, path=path, role=role, size=size)
    try:
        with parse(local) as mf:
            sl = mf.select_slice() or (mf.slices[0] if mf.slices else None)
            if sl is None:
                rec.error = "no slices"
                return rec
            rec.encrypted = bool(sl.is_encrypted)
            rec.dylibs = [d.path for d in sl.dylibs]
            rec.has_swift, rec.has_objc, rec.has_cpp = bool(sl.has_swift), bool(sl.has_objc), bool(sl.has_cpp)
            secs = sl.sections
            rec.sections = sorted({"%s,%s" % (s.segname, s.sectname) for s in secs})
            symbols: List[str] = []
            classes: List[str] = []
            own: Set[str] = set()
            for n, sym in enumerate(sl.iter_symbols()):
                if n >= MAX_SYMBOLS_PER_BINARY:
                    break
                if sym.is_stab or not sym.name:
                    continue
                name = _strip_underscore(sym.name)
                symbols.append(name)
                if name.startswith("OBJC_CLASS_$_"):
                    cls = name[len("OBJC_CLASS_$_"):]
                    classes.append(cls)
                    if sym.is_defined:
                        own.add(cls)
                if sym.is_defined:
                    rec.defined_symbols += 1
                    if name.startswith("_Z"):
                        rec.defined_cpp += 1
                    elif name.startswith(("OBJC_", "$s", "$S")):
                        rec.defined_objc_swift += 1
            rec.symbols = symbols
            for name in sl.objc_class_names(skip_encrypted=True):
                classes.append(name)
                own.add(name)
            rec.classes = classes
            rec.own_classes = len(own)
            blob_bytes = 0
            strings: List[bytes] = []
            for sec in secs:
                if not sec.is_cstring or sec.sectname in _SKIP_CSTRING_SECTIONS:
                    continue
                if sl.range_encrypted(sec.offset, sec.size):
                    rec.strings_skipped_encrypted += 1
                    continue
                if budget[0] <= 0 or blob_bytes >= MAX_BLOB_PER_BINARY:
                    break
                for text in sl.iter_section_strings([sec], 4, skip_encrypted=True):
                    if len(text) > MAX_STRING_LEN:
                        continue
                    raw = text.encode("utf-8", "replace")
                    strings.append(raw)
                    blob_bytes += len(raw) + 1
                    if blob_bytes >= MAX_BLOB_PER_BINARY:
                        break
                budget[0] -= sec.size
            rec.strings = strings
    except (MachOError, OSError, ValueError, MemoryError) as exc:
        rec.error = "%s: %s" % (type(exc).__name__, exc)
    return rec


def _binary_candidates(ctx: Any, recs: Sequence[FileRec]) -> List[Tuple[str, str, str, int]]:
    """``[(archive name, rel, role, size)]`` main binary first, then by size (largest first)."""
    macho = ctx.results.get("macho") or {}
    out: List[Tuple[str, str, str, int]] = []
    if macho.get("binaries"):
        for b in macho["binaries"]:
            out.append((b["path"], b.get("rel") or ctx.rel(b["path"]) or b["path"], b.get("role", "other"),
                        int(b.get("size") or 0)))
    else:
        for f in recs:
            if f.magic.startswith("macho"):
                out.append((f.path, f.rel, "other", f.size))
    out.sort(key=lambda x: (x[2] != "main", -x[3], x[0]))
    return out[:MAX_BINARIES]


def collect_evidence(ctx: Any, *, use_cache: bool = True) -> EvidenceBundle:
    """Build (or fetch the cached) ``EvidenceBundle`` for ``ctx``; needs ``ctx.results['inventory']``."""
    if use_cache:
        cached = cached_bundle(ctx)
        if cached is not None:
            return cached
    from ..util.filetypes import load_inventory_files
    inv = ctx.results.get("inventory") or {}
    rows = load_inventory_files(inv, ctx.out_dir if ctx.is_bound else None)
    recs: List[FileRec] = []
    for r in rows:
        path = r.get("path")
        if not isinstance(path, str):
            continue
        rel = ctx.rel(path)
        if rel is None:
            continue
        recs.append(FileRec(path=path, rel=rel, size=int(r.get("size") or 0), magic=str(r.get("magic") or "unknown"),
                            ext=str(r.get("ext") or ""), category=str(r.get("category") or "other"),
                            entropy=r.get("entropy")))
    plist = _plist_values(ctx.source, ctx.app_path("Info.plist")) if ctx.source is not None else {}
    bundle = EvidenceBundle(recs, plist=plist, head_loader=lambda: _load_heads(ctx, recs))
    hc = inv.get("header_clusters")
    bundle.inv_header_clusters = [c for c in hc if isinstance(c, dict)] if isinstance(hc, list) else None

    cands = _binary_candidates(ctx, recs)
    budget = [MAX_SECTION_BYTES_TOTAL]
    deadline = time.monotonic() + BINARY_TIME_BUDGET_S
    scanned = 0
    for name, rel, role, size in cands:
        if time.monotonic() > deadline or budget[0] <= 0:
            bundle.notes.append("binary scan stopped early (time/size budget)")
            break
        local = ctx.extract([name]).get(name)
        if local is None:
            bundle.notes.append("cannot extract %s" % name)
            continue
        rec = _read_binary(local, rel, name, role, size, budget)
        if rec.error:
            bundle.notes.append("%s: %s" % (rel, rec.error))
        bundle.add_binary(rec)
        scanned += 1
    enc = [b for b in bundle.binaries if b.encrypted]
    main = next((b for b in bundle.binaries if b.role == "main"), None)
    bundle.visibility = {
        "binaries_total": len(cands), "binaries_scanned": scanned, "encrypted_binaries": len(enc),
        "main_encrypted": bool(main.encrypted) if main else None,
        "strings_available": bundle.strings_available,
        "classes_available": bool(bundle._cls_owner),
        "symbols_available": bool(bundle._sym_owner),
        "sections_skipped_encrypted": sum(b.strings_skipped_encrypted for b in bundle.binaries),
        "macho_stage": ctx.stage_status("macho").value if ctx.stage_status("macho") else None,
    }
    # "limited" = encrypted code could hide the engine's strings / symbols
    bundle.visibility["limited"] = bool(enc) and (
        not bundle.visibility["strings_available"] or bundle.visibility["sections_skipped_encrypted"] > 0)
    if use_cache:
        remember_bundle(ctx, bundle)
    return bundle


# --- languages ------------------------------------------------------------------------------------------------
_LANG_FILE_EXTS = {
    "lua": (".lua", ".luac"), "javascript": (".js", ".jsc", ".jsbundle"), "python": (".py", ".pyc", ".pyo"),
    "typescript": (".ts",), "csharp": (".cs",),
}


def infer_languages(bundle: EvidenceBundle, detect: DetectResult, sigset: Optional[SignatureSet] = None,
                    script_vm_ids: Sequence[str] = ()) -> List[Dict[str, Any]]:
    """Programming languages with evidence: Mach-O flags, script / assembly files, engine hints."""
    acc: Dict[str, Tuple[float, List[Evidence]]] = {}

    def add(lang: str, conf: float, ev: Evidence) -> None:
        cur = acc.get(lang)
        if cur is None:
            acc[lang] = (conf, [ev])
        else:
            acc[lang] = (min(0.99, max(cur[0], conf) + 0.05), cur[1] + [ev])

    main = next((b for b in bundle.binaries if b.role == "main"), None)
    for rec in ([main] if main else []) + [b for b in bundle.binaries if b is not main][:6]:
        w = 0.8 if rec is main else 0.6
        if rec.has_objc:
            add("objc", w, Evidence("macho", rec.rel, "Objective-C runtime sections / classes"))
        if rec.has_swift:
            add("swift", w, Evidence("macho", rec.rel, "Swift sections or libswift* dependency"))
        if rec.has_cpp:
            add("cpp", w - 0.1, Evidence("macho", rec.rel, "links libc++ / libstdc++"))
    for lang, exts in _LANG_FILE_EXTS.items():
        files = [f for e in exts for f in bundle.files_with_ext(e)]
        if lang == "javascript":
            files = [f for f in files if "node_modules" not in f.lrel]
        if len(files) >= (3 if lang in ("javascript", "typescript", "csharp") else 1):
            add(lang, 0.6 if lang != "lua" else 0.7, Evidence("file", files[0].path, "%d %s file(s)" % (len(files), "/".join(exts))))
    if bundle.count_magic("lua_bytecode"):
        add("lua", 0.75, Evidence("file", bundle._by_magic["lua_bytecode"][0].path, "Lua bytecode files"))
    if "lua" in script_vm_ids or "luajit" in script_vm_ids:
        add("lua", 0.75, Evidence("heuristic", "engine.fingerprint", "Lua VM detected in the capability profile"))
    if bundle.count_magic("il2cpp_metadata") or [f for f in bundle.files if f.lrel.startswith("data/managed/") and f.ext == ".dll"]:
        add("csharp", 0.85, Evidence("file", "Data/Managed", "IL2CPP metadata or Mono assemblies (C# game code)"))
    if bundle.count_magic("hermes_bytecode"):
        add("javascript", 0.8, Evidence("file", bundle._by_magic["hermes_bytecode"][0].path, "Hermes bytecode"))
    for c in detect.candidates:
        if not c.confirmed or sigset is None:
            continue
        for lang in sigset.signatures[c.id].language_hints:
            add(lang, min(0.9, c.confidence * 0.8), Evidence("heuristic", c.id, "language hint of engine %s" % c.name))
    # UNVERIFIED (memory): Rust panic strings / Go build info section
    r = bundle.find_string(parse_pattern("string", "RUST_BACKTRACE"))
    if r:
        add("rust", 0.45, Evidence("string", r[0], "RUST_BACKTRACE string"))
    if bundle.find_section("__DATA,__go_buildinfo") or bundle.find_section("__TEXT,__go_buildinfo"):
        add("go", 0.5, Evidence("macho", "binary", "go_buildinfo section"))
    out = [{"lang": k, "confidence": round(v[0], 3), "evidence": [e.to_dict() for e in v[1][:4]]}
           for k, v in acc.items()]
    out.sort(key=lambda d: (-d["confidence"], d["lang"]))
    return out
