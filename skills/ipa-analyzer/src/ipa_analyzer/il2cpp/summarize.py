"""Streaming summary of an IL2CPP dump: counts, namespaces, known frameworks and identifier obfuscation.

``dump.cs`` (Il2CppDumper) can reach several hundred MB, so it is read line by line and only counters,
a namespace dictionary and a few examples are kept. The line format is taken from Il2CppDumper's
``Il2CppDecompiler.cs`` (v6.7.46): ``// Image N: <name> - <typeStart>`` header lines, then per type
``// Namespace: <ns>`` and ``<modifiers> class|struct|enum|interface <Name>[ : bases] // TypeDefIndex: N``
followed by ``\\t// Fields`` / ``\\t// Properties`` / ``\\t// Methods`` sections with one member per line.
For backends that emit a C# file tree instead (Cpp2IL ``DiffableCs``, Il2CppInspectorRedux ``cs``) a
coarser fallback scanner is used (no member counts).
"""
from __future__ import annotations

import json
import logging
import os
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ..util import paths as _paths

log = logging.getLogger(__name__)

NAMESPACES_FILE = "namespaces.txt"
GLOBAL_NAMESPACE = "(global)"

# --- built-in framework namespaces (used when data/libs.json is missing or has no namespace rules) ---------
# Namespace names VERIFIED against upstream sources on 2026-10-03: HybridCLR, XLua, ILRuntime, YooAsset,
# Cysharp.Threading.Tasks, Spine, AppsFlyerSDK, GoogleMobileAds, Facebook.Unity, Newtonsoft.Json.
# UNVERIFIED (recalled from memory, not checked against sources): Puerts, LuaInterface, Photon.*, Mirror,
# DG.Tweening, Firebase, AppLovin*, UnityEngine.AddressableAssets, UnityEngine.Advertisements, com.adjust.sdk.
BUILTIN_FRAMEWORKS: Tuple[Dict[str, Any], ...] = (
    {"id": "hybridclr", "name": "HybridCLR", "namespaces": ["HybridCLR"]},
    {"id": "xlua", "name": "xLua", "namespaces": ["XLua"]},
    {"id": "tolua", "name": "ToLua", "namespaces": ["LuaInterface"]},          # UNVERIFIED
    {"id": "ilruntime", "name": "ILRuntime", "namespaces": ["ILRuntime"]},
    {"id": "puerts", "name": "puerts", "namespaces": ["Puerts"]},               # UNVERIFIED
    {"id": "addressables", "name": "Unity Addressables", "namespaces": ["UnityEngine.AddressableAssets",
                                                                      "UnityEngine.ResourceManagement"]},  # UNVERIFIED
    {"id": "yooasset", "name": "YooAsset", "namespaces": ["YooAsset"]},
    {"id": "photon", "name": "Photon", "namespaces": ["Photon.Pun", "Photon.Realtime", "ExitGames.Client.Photon"]},  # UNVERIFIED
    {"id": "mirror", "name": "Mirror", "namespaces": ["Mirror"]},               # UNVERIFIED
    {"id": "dotween", "name": "DOTween", "namespaces": ["DG.Tweening"]},        # UNVERIFIED
    {"id": "spine", "name": "Spine", "namespaces": ["Spine"]},
    {"id": "unitask", "name": "UniTask", "namespaces": ["Cysharp.Threading.Tasks"]},
    {"id": "firebase", "name": "Firebase", "namespaces": ["Firebase"]},         # UNVERIFIED
    {"id": "applovin", "name": "AppLovin MAX", "namespaces": ["AppLovinMax"]},  # UNVERIFIED
    {"id": "appsflyer", "name": "AppsFlyer", "namespaces": ["AppsFlyerSDK"]},
    {"id": "admob", "name": "Google Mobile Ads", "namespaces": ["GoogleMobileAds"]},
    {"id": "facebook", "name": "Facebook SDK", "namespaces": ["Facebook.Unity"]},
    {"id": "unityads", "name": "Unity Ads", "namespaces": ["UnityEngine.Advertisements"]},  # UNVERIFIED
    {"id": "newtonsoft", "name": "Newtonsoft.Json", "namespaces": ["Newtonsoft.Json"]},
)

# --- obfuscation heuristics ------------------------------------------------------------------------------------
# Weights and level thresholds are HEURISTICS calibrated only on synthetic fixtures (readable names vs.
# single-letter / control-character / random names); they have not been validated on real obfuscated games.
W_SHORT, W_GARBLED, W_ASCII_NONSTD, W_NON_ASCII, W_RANDOM = 2.0, 3.0, 3.0, 0.25, 1.5
LEVELS = ((0.15, "none"), (0.35, "low"), (0.60, "medium"), (1.01, "high"))

_ASCII_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_GENERIC = re.compile(r"<[^<>]*>")
_CONSONANT_RUN = re.compile(r"[^aeiouyAEIOUY0-9_]{6,}")
_LETTER_DIGIT_EDGE = re.compile(r"(?<=[A-Za-z])\d|(?<=\d)[A-Za-z]")
_TYPE_RE = re.compile(r"^(?:(?:public|internal|private|protected|static|abstract|sealed)\s+)*"
                      r"(class|struct|enum|interface)\s+(.+)$")
_BAD_CATEGORIES = frozenset(("Cc", "Cf", "Co", "Cs", "Cn", "So", "Sm", "Sk", "Zl", "Zp"))


@dataclass
class ObfuscationStats:
    score: float = 0.0
    level: str = "none"
    non_standard_ratio: float = 0.0     # names not matching [A-Za-z_][A-Za-z0-9_]*
    short_ratio: float = 0.0            # length <= 2
    non_ascii_ratio: float = 0.0
    garbled_ratio: float = 0.0          # control / private-use / symbol / unassigned characters, U+FFFD
    random_like_ratio: float = 0.0      # long consonant runs or many letter/digit alternations
    names_considered: int = 0
    examples: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"score": round(self.score, 4), "level": self.level,
                "non_standard_ratio": round(self.non_standard_ratio, 4), "short_ratio": round(self.short_ratio, 4),
                "non_ascii_ratio": round(self.non_ascii_ratio, 4), "garbled_ratio": round(self.garbled_ratio, 4),
                "random_like_ratio": round(self.random_like_ratio, 4), "names_considered": self.names_considered,
                "examples": list(self.examples)}


class _NameStats:
    __slots__ = ("n", "short", "non_ascii", "non_std", "ascii_nonstd", "garbled", "random", "examples")

    def __init__(self) -> None:
        self.n = self.short = self.non_ascii = self.non_std = self.ascii_nonstd = self.garbled = self.random = 0
        self.examples: List[str] = []

    def add(self, name: str) -> None:
        """Account one identifier (compiler-generated names are ignored)."""
        if not name or name[0] in "<.$" or "<>" in name or name == "value__":
            return
        if "<" in name:
            prev = None
            while prev != name and "<" in name:
                prev, name = name, _GENERIC.sub("", name)
            if not name:
                return
        if "." in name:
            name = name.rsplit(".", 1)[-1]
            if not name:
                return
        self.n += 1
        if len(name) <= 2:
            self.short += 1
        ascii_name = name.isascii()
        flagged = False
        if _ASCII_IDENT.match(name):
            if len(name) >= 6 and (_CONSONANT_RUN.search(name) or len(_LETTER_DIGIT_EDGE.findall(name)) >= 6):
                self.random += 1
                flagged = True
        else:
            self.non_std += 1
            if ascii_name:
                self.ascii_nonstd += 1
                flagged = True
            if not ascii_name:
                self.non_ascii += 1
            if any(ord(ch) < 32 or ord(ch) == 127 or ch == "�" or unicodedata.category(ch) in _BAD_CATEGORIES
                   for ch in name):
                self.garbled += 1
                flagged = True
        if flagged and len(self.examples) < 10:
            self.examples.append(name[:40])

    def result(self) -> ObfuscationStats:
        n = self.n
        if n == 0:
            return ObfuscationStats()
        r = lambda x: x / n  # noqa: E731
        score = min(1.0, W_SHORT * r(self.short) + W_GARBLED * r(self.garbled) + W_ASCII_NONSTD * r(self.ascii_nonstd)
                    + W_NON_ASCII * r(self.non_ascii) + W_RANDOM * r(self.random))
        level = next(lbl for limit, lbl in LEVELS if score < limit)
        return ObfuscationStats(score=score, level=level, non_standard_ratio=r(self.non_std), short_ratio=r(self.short),
                                non_ascii_ratio=r(self.non_ascii), garbled_ratio=r(self.garbled),
                                random_like_ratio=r(self.random), names_considered=n, examples=list(self.examples))


# --- result ------------------------------------------------------------------------------------------------------
@dataclass
class DumpSummary:
    source: str = "none"                      # dump.cs | cs_tree | none
    assemblies: int = 0
    assembly_names: List[str] = field(default_factory=list)
    classes: int = 0
    structs: int = 0
    interfaces: int = 0
    enums: int = 0
    methods: int = 0
    fields: int = 0
    properties: int = 0
    string_literals: int = 0
    namespaces_total: int = 0
    namespaces: List[str] = field(default_factory=list)          # top-N by type count
    namespaces_file: Optional[str] = None                        # relative to out_dir
    framework_namespaces: List[str] = field(default_factory=list)
    framework_hits: List[Dict[str, Any]] = field(default_factory=list)
    obfuscation: ObfuscationStats = field(default_factory=ObfuscationStats)
    lines: int = 0
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """JSON-able dict; the keys required by the engine.unity ``dump.summary`` contract come first."""
        return {
            "assemblies": self.assemblies, "classes": self.classes, "interfaces": self.interfaces,
            "enums": self.enums, "methods": self.methods, "fields": self.fields,
            "string_literals": self.string_literals, "framework_namespaces": list(self.framework_namespaces),
            "obfuscation": self.obfuscation.to_dict(),
            "structs": self.structs, "properties": self.properties, "namespaces_total": self.namespaces_total,
            "namespaces_file": self.namespaces_file, "framework_hits": list(self.framework_hits),
            "assembly_names": list(self.assembly_names), "source": self.source, "lines": self.lines,
            "warnings": list(self.warnings),
        }


# --- known frameworks ----------------------------------------------------------------------------------------------
def _as_list(v: Any) -> List[str]:
    if isinstance(v, str):
        return [v]
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v if isinstance(x, str)]
    return []


def load_framework_rules(libs_paths: Optional[Sequence[Path]] = None) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Built-in table merged with ``match.namespace`` rules from ``data/libs.json`` (+ optional extra files).

    ``libs.json`` is produced by another work package; any structural surprise degrades silently to the
    built-in table (a warning string is returned for diagnostics).
    """
    rules: List[Dict[str, Any]] = [dict(r) for r in BUILTIN_FRAMEWORKS]
    warnings: List[str] = []
    paths = list(libs_paths) if libs_paths else [_paths.resource_dir("data") / "libs.json"]
    for p in paths:
        try:
            if not Path(p).is_file():
                continue
            data = json.loads(Path(p).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            warnings.append("libs knowledge base unreadable (%s): %s" % (p, exc))
            continue
        entries: Iterable[Any]
        if isinstance(data, list):
            entries = data
        elif isinstance(data, dict):
            entries = next((data[k] for k in ("libs", "items", "entries") if isinstance(data.get(k), list)), [])
        else:
            entries = []
        for e in entries:
            if not isinstance(e, dict):
                continue
            match = e.get("match")
            ns = _as_list(match.get("namespace")) if isinstance(match, dict) else []
            if ns:
                rules.append({"id": str(e.get("id", "")), "name": str(e.get("name", e.get("id", ""))), "namespaces": ns})
    return rules, warnings


def match_frameworks(namespaces: Iterable[str], assemblies: Iterable[str], rules: Sequence[Dict[str, Any]]
                     ) -> List[Dict[str, Any]]:
    """Rules whose namespace (segment-wise prefix) or assembly name is present. Result sorted by id/namespace."""
    prefixes: Set[str] = set()
    for ns in namespaces:
        parts = ns.split(".")
        for i in range(1, len(parts) + 1):
            prefixes.add(".".join(parts[:i]))
    for asm in assemblies:
        prefixes.add(asm[:-4] if asm.lower().endswith(".dll") else asm)
    hits: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str]] = set()
    for rule in rules:
        for pat in rule.get("namespaces", []):
            clean = pat[:-2] if pat.endswith(".*") else pat.rstrip("*").rstrip(".")
            if clean and clean in prefixes and (rule["id"], clean) not in seen:
                seen.add((rule["id"], clean))
                hits.append({"id": rule["id"], "name": rule["name"], "namespace": clean})
    hits.sort(key=lambda h: (h["id"], h["namespace"]))
    return hits


# --- scanners ---------------------------------------------------------------------------------------------------------
def _scan_dump_cs(path: Path, summary: DumpSummary, stats: _NameStats, ns_counts: Dict[str, int]) -> None:
    section = ""
    ns = GLOBAL_NAMESPACE
    in_type = False
    type_counters = {"class": "classes", "struct": "structs", "interface": "interfaces", "enum": "enums"}
    asm_names: List[str] = []
    with open(path, "r", encoding="utf-8", errors="replace", newline=None) as fh:
        for raw in fh:
            summary.lines += 1
            if not raw or raw == "\n":
                continue
            c = raw[0]
            if c == "\t":
                if not in_type:
                    continue
                s = raw[1:].rstrip("\n")
                if not s or s[0] == "[":
                    continue
                if s.startswith("//"):
                    t = s[2:].strip()
                    if t in ("Fields", "Properties", "Methods", "Events"):
                        section = t
                    continue
                if section == "Fields":
                    body = s.split(" = ", 1)[0] if " = " in s else s.split(";", 1)[0]
                    tok = body.rstrip("; ").rsplit(None, 1)
                    if tok:
                        summary.fields += 1
                        stats.add(tok[-1])
                elif section == "Methods":
                    head = s.split("(", 1)[0]
                    if "(" in s and head:
                        tok = head.rsplit(None, 1)
                        summary.methods += 1
                        stats.add(tok[-1])
                elif section == "Properties":
                    head = s.split(" {", 1)[0]
                    tok = head.rsplit(None, 1)
                    if tok:
                        summary.properties += 1
                        stats.add(tok[-1])
                continue
            if c == "/":
                if raw.startswith("// Namespace: "):
                    ns = raw[14:].rstrip("\n").strip() or GLOBAL_NAMESPACE
                elif raw.startswith("// Image "):
                    summary.assemblies += 1
                    rest = raw[9:].rstrip("\n")
                    name = rest.split(": ", 1)[-1].rsplit(" - ", 1)[0]
                    if len(asm_names) < 500:
                        asm_names.append(name)
                continue
            if c in "{}[":
                continue
            m = _TYPE_RE.match(raw.rstrip("\n"))
            if not m:
                continue
            kind, rest = m.group(1), m.group(2)
            name = rest.split(" // ", 1)[0].split(" : ", 1)[0].strip()
            setattr(summary, type_counters[kind], getattr(summary, type_counters[kind]) + 1)
            ns_counts[ns] = ns_counts.get(ns, 0) + 1
            stats.add(name)
            section = ""
            in_type = True
    summary.assembly_names = asm_names


_NS_DECL = re.compile(r"^\s*namespace\s+([A-Za-z0-9_.]+)")
_CS_TYPE = re.compile(r"^\s*(?:\[[^\]]*\]\s*)*(?:(?:public|internal|private|protected|static|abstract|sealed|partial|unsafe|readonly)\s+)*"
                      r"(class|struct|enum|interface)\s+([^\s:{<(]+)")


def _scan_cs_tree(root: Path, summary: DumpSummary, stats: _NameStats, ns_counts: Dict[str, int]) -> None:
    asm_dirs: Set[str] = set()
    type_counters = {"class": "classes", "struct": "structs", "interface": "interfaces", "enum": "enums"}
    for dirpath, _dirs, files in os.walk(str(root)):
        rel = Path(dirpath).relative_to(root).parts
        if rel and len(asm_dirs) < 500:
            asm_dirs.add(rel[0])
        for fn in files:
            if not fn.endswith(".cs"):
                continue
            ns = GLOBAL_NAMESPACE
            try:
                with open(os.path.join(dirpath, fn), "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        summary.lines += 1
                        m = _NS_DECL.match(line)
                        if m:
                            ns = m.group(1)
                            continue
                        t = _CS_TYPE.match(line)
                        if t:
                            setattr(summary, type_counters[t.group(1)], getattr(summary, type_counters[t.group(1)]) + 1)
                            ns_counts[ns] = ns_counts.get(ns, 0) + 1
                            stats.add(t.group(2))
            except OSError as exc:
                summary.warnings.append("unreadable %s: %s" % (fn, exc))
    summary.assemblies = len(asm_dirs)
    summary.assembly_names = sorted(asm_dirs)


def count_string_literals(path: Path) -> int:
    """Count entries of ``stringliteral.json`` without loading it (Il2CppDumper writes indented JSON with one
    ``"address"`` property per entry; compact JSON falls back to counting ``"address":`` occurrences)."""
    count = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.lstrip().startswith('"address":'):
                count += 1
            elif len(line) > 200 and line.count('"address":') > 1:   # compact JSON on very few lines
                count += line.count('"address":')
    return count


def summarize_dump(out_dir: Path, *, libs_paths: Optional[Sequence[Path]] = None, top_n: int = 500,
                   write_namespaces: bool = True) -> DumpSummary:
    """Summarise the artifacts below ``out_dir`` (the directory holding ``dump.cs`` or a C# tree).

    Never raises for missing/odd input: ``source == "none"`` plus a warning describes what was not found.
    Memory use is independent of the size of ``dump.cs``.
    """
    out_dir = Path(out_dir)
    summary = DumpSummary()
    stats = _NameStats()
    ns_counts: Dict[str, int] = {}
    dump = out_dir / "dump.cs"
    try:
        if dump.is_file():
            summary.source = "dump.cs"
            _scan_dump_cs(dump, summary, stats, ns_counts)
        else:
            tree = next((out_dir / d for d in ("DiffableCs", "cs") if (out_dir / d).is_dir()), None)
            if tree is not None:
                summary.source = "cs_tree"
                summary.warnings.append("C# tree output: method/field counts are not available")
                _scan_cs_tree(tree, summary, stats, ns_counts)
            else:
                summary.warnings.append("neither dump.cs nor a C# output tree was found in %s" % out_dir)
    except OSError as exc:
        summary.warnings.append("could not read the dump: %s" % exc)
    sl = out_dir / "stringliteral.json"
    if sl.is_file():
        try:
            summary.string_literals = count_string_literals(sl)
        except OSError as exc:
            summary.warnings.append("could not read stringliteral.json: %s" % exc)
    ordered = sorted(ns_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    summary.namespaces_total = len(ordered)
    summary.namespaces = [n for n, _c in ordered[:max(0, top_n)]]
    if write_namespaces and ordered:
        try:
            target = out_dir / NAMESPACES_FILE
            with open(target, "w", encoding="utf-8", newline="\n") as fh:
                for n, c in sorted(ns_counts.items()):
                    fh.write("%d\t%s\n" % (c, n))
            summary.namespaces_file = NAMESPACES_FILE
        except OSError as exc:
            summary.warnings.append("could not write %s: %s" % (NAMESPACES_FILE, exc))
    rules, warns = load_framework_rules(libs_paths)
    summary.warnings.extend(warns)
    hits = match_frameworks([n for n in ns_counts if n != GLOBAL_NAMESPACE], summary.assembly_names, rules)
    summary.framework_hits = hits
    summary.framework_namespaces = sorted({h["namespace"] for h in hits})
    summary.obfuscation = stats.result()
    return summary
