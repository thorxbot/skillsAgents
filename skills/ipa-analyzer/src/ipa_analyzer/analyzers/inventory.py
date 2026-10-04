"""Stage ``inventory`` (WP1): file table, categories, project / resource structure and "split" extraction.

Every file is typed by header bytes only (``util.magic``) and classified (``util.filetypes``); plist /
Mach-O contents are not parsed here. Entropy is recorded as a number for files >= 4 KiB (first 64 KiB
only, within a global byte budget) and never turned into an encryption verdict.

``build_inventory`` is a pure function of an ``ArchiveSource`` so that directory and zip inputs with
the same content give the same result (except ``csize``, which is only meaningful for zips).
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from ..config import EXTRACT_CATEGORIES
from ..context import AnalysisContext
from ..errors import InvalidInput
from ..ingest import ArchiveSource
from ..ingest.safe_extract import ExtractBudget, SafeExtractor
from ..models import Finding, StageResult, Verdict
from ..registry import register
from ..util.entropy import shannon
from ..util.filetypes import classify, file_ext, load_rules
from ..util.magic import TEXT_SNIFF_BYTES, sniff

log = logging.getLogger(__name__)

NAME = 'inventory'

TOP_N = 30
TREE_DEPTH = 3
ENTROPY_MIN_SIZE = 4096
ENTROPY_HEAD = 64 * 1024              # bytes read per file for entropy (same as util.entropy.HEAD_BYTES)
ENTROPY_BYTE_BUDGET = 512 * 1024 * 1024
ENTROPY_MAX_FILES = 100_000
INLINE_FILES_LIMIT = 20_000           # files kept in ctx.results; the full table is in inventory.json
INVENTORY_FILE = "inventory.json"
_READ_ERROR_EXAMPLES = 10

# "Extension says format X but the content is not X": files whose type is unknown by magic although the
# extension names a structured format. Files sharing one 4-byte header are clustered (custom containers).
HEADER_CLUSTER_MIN = 50
HEADER_CLUSTER_MAX_KEYS = 10_000      # distinct headers tracked (random / encrypted data would otherwise grow without bound)
HEADER_CLUSTER_EXAMPLES = 5
HEADER_CLUSTER_LIMIT = 20             # clusters reported
_STRUCTURED_CATEGORIES = frozenset({"image", "audio", "video", "script", "config"})

_DIR_UNIT_SUFFIX = {".framework": "framework", ".appex": "appex", ".bundle": "bundle", ".app": "app"}


def list_categories() -> Tuple[str, ...]:
    """Valid ``--extract`` values (for CLI validation)."""
    return tuple(EXTRACT_CATEGORIES)


def _rel(name: str, app_root: str) -> Optional[str]:
    if not app_root:
        return name
    return name[len(app_root):] if name.startswith(app_root) else None


def _unit_kind(parts: List[str], i: int) -> Optional[str]:
    comp = parts[i]
    dot = comp.rfind(".")
    if dot <= 0:
        return None
    kind = _DIR_UNIT_SUFFIX.get(comp[dot:].lower())
    if kind != "app":
        return kind
    if i == 0:
        return None
    if parts[0] == "Watch":
        return "watch_app"
    if parts[0] == "AppClips":
        return "app_clip"
    return "bundle"


def _new_node(name: str, kind: str) -> Dict[str, Any]:
    return {"name": name, "size": 0, "count": 0, "type": kind, "children": {}}


def _finish_tree(node: Dict[str, Any]) -> Dict[str, Any]:
    kids = sorted(node["children"].values(), key=lambda n: (-n["size"], n["name"]))
    return {"name": node["name"], "size": node["size"], "count": node["count"], "type": node["type"],
            "children": [_finish_tree(k) for k in kids]}


def build_inventory(source: ArchiveSource, app_root: str, *, root_name: str = "", tree_depth: int = TREE_DEPTH,
                    top_n: int = TOP_N, entropy_byte_budget: int = ENTROPY_BYTE_BUDGET,
                    entropy_max_files: int = ENTROPY_MAX_FILES,
                    header_cluster_min: int = HEADER_CLUSTER_MIN) -> Dict[str, Any]:
    """Build the full inventory (all files) for ``source``; see CONTRACT-FREEZE section 4.2."""
    rules = load_rules()
    entries = [e for e in source.namelist() if not e.is_dir]
    entries.sort(key=lambda e: e.name)
    names = {e.name for e in source.namelist()}
    files: List[Dict[str, Any]] = []
    cat_stat: Dict[str, List[int]] = {}
    ext_stat: Dict[str, List[int]] = {}
    units: Dict[str, Dict[str, Any]] = {}
    root = _new_node(root_name, "dir")
    top_dirs = set()
    lprojs_root = set()
    lprojs_any = set()
    read_errors: List[str] = []
    n_read_errors = 0
    sampled = skipped = 0
    entropy_bytes = 0
    total = 0
    clusters: Dict[bytes, Dict[str, Any]] = {}
    mismatch_files = mismatch_size = 0

    for e in entries:
        name = e.name
        rel = _rel(name, app_root)
        ext = file_ext(name)
        magic, conf, entropy = "unknown", 0.0, None
        if e.is_symlink:
            magic, conf = "symlink", 1.0
        elif e.size > 0:
            want_entropy = (e.size >= ENTROPY_MIN_SIZE and sampled < entropy_max_files
                            and entropy_bytes < entropy_byte_budget)
            n = min(e.size, ENTROPY_HEAD if want_entropy else TEXT_SNIFF_BYTES)
            try:
                data = source.read_head(name, n)
            except (InvalidInput, OSError, ValueError, OverflowError) as exc:
                data = b""
                n_read_errors += 1
                if len(read_errors) < _READ_ERROR_EXAMPLES:
                    read_errors.append("%s: %s" % (name, exc))
                magic = "unreadable"
            if data:
                magic, conf = sniff(data[:TEXT_SNIFF_BYTES])
                if magic == "unknown" and len(data) >= 4 and rules.ext.get(ext) in _STRUCTURED_CATEGORIES:
                    mismatch_files += 1
                    mismatch_size += e.size
                    head4 = bytes(data[:4])
                    cl = clusters.get(head4)
                    if cl is None and len(clusters) < HEADER_CLUSTER_MAX_KEYS:
                        cl = clusters[head4] = {"count": 0, "exts": {}, "size": 0, "examples": []}
                    if cl is not None:
                        cl["count"] += 1
                        cl["size"] += e.size
                        cl["exts"][ext] = cl["exts"].get(ext, 0) + 1
                        if len(cl["examples"]) < HEADER_CLUSTER_EXAMPLES:
                            cl["examples"].append(name)
                if want_entropy:
                    entropy = round(shannon(data), 4)
                    sampled += 1
                    entropy_bytes += len(data)
            if e.size >= ENTROPY_MIN_SIZE and entropy is None:
                skipped += 1
        elif e.size == 0:
            magic, conf = "empty", 1.0
        in_app = rel is not None
        if e.is_symlink or magic == "unreadable":
            category = "other" if e.is_symlink else classify(rel if in_app else name, "unknown", 0.0, in_app=in_app,
                                                              rules=rules)
        else:
            category = classify(rel if in_app else name, magic, conf, in_app=in_app, rules=rules)
        item: Dict[str, Any] = {"path": name, "size": e.size, "csize": e.compressed_size, "ext": ext,
                                "magic": magic, "category": category}
        if entropy is not None:
            item["entropy"] = entropy
        files.append(item)
        total += e.size
        s = cat_stat.setdefault(category, [0, 0])
        s[0] += 1
        s[1] += e.size
        x = ext_stat.setdefault(ext, [0, 0])
        x[0] += 1
        x[1] += e.size

        if not in_app:
            continue
        parts = rel.split("/")
        if len(parts) > 1:
            top_dirs.add(parts[0])
        for i, comp in enumerate(parts[:-1]):
            if comp.endswith(".lproj"):
                code = comp[:-len(".lproj")]
                lprojs_any.add(code)
                if i == 0:
                    lprojs_root.add(code)
            kind = _unit_kind(parts, i)
            if kind:
                prefix = "/".join(parts[:i + 1])
                u = units.setdefault(prefix, {"path": app_root + prefix, "rel": prefix, "kind": kind,
                                              "name": comp[:comp.rfind(".")], "size": 0, "file_count": 0})
                u["size"] += e.size
                u["file_count"] += 1
        if ext == ".dylib":
            units[rel] = {"path": name, "rel": rel, "kind": "dylib", "name": parts[-1], "size": e.size,
                          "file_count": 1}
        # directory tree rooted at the .app
        root["size"] += e.size
        root["count"] += 1
        node = root
        for i in range(min(len(parts), tree_depth)):
            leaf = i == len(parts) - 1
            child = node["children"].get(parts[i])
            if child is None:
                child = node["children"][parts[i]] = _new_node(parts[i], "file" if leaf else "dir")
            child["size"] += e.size
            child["count"] += 1
            node = child

    pct_base = total or 1
    by_category = [{"category": c, "count": v[0], "size": v[1], "percent": round(100.0 * v[1] / pct_base, 2)}
                   for c, v in cat_stat.items()]
    by_category.sort(key=lambda d: (-d["size"], d["category"]))
    by_ext = [{"ext": x, "count": v[0], "size": v[1]} for x, v in ext_stat.items()]
    by_ext.sort(key=lambda d: (-d["size"], d["ext"]))
    top_files = [{"path": f["path"], "size": f["size"], "category": f["category"]}
                 for f in sorted(files, key=lambda f: (-f["size"], f["path"]))[:top_n]]
    archives = [{"path": f["path"], "size": f["size"], "magic": f["magic"], "category": f["category"]}
                for f in files if f["category"] == "packed_archive"]
    root_children = top_dirs
    hints_has = {
        "Frameworks": "Frameworks" in root_children, "PlugIns": "PlugIns" in root_children,
        "Watch": "Watch" in root_children, "SC_Info": "SC_Info" in root_children,
        "_CodeSignature": "_CodeSignature" in root_children, "Data": "Data" in root_children,
        "Assets_car": (app_root + "Assets.car") in names,
        "embedded_mobileprovision": (app_root + "embedded.mobileprovision") in names,
        "iTunesMetadata_plist": "iTunesMetadata.plist" in names,
    }
    header_clusters = [
        {"head_hex": h.hex(), "head_ascii": "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in h),
         "count": c["count"], "exts": dict(sorted(c["exts"].items())), "size": c["size"], "examples": c["examples"]}
        for h, c in sorted(clusters.items(), key=lambda kv: (-kv[1]["count"], kv[0]))
        if c["count"] >= header_cluster_min][:HEADER_CLUSTER_LIMIT]
    return {
        "files": files,
        "files_total": len(files),
        "files_truncated": False,
        "total_size": total,
        "inventory_file": INVENTORY_FILE,
        "by_category": by_category,
        "by_ext": by_ext,
        "top_files": top_files,
        "localizations": sorted(lprojs_root or lprojs_any),
        "archives": archives,
        "nested_units": sorted(units.values(), key=lambda u: u["path"]),
        "tree": _finish_tree(root),
        "structure_hints": {"top_level_dirs": sorted(top_dirs), "has": hints_has},
        "entropy_info": {"head_bytes": ENTROPY_HEAD, "sampled_files": sampled, "skipped_files": skipped,
                         "budget_exhausted": skipped > 0},
        "read_errors": {"count": n_read_errors, "examples": read_errors},
        "header_clusters": header_clusters,
        "ext_magic_mismatch": {"files": mismatch_files, "size": mismatch_size},
    }


# --- split ("--extract") ----------------------------------------------------------------------------
def select_for_split(category: str, files: List[Dict[str, Any]], app_root: str,
                     nested_units: List[Dict[str, Any]]) -> List[str]:
    """Archive names belonging to an ``--extract`` category (see ``list_categories``)."""
    if category not in EXTRACT_CATEGORIES:
        raise ValueError("unknown extract category %r" % category)
    if category == "all":
        return [f["path"] for f in files]
    bundle_prefixes = tuple(u["path"] + "/" for u in nested_units if u["kind"] == "bundle")
    out = []
    for f in files:
        name, cat = f["path"], f["category"]
        rel = _rel(name, app_root)
        if category == "binary":
            ok = cat == "executable"
        elif category == "frameworks":
            ok = cat in ("framework", "dylib") or (rel is not None and rel.startswith("Frameworks/"))
        elif category == "metadata":
            ok = (cat == "signing" or rel in ("Info.plist", "PkgInfo") or f["magic"] == "il2cpp_metadata"
                  or name.endswith("/global-metadata.dat"))
        elif category == "bundles":
            ok = cat == "assetbundle" or name.startswith(bundle_prefixes)
        else:  # plists
            ok = cat == "plist"
        if ok:
            out.append(name)
    return out


def _run_split(ctx: AnalysisContext, data: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    result: Dict[str, Any] = {}
    warnings: List[str] = []
    wanted = list(dict.fromkeys(ctx.cfg.extract))
    if "all" in wanted:
        wanted = ["all"]
    for cat in wanted:
        names = select_for_split(cat, data["files"], ctx.app_root, data["nested_units"])
        rel_dir = "split/%s" % cat
        root = ctx.out_dir / "split" / cat
        ex = SafeExtractor(ctx.source, root, ctx.cfg.limits,  # type: ignore[arg-type]
                           path_fn=lambda n: ctx.rel(n) if ctx.rel(n) is not None else "_archive/" + n,
                           manifest_path=ctx.out_dir / "split" / (cat + ".manifest.json"), budget=ExtractBudget())
        got, errors = ex.extract_many(names)
        ex.save_manifest()
        for n, msg in sorted(errors.items())[:20]:
            warnings.append("split/%s: skipping %r: %s" % (cat, n, msg))
        if len(errors) > 20:
            warnings.append("split/%s: %d more entries skipped" % (cat, len(errors) - 20))
        result[cat] = {"dir": rel_dir, "selected": len(names), "files": len(got),
                       "size": sum(os.path.getsize(p) for p in got.values()), "errors": len(errors),
                       "manifest": rel_dir + ".manifest.json"}
    return result, warnings


def _write_inventory_file(ctx: AnalysisContext, data: Dict[str, Any]) -> None:
    path = ctx.artifact_path(INVENTORY_FILE)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, ensure_ascii=False, separators=(",", ":"))
        fh.write("\n")
    os.replace(tmp, path)
    ctx.register_artifact(INVENTORY_FILE, INVENTORY_FILE)


@register(name='inventory', requires=('ingest',))
class InventoryStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        if ctx.source is None:
            return StageResult.skipped(NAME, "no input source is open")
        ingest = ctx.results.get("ingest") or {}
        root_name = ingest.get("app_name_dir") or ctx.input_path.name
        data = build_inventory(ctx.source, ctx.app_root, root_name=root_name)
        warnings: List[str] = []
        if data["read_errors"]["count"]:
            warnings.append("%d file(s) could not be read for type sniffing (e.g. %s)"
                            % (data["read_errors"]["count"], data["read_errors"]["examples"][0]))
        if data["entropy_info"]["budget_exhausted"]:
            warnings.append("entropy sampled for %d files; %d more were skipped (sampling budget reached)"
                            % (data["entropy_info"]["sampled_files"], data["entropy_info"]["skipped_files"]))

        _write_inventory_file(ctx, data)          # complete table, relative to out_dir
        full_files = data["files"]
        if len(full_files) > INLINE_FILES_LIMIT:
            data = dict(data)
            data["files"] = full_files[:INLINE_FILES_LIMIT]
            data["files_truncated"] = True
        partial = False
        if ctx.cfg.extract:
            split, split_warnings = _run_split(ctx, dict(data, files=full_files))
            data["split"] = split
            warnings += split_warnings
            partial = any(v["errors"] for v in split.values())

        top = data["by_category"][0]["category"] if data["by_category"] else "other"
        finding = Finding(
            "inventory.summary", Verdict.YES, 1.0, "File inventory built",
            "%d files, %d bytes; largest category: %s" % (data["files_total"], data["total_size"], top),
            params={"files": data["files_total"], "size": data["total_size"], "top_category": top,
                    "localizations": len(data["localizations"]), "nested_units": len(data["nested_units"])})
        if partial:
            return StageResult.partial(NAME, data, [finding], warnings, reason="some files could not be extracted")
        return StageResult.ok(NAME, data, [finding], warnings)
