"""Markdown report renderer (zh / en through the i18n catalog).

Input is the *report dict* (``Report.to_dict()`` / ``report.json``) plus a ``Catalog``; no stage code is
imported. Chapter order is fixed (see ``render_markdown``). A stage that did not run never silently
disappears: its chapter says "Not run: <reason> (<advice>)". Text is written to be readable as plain
UTF-8 (verdict badges are text), tables escape ``|``, backticks, ``*`` and line breaks.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .i18n import Catalog
from .summary import (RISK_FINDING_IDS, PROTECTION_ORDER, StageNote, build_summary, custom_engine, d_, dump_state,
                      exec_rows, explain_stage, findings_of, fmt_conf, g, is_unity_app, l_, not_run_line,
                      stage_map)

__all__ = ["render_markdown", "esc", "code", "Md", "fmt_size", "split_row"]

MAX_ROWS = 60          # rows per table before "... N more (see report.json)"
CELL_MAX = 120         # characters per evidence / free-text cell


# --- low level helpers ---------------------------------------------------------------------------
class Md(str):
    """A string that is already valid Markdown (not escaped again by ``cell``)."""


_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_BSL_RE = re.compile(r"\\(?=[\\`*_{}\[\]()#+\-.!|<>~])")
_TAG_RE = re.compile(r"<(?=[A-Za-z/!?])")


def esc(text: Any, nl: str = "<br>") -> str:
    """Escape ``text`` for use inside Markdown text / table cells."""
    s = "" if text is None else str(text)
    s = _CTRL_RE.sub("", s.replace("\r\n", "\n").replace("\r", "\n"))
    s = _BSL_RE.sub(r"\\\\", s)
    s = s.replace("`", "\\`").replace("*", "\\*").replace("|", "\\|")
    s = _TAG_RE.sub(r"\\<", s)
    return s.replace("\n", nl)


def clip(s: Any, n: int = CELL_MAX) -> str:
    s = " ".join(("" if s is None else str(s)).split())
    return s if len(s) <= n else s[: max(n - 1, 1)] + "…"


def code(text: Any, maxlen: int = 0, *, pipe: bool = True) -> Md:
    """Inline code span (safe for table cells with ``pipe=True``)."""
    s = " ".join(("" if text is None else str(text)).split())
    if not s:
        return Md("—")
    if maxlen:
        s = clip(s, maxlen)
    s = _CTRL_RE.sub("", s)
    if pipe:
        s = s.replace("|", "\\|")
    longest = max([len(m) for m in re.findall(r"`+", s)] + [0])
    fence = "`" * (longest + 1)
    pad = " " if s.startswith("`") or s.endswith("`") else ""
    return Md("%s%s%s%s%s" % (fence, pad, s, pad, fence))


def fmt_size(n: Any) -> str:
    try:
        v = float(n)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024 or unit == "TB":
            return "%d B" % v if unit == "B" else "%.1f %s" % (v, unit)
        v /= 1024.0
    return "—"


def fmt_num(v: Any) -> str:
    if isinstance(v, bool) or v is None:
        return "—"
    if isinstance(v, int):
        return "{:,}".format(v)
    if isinstance(v, float):
        return ("%.4f" % v).rstrip("0").rstrip(".") if v != int(v) else "{:,}".format(int(v))
    return str(v)


def bar(percent: float, width: int = 20) -> str:
    n = max(0, min(width, int(round(percent / 100.0 * width))))
    return "█" * n + "░" * (width - n)


def split_row(line: str) -> List[str]:
    """Split a Markdown table row into cells (honours ``\\|`` escapes). Used by tests / the HTML converter."""
    body = line.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|") and not body.endswith("\\|"):
        body = body[:-1]
    cells, cur, i = [], [], 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body) and body[i + 1] == "|":
            cur.append("\\|")
            i += 2
            continue
        if ch == "`":      # code span: pipes inside are escaped, so just copy through
            j = i
            while j < len(body) and body[j] == "`":
                j += 1
            fence = body[i:j]
            k = body.find(fence, j)
            if k != -1:
                cur.append(body[i:k + len(fence)])
                i = k + len(fence)
                continue
        if ch == "|":
            cells.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    cells.append("".join(cur).strip())
    return cells


_PROT_IDS = frozenset(PROTECTION_ORDER)
_LANG_KEYS = ("objc", "swift", "c", "cpp", "csharp", "lua", "javascript", "typescript", "dart", "python", "java",
              "kotlin", "rust", "go")


class _R:
    """One rendering pass."""

    def __init__(self, report: Mapping[str, Any], cat: Catalog, summary: Optional[Mapping[str, Any]]) -> None:
        self.r = report
        self.cat = cat
        self.t = cat.t
        self.lang = cat.lang
        self.stages = stage_map(report)
        self.sm: Mapping[str, Any] = summary if summary else (report.get("summary") or build_summary(report))
        self.findings = findings_of(report)
        self._notes: Dict[str, StageNote] = {}

    # --- formatting ------------------------------------------------------------------------------
    def fv(self, v: Any, depth: int = 0) -> str:
        """Plain-text value formatter: never yields ``None`` / ``{}`` / ``[]`` text."""
        t = self.t
        if v is None or v == "" or v == [] or v == {}:
            return "—"
        if isinstance(v, bool):
            return t("report.yes") if v else t("report.no")
        if isinstance(v, (int, float)):
            return fmt_num(v)
        if isinstance(v, str):
            return v
        if isinstance(v, (list, tuple)):
            parts = [self.fv(x, depth + 1) for x in v[:12]]
            more = t("report.more_n", n=len(v) - 12) if len(v) > 12 else ""
            return ", ".join(parts) + more
        if isinstance(v, dict):
            if depth >= 2:
                return t("report.n_fields", n=len(v))
            items = ["%s=%s" % (k, self.fv(x, depth + 1)) for k, x in sorted(v.items(), key=lambda kv: str(kv[0]))[:8]]
            return "; ".join(items) + (t("report.more_n", n=len(v) - 8) if len(v) > 8 else "")
        return str(v)

    def cell(self, v: Any) -> str:
        if isinstance(v, Md):
            return str(v)
        return esc(self.fv(v))

    def table(self, headers: Sequence[str], rows: Iterable[Sequence[Any]], *, right: Sequence[int] = (),
              limit: int = MAX_ROWS) -> List[str]:
        rows = list(rows)
        if not rows:
            return [self.t("report.none"), ""]
        n = len(headers)
        out = ["| " + " | ".join(esc(h) for h in headers) + " |",
               "| " + " | ".join("---:" if i in right else "---" for i in range(n)) + " |"]
        for row in rows[:limit]:
            cells = [self.cell(c) for c in list(row)[:n]]
            cells += ["—"] * (n - len(cells))
            out.append("| " + " | ".join(cells) + " |")
        out.append("")
        if len(rows) > limit:
            out.append(self.t("report.table_more", n=len(rows) - limit))
            out.append("")
        return out

    def kv(self, pairs: Iterable[Tuple[str, Any]], headers: Optional[Tuple[str, str]] = None) -> List[str]:
        pairs = [(k, v) for k, v in pairs]
        h = headers or (self.t("report.col.item"), self.t("report.col.value"))
        return self.table(list(h), [(k, v) for k, v in pairs])

    def bullets(self, items: Iterable[Any], limit: int = 20) -> List[str]:
        items = [i for i in items if i not in (None, "")]
        out = ["- " + (str(i) if isinstance(i, Md) else esc(self.fv(i), nl=" ")) for i in items[:limit]]
        if len(items) > limit:
            out.append("- " + self.t("report.more_n", n=len(items) - limit).strip())
        out.append("")
        return out

    def H(self, level: int, num: str, key: str) -> str:
        return "%s %s %s" % ("#" * level, num + ("." if level == 2 else ""), self.t("report.h." + key))

    def para(self, text: str) -> List[str]:
        return [text, ""]

    def quote(self, text: str) -> List[str]:
        return ["> " + text, ""]

    def note(self, stage: str) -> StageNote:
        if stage not in self._notes:
            self._notes[stage] = explain_stage(stage, self.r, self.t)
        return self._notes[stage]

    def gate(self, *stages: str) -> Tuple[List[str], bool]:
        """``(notice lines, all_ran)`` for the stages a chapter depends on."""
        lines: List[str] = []
        ran = True
        for s in stages:
            n = self.note(s)
            if not n.ran:
                ran = False
                lines += self.quote(Md("**%s**" % esc(not_run_line(n, self.t), nl=" ")))
            elif n.status == "partial":
                lines += self.quote(Md("*%s*" % esc(n.text, nl=" ")))
        return lines, ran

    # --- badges / findings -----------------------------------------------------------------------
    def badge(self, verdict: Any, fid: str = "", risk: Optional[bool] = None) -> str:
        v = str(verdict)
        key = "na" if v == "n/a" else (v if v in ("yes", "no", "suspected", "unknown") else "unknown")
        polarity = "risk" if (risk if risk is not None else fid in RISK_FINDING_IDS) else "info"
        return self.t("report.badge.%s.%s" % (polarity, key))

    def conf(self, c: Any) -> str:
        return fmt_conf(c, self.t)

    def ftext(self, f: Mapping[str, Any]) -> Tuple[str, str, str]:
        ft = self.cat.finding_text(f)
        return ft.title, ft.summary, ft.remediation

    def ev_cell(self, evidence: Any, limit: int = 3) -> Md:
        ev = [e for e in l_(evidence) if isinstance(e, dict)]
        if not ev:
            return Md("—")
        parts = []
        for e in ev[:limit]:
            s = "%s: %s" % (esc(e.get("kind") or "?"), code(e.get("ref"), 48))
            if e.get("detail"):
                s += " — " + esc(clip(e["detail"], 40))
            parts.append(s)
        txt = "; ".join(parts)
        if len(ev) > limit:
            txt += " " + esc(self.t("report.more_n", n=len(ev) - limit).strip())
        return Md(txt)

    def finding_table(self, findings: Sequence[Mapping[str, Any]]) -> List[str]:
        rows = []
        for f in findings:
            title, summ, _ = self.ftext(f)
            rows.append((title, self.badge(f.get("verdict"), str(f.get("id"))), self.conf(f.get("confidence")),
                         Md(esc(clip(summ, 200))) if summ else "—"))
        return self.table([self.t("report.col.item"), self.t("report.col.verdict"),
                           self.t("report.col.confidence"), self.t("report.col.summary")], rows)

    def finding_details(self, findings: Sequence[Mapping[str, Any]], *, skip_protection: bool = False) -> List[str]:
        out: List[str] = []
        for f in findings:
            if skip_protection and f.get("id") in _PROT_IDS:
                continue       # shown with evidence and advice in chapter 7
            ev = [e for e in l_(f.get("evidence")) if isinstance(e, dict)]
            title, summ, rem = self.ftext(f)
            if not ev and not rem:
                continue
            out.append("- **%s** %s %s %s" % (esc(title, nl=" "), self.badge(f.get("verdict"), str(f.get("id"))),
                                              esc(self.conf(f.get("confidence"))),
                                              code(f.get("id"), pipe=False)))
            if summ:
                out.append("  - " + esc(clip(summ, 400), nl=" "))
            for e in ev[:5]:
                line = "  - %s %s: %s" % (self.t("report.evidence"), esc(e.get("kind") or "?"),
                                          code(e.get("ref"), 90, pipe=False))
                if e.get("detail"):
                    line += " — " + esc(clip(e["detail"], 120), nl=" ")
                out.append(line)
            if len(ev) > 5:
                out.append("  - " + esc(self.t("report.evidence_more", n=len(ev) - 5), nl=" "))
            if rem:
                out.append("  - %s%s" % (esc(self.t("report.advice"), nl=" "), esc(clip(rem, 400), nl=" ")))
        if out:
            out.append("")
        return out

    def flatten(self, data: Any, prefix: str = "", depth: int = 3, skip: Iterable[str] = ()) -> List[Tuple[Any, Any]]:
        """Flatten nested dict data into ``(key, value)`` rows (lists of dicts become a count)."""
        return [(code(k), v) for k, v in self._flat_rows(data, prefix, depth, skip)]

    def _flat_rows(self, data: Any, prefix: str, depth: int, skip: Iterable[str]) -> List[Tuple[str, Any]]:
        rows: List[Tuple[str, Any]] = []
        skipset = set(skip)
        for k in sorted(d_(data)):
            if k in skipset:
                continue
            v = data[k]
            key = prefix + k
            if v is None or v == "" or v == [] or v == {}:
                continue
            if isinstance(v, dict) and depth > 1:
                rows += self._flat_rows(v, key + ".", depth - 1, ())
            elif isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                rows.append((key, self.t("report.n_items", n=len(v))))
            else:
                rows.append((key, v))
        return rows

    # --- label lookups -----------------------------------------------------------------------------
    def label(self, *keys: str, default: str = "") -> str:
        for k in keys:
            if self.cat.has(k, any_lang=True):
                return self.cat.tr(k)
        return default

    def category_label(self, cid: Any) -> str:
        cid = str(cid)
        return self.label("inventory.category." + cid, "report.fallback.category." + cid,
                          default=cid.replace("_", " "))

    def libcat_label(self, cid: Any) -> str:
        cid = str(cid)
        return self.label("libs.category." + cid, "report.libcat." + cid, default=cid.replace("_", " "))

    def engine_name(self, eid: str, data: Any = None) -> str:
        return self.label("engine.name." + eid, "report.engine." + eid, default=eid)

    # === document ===============================================================================
    def render(self) -> str:
        out: List[str] = []
        out += self.s0_header()
        out += self.s1_summary()
        out += self.s2_basic()
        out += self.s3_type()
        out += self.s4_structure()
        out += self.s5_resources()
        out += self.s6_libs()
        out += self.s7_protect()
        out += self.s8_engine()
        out += self.s9_privacy()
        out += self.s10_appendix()
        text = "\n".join(out).rstrip("\n") + "\n"
        return re.sub(r"\n{3,}", "\n\n", text)

    # --- 0. header -------------------------------------------------------------------------------
    def s0_header(self) -> List[str]:
        t, r = self.t, self.r
        name = self.sm.get("name") or re.split(r"[\\/]", str(g(r, "input", "path") or "-"))[-1]
        total = sum(float(s.get("duration_s") or 0) for s in self.stages.values())
        inp = d_(r.get("input"))
        parts: List[Any] = [
            "%s %s" % (g(r, "tool", "name", default="ipa-analyzer"), g(r, "tool", "version", default="")),
            t("report.meta.schema", v=r.get("schema_version") or "-"),
            t("report.meta.generated", v=r.get("generated_at") or "-"),
            t("report.meta.input", kind=inp.get("kind") or "-", size=fmt_size(inp.get("size"))),
            Md("sha256 " + str(code(inp.get("sha256") or "-", pipe=False))),
            t("report.meta.duration", v="%.2f" % total),
        ]
        line = " \u00b7 ".join(str(p) if isinstance(p, Md) else esc(p, nl=" ") for p in parts)
        return ["# " + esc(t("report.title", name=name), nl=" "), "", "> " + line, ""]

    # --- 1. executive summary ----------------------------------------------------------------------
    def s1_summary(self) -> List[str]:
        t = self.t
        out = [self.H(2, "1", "summary"), ""]
        rows = exec_rows(self.r, self.sm, t)
        out += self.table([t("report.col.item"), t("report.col.conclusion")], rows)
        cust = custom_engine(self.r)
        if cust.get("verdict") in ("yes", "suspected"):
            out += self.quote(Md("**%s** %s" % (esc(t("report.custom.callout_title"), nl=" "),
                                                esc(t("report.custom.callout", verdict=t("report.verdict." + str(cust["verdict"])),
                                                      conf=self.conf(cust.get("confidence"))), nl=" "))))
        return out

    # --- 2. basic info -----------------------------------------------------------------------------
    def s2_basic(self) -> List[str]:
        t, r = self.t, self.r
        app, inp = d_(r.get("app")), d_(r.get("input"))
        out = [self.H(2, "2", "basic"), ""]
        gate, ran = self.gate("meta")
        out += gate
        dist = app.get("distribution")
        dist = dist if isinstance(dist, dict) else ({"type": dist} if dist else {})
        sdk = d_(app.get("sdk"))
        prov = d_(app.get("provision"))
        pairs: List[Tuple[str, Any]] = [
            (t("report.basic.name"), app.get("selected_name")),
            (t("report.basic.bundle_id"), Md(str(code(app.get("bundle_id")))) if app.get("bundle_id") else None),
            (t("report.basic.version"), app.get("version")),
            (t("report.basic.build"), app.get("build")),
            (t("report.basic.executable"), Md(str(code(app.get("executable")))) if app.get("executable") else None),
            (t("report.basic.min_os"), app.get("min_os")),
            (t("report.basic.devices"), app.get("devices")),
            (t("report.basic.input"), "%s, %s" % (inp.get("kind") or "-", fmt_size(inp.get("size")))),
            (t("report.basic.input_path"), Md(str(code(inp.get("path")))) if inp.get("path") else None),
            (t("report.basic.sha256"), Md(str(code(inp.get("sha256")))) if inp.get("sha256") else None),
        ]
        if dist:
            dtxt = t("report.dist." + str(dist.get("type")), str(dist.get("type"))) if dist.get("type") else "—"
            pairs.append((t("report.basic.distribution"), "%s (%s)" % (
                dtxt, self.conf(dist.get("confidence")) if dist.get("confidence") is not None else "-")))
        if sdk:
            pairs.append((t("report.basic.sdk"), "; ".join("%s=%s" % (k, self.fv(v)) for k, v in sorted(sdk.items()) if v)))
        if prov:
            pairs.append((t("report.basic.provision"), "; ".join("%s=%s" % (k, self.fv(v)) for k, v in sorted(prov.items())
                                                                  if v is not None)))
        sig = d_(app.get("signature_integrity"))
        if sig:
            pairs.append((t("report.basic.signature_integrity"), "; ".join(
                "%s=%s" % (k, self.fv(sig.get(k))) for k in ("checked", "missing", "modified", "extra") if k in sig)))
        pairs.append((t("report.basic.background_modes"), app.get("background_modes")))
        pairs.append((t("report.basic.capabilities"), app.get("capabilities")))
        out += self.kv(pairs)
        names = [n for n in l_(app.get("names")) if isinstance(n, dict)]
        if names:
            out += [self.H(3, "2.1", "names"), ""]
            out += self.table([t("report.col.name"), t("report.col.source"), t("report.col.lang")],
                              [(n.get("value"), n.get("source"), n.get("lang")) for n in names])
        exts = [e for e in l_(app.get("extensions")) if isinstance(e, dict)]
        if exts:
            out += [self.H(3, "2.2", "extensions"), ""]
            out += self.table([t("report.col.path"), t("report.col.kind"), "Bundle ID", t("report.col.point")],
                              [(Md(str(code(e.get("path")))), e.get("kind"), e.get("bundle_id"), e.get("point"))
                               for e in exts])
        ev = l_(dist.get("evidence")) if dist else []
        if ev:
            out += [self.H(3, "2.3", "dist_evidence"), ""]
            out += self.table([t("report.col.kind"), t("report.col.ref"), t("report.col.detail")],
                              [(e.get("kind"), Md(str(code(e.get("ref"), 80))), clip(e.get("detail"), 100))
                               for e in ev if isinstance(e, dict)])
        return out

    # --- 3. project type ---------------------------------------------------------------------------
    def s3_type(self) -> List[str]:
        t, r = self.t, self.r
        cls = d_(r.get("classification"))
        out = [self.H(2, "3", "type"), ""]
        gate, ran = self.gate("classify")
        out += gate
        if cls:
            ru = d_(cls.get("runner_up"))
            out += self.kv([
                (t("report.type.category"), t("report.category." + str(cls.get("category")), str(cls.get("category")))
                 if cls.get("category") else None),
                (t("report.type.subcategory"), cls.get("subcategory")),
                (t("report.col.confidence"), self.conf(cls.get("confidence")) if cls.get("confidence") is not None else None),
                (t("report.type.runner_up"), "%s (%s)" % (t("report.category." + str(ru.get("category")),
                                                            str(ru.get("category"))), self.fv(ru.get("score")))
                 if ru else None),
            ])
            evs = [e for e in l_(cls.get("evidence")) if isinstance(e, dict)]
            if evs:
                out += [self.H(3, "3.1", "evidence"), ""]
                out += self.table([t("report.col.kind"), t("report.col.ref"), t("report.col.detail")],
                                  [(e.get("kind"), Md(str(code(e.get("ref"), 80))), clip(e.get("detail"), 120)) for e in evs])
        fs = [f for f in self.findings if f.get("id") == "classify.category"]
        if fs:
            out += self.finding_table(fs)
        return out

    # --- 4. structure ------------------------------------------------------------------------------
    def _tree_lines(self, node: Mapping[str, Any], prefix: str, is_root: bool, out: List[str], budget: List[int]) -> None:
        t = self.t
        children = [c for c in l_(node.get("children")) if isinstance(c, dict)]
        children.sort(key=lambda c: (-float(c.get("size") or 0), str(c.get("name"))))
        shown = children[:25]
        for i, ch in enumerate(shown):
            if budget[0] <= 0:
                return
            last = i == len(shown) - 1 and len(children) <= 25
            is_dir = bool(ch.get("children")) or int(ch.get("count") or 1) > 1
            label = "%s%s  (%s%s)" % (ch.get("name"), "/" if is_dir else "", fmt_size(ch.get("size")),
                                      (", " + t("report.tree.files", n=fmt_num(ch.get("count")))) if is_dir else "")
            out.append("%s%s%s" % (prefix, "└── " if last else "├── ", label))
            budget[0] -= 1
            self._tree_lines(ch, prefix + ("    " if last else "│   "), False, out, budget)
        if len(children) > 25:
            out.append("%s└── %s" % (prefix, t("report.tree.more", n=len(children) - 25).strip()))

    def s4_structure(self) -> List[str]:
        t, r = self.t, self.r
        st = d_(r.get("structure"))
        out = [self.H(2, "4", "structure"), ""]
        # 4.1 tree
        out += [self.H(3, "4.1", "tree"), ""]
        gate, ran = self.gate("inventory")
        out += gate
        tree = st.get("tree")
        if isinstance(tree, dict) and tree:
            lines = ["%s/  (%s, %s)" % (tree.get("name") or ".", fmt_size(tree.get("size")),
                                        t("report.tree.files", n=fmt_num(tree.get("count"))))]
            self._tree_lines(tree, "", True, lines, [80])
            out += ["```text"] + [ln.replace("```", "'''") for ln in lines] + ["```", ""]
        elif ran:
            out += [t("report.none"), ""]
        # 4.2 nested units
        out += [self.H(3, "4.2", "nested"), ""]
        units = [u for u in l_(st.get("nested_units")) if isinstance(u, dict)]
        out += gate
        if ran or units:
            out += self.table([t("report.col.path"), t("report.col.kind"), t("report.col.name"),
                               t("report.col.size"), t("report.col.files")],
                              [(Md(str(code(u.get("rel") or u.get("path"), 70))), u.get("kind"), u.get("name"),
                                fmt_size(u.get("size")), fmt_num(u.get("file_count"))) for u in
                               sorted(units, key=lambda u: str(u.get("path")))], right=(3, 4))
        # 4.3 mach-o
        out += [self.H(3, "4.3", "macho"), ""]
        gate, ran = self.gate("macho")
        out += gate
        bins = [b for b in l_(st.get("binaries")) if isinstance(b, dict)]
        ms = d_(st.get("macho_summary"))
        if ms:
            out += self.kv([(t("report.macho.main"), Md(str(code(ms.get("main_binary")))) if ms.get("main_binary") else None),
                            (t("report.macho.archs"), ms.get("archs")), (t("report.basic.min_os"), ms.get("min_os")),
                            (t("report.macho.any_encrypted"), ms.get("any_encrypted")),
                            (t("report.macho.all_encrypted"), ms.get("all_encrypted")),
                            (t("report.macho.languages_hint"), ms.get("languages_hint"))])
        if bins:
            order = {"main": 0, "framework": 1, "dylib": 2, "appex": 3, "watch": 4, "other": 5}
            bins = sorted(bins, key=lambda b: (order.get(str(b.get("role")), 9), str(b.get("path"))))
            rows = []
            for b in bins:
                sl = [s for s in l_(b.get("slices")) if isinstance(s, dict)]
                rows.append((Md(str(code(b.get("rel") or b.get("path"), 60))), b.get("role"), b.get("kind"),
                             [s.get("arch") for s in sl], self._uniq([s.get("min_os") for s in sl]),
                             self._tri([s.get("encrypted") for s in sl]), self._tri([s.get("signed") for s in sl]),
                             self._tri([s.get("is_pie") for s in sl]), self._tri([s.get("stripped") for s in sl]),
                             self._langs(sl), clip("; ".join(map(str, l_(b.get("parse_warnings")))), 60)))
            out += self.table([t("report.col.path"), t("report.col.role"), t("report.col.kind"),
                               t("report.macho.col_archs"), t("report.basic.min_os"), "FairPlay",
                               t("report.macho.col_signed"), "PIE", t("report.macho.col_stripped"),
                               t("report.macho.col_langs"), t("report.col.warnings")], rows)
        elif ran:
            out += [t("report.none"), ""]
        # 4.4 languages
        out += [self.H(3, "4.4", "languages"), ""]
        langs = [x for x in l_(st.get("languages")) if isinstance(x, dict)]
        gate, ran = self.gate("engine.detect")
        out += gate
        if langs:
            out += self.table([t("report.col.language"), t("report.col.confidence"), t("report.col.evidence")],
                              [(t("report.lang." + str(x.get("lang")), str(x.get("lang"))), self.conf(x.get("confidence")),
                                self.ev_cell(x.get("evidence"), 2)) for x in
                               sorted(langs, key=lambda x: (-float(x.get("confidence") or 0), str(x.get("lang"))))])
        elif ran:
            out += [t("report.none"), ""]
        return out

    def _uniq(self, vals: Iterable[Any]) -> str:
        seen = sorted({str(v) for v in vals if v not in (None, "")})
        return ", ".join(seen) if seen else "—"

    def _tri(self, vals: Sequence[Any]) -> str:
        known = [v for v in vals if isinstance(v, bool)]
        if not known:
            return "—"
        if all(known):
            return self.t("report.yes")
        if not any(known):
            return self.t("report.no")
        return self.t("report.partial_word")

    def _langs(self, slices: Sequence[Mapping[str, Any]]) -> str:
        names = [n for k, n in (("has_objc", "ObjC"), ("has_swift", "Swift"), ("has_cpp", "C++"))
                 if any(s.get(k) is True for s in slices)]
        return ", ".join(names) if names else "—"

    # --- 5. resources ------------------------------------------------------------------------------
    def s5_resources(self) -> List[str]:
        t, r = self.t, self.r
        res = d_(r.get("resources"))
        out = [self.H(2, "5", "resources"), ""]
        gate, ran = self.gate("inventory")
        out += gate
        if not ran and not any(res.get(k) for k in ("by_category", "by_ext", "top_files", "archives", "localizations")):
            return out
        total_files = res.get("files_total")
        if total_files is not None:
            line = t("report.res.total", n=fmt_num(total_files))
            if res.get("inventory_file"):
                line += " " + t("report.res.see_inventory", file=res["inventory_file"])
            out += self.para(esc(line, nl=" "))
        cats = [c for c in l_(res.get("by_category")) if isinstance(c, dict)]
        out += [self.H(3, "5.1", "categories"), ""]
        total = sum(float(c.get("size") or 0) for c in cats) or 1.0
        out += self.table([t("report.col.category"), t("report.col.count"), t("report.col.size"),
                           t("report.col.percent"), ""],
                          [(self.category_label(c.get("category")), fmt_num(c.get("count")), fmt_size(c.get("size")),
                            "%.1f%%" % (float(c.get("size") or 0) / total * 100.0),
                            Md(bar(float(c.get("size") or 0) / total * 100.0)))
                           for c in sorted(cats, key=lambda c: (-float(c.get("size") or 0), str(c.get("category"))))],
                          right=(1, 2, 3))
        out += [self.H(3, "5.2", "exts"), ""]
        exts = sorted([e for e in l_(res.get("by_ext")) if isinstance(e, dict)],
                      key=lambda e: (-float(e.get("size") or 0), str(e.get("ext"))))[:15]
        out += self.table([t("report.col.ext"), t("report.col.count"), t("report.col.size")],
                          [(Md(str(code(e.get("ext") or t("report.no_ext")))), fmt_num(e.get("count")),
                            fmt_size(e.get("size"))) for e in exts], right=(1, 2))
        out += [self.H(3, "5.3", "bigfiles"), ""]
        tops = sorted([f for f in l_(res.get("top_files")) if isinstance(f, dict)],
                      key=lambda f: (-float(f.get("size") or 0), str(f.get("path"))))[:15]
        out += self.table([t("report.col.path"), t("report.col.size"), t("report.col.category")],
                          [(Md(str(code(f.get("path"), 90))), fmt_size(f.get("size")), self.category_label(f.get("category")))
                           for f in tops], right=(1,))
        out += [self.H(3, "5.4", "archives"), ""]
        arcs = sorted([a for a in l_(res.get("archives")) if isinstance(a, dict)], key=lambda a: str(a.get("path")))
        out += self.table([t("report.col.path"), t("report.col.size"), t("report.col.magic"), t("report.col.category")],
                          [(Md(str(code(a.get("path"), 90))), fmt_size(a.get("size")), a.get("magic"),
                            self.category_label(a.get("category"))) for a in arcs], right=(1,))
        out += [self.H(3, "5.5", "locales"), ""]
        locs = sorted(str(x) for x in l_(res.get("localizations")))
        out += self.para(esc(", ".join(locs), nl=" ")) if locs else [t("report.none"), ""]
        return out

    # --- 6. libraries ------------------------------------------------------------------------------
    def _purpose(self, item: Mapping[str, Any]) -> str:
        first, second = ("purpose_zh", "purpose_en") if self.lang == "zh" else ("purpose_en", "purpose_zh")
        return str(item.get(first) or item.get(second) or "")

    def s6_libs(self) -> List[str]:
        t, r = self.t, self.r
        items = [i for i in l_(r.get("libraries")) if isinstance(i, dict)]
        out = [self.H(2, "6", "libs"), ""]
        gate, ran = self.gate("libs")
        out += gate
        if not ran and not items:
            return out
        groups: Dict[str, List[Mapping[str, Any]]] = {}
        for it in items:
            groups.setdefault(str(it.get("category") or "other"), []).append(it)
        out += [self.H(3, "6.1", "libs_known"), ""]
        out += self.para(esc(t("report.libs.total", n=len(items), cats=len(groups)), nl=" "))
        hdr = [t("report.col.name"), t("report.col.kind"), t("report.col.vendor"), t("report.col.category"),
               t("report.col.purpose"), t("report.col.confidence"), t("report.col.evidence")]
        for cid in sorted(groups, key=lambda c: (c == "other", self.libcat_label(c).lower(), c)):
            members = sorted(groups[cid], key=lambda i: (str(i.get("name") or i.get("id")).lower(), str(i.get("id"))))
            out += ["#### %s (%d)" % (esc(self.libcat_label(cid), nl=" "), len(members)), ""]
            out += self.table(hdr, [(i.get("name") or i.get("id"), self.label("report.libkind.%s" % i.get("kind"),
                                                                              default=str(i.get("kind") or "-")),
                                     i.get("vendor"), self.libcat_label(cid),
                                     Md(esc(clip(self._purpose(i), 90))) if self._purpose(i) else "—",
                                     self.conf(i.get("confidence")), self.ev_cell(i.get("evidence"), 2))
                                    for i in members])
        sm_libs = self.sm.get("libs")
        tags = d_(d_(sm_libs).get("privacy_tags"))
        shown = [(k, v) for k, v in sorted(tags.items()) if v]
        if shown:
            out += self.para(esc(t("report.libs.privacy_tags") + "; ".join("%s: %s" % (k, ", ".join(map(str, v)))
                                                                           for k, v in shown), nl=" "))
        out += [self.H(3, "6.2", "libs_unknown"), ""]
        if sm_libs is None:
            out += [t("report.libs.unknown_unavailable"), ""]
        else:
            unk = [u for u in l_(sm_libs.get("unknown")) if isinstance(u, dict)]
            out += self.para(esc(t("report.libs.unknown_note"), nl=" "))
            out += self.table([t("report.col.name"), t("report.col.kind"), t("report.col.hint"), t("report.col.evidence")],
                              [(u.get("name"), self.label("report.libkind.%s" % u.get("kind"), default=str(u.get("kind") or "-")),
                                u.get("hint"), self.ev_cell(u.get("evidence"), 2))
                               for u in sorted(unk, key=lambda u: str(u.get("name")).lower())])
        return out

    # --- 7. protection -----------------------------------------------------------------------------
    def s7_protect(self) -> List[str]:
        t, r = self.t, self.r
        out = [self.H(2, "7", "protect"), ""]
        gate, ran = self.gate("protect")
        out += gate
        pf = [f for f in l_(g(r, "protection", "findings", default=[])) if isinstance(f, dict)]
        order = {fid: i for i, fid in enumerate(PROTECTION_ORDER)}
        pf.sort(key=lambda f: (order.get(str(f.get("id")), 99), str(f.get("id")), str(f.get("title"))))
        prot = d_(r.get("protection"))
        if not pf and not ran and not any(k != "findings" for k in prot):
            return out
        out += self.para(esc(t("report.protect.note"), nl=" "))
        out += [self.H(3, "7.1", "protect_items"), ""]
        out += self.finding_table(pf) if pf else [t("report.none"), ""]
        out += self.finding_details(pf)
        fp = d_(prot.get("fairplay"))
        if fp:
            out += [self.H(3, "7.2", "fairplay"), ""]
            out += self.kv([(t("report.col.verdict"), self.badge(fp.get("verdict"), "protect.fairplay")),
                            (t("report.fp.scope"), t("report.scope." + str(fp.get("scope")), str(fp.get("scope")))
                             if fp.get("scope") else None),
                            (t("report.fp.encrypted"), "%s / %s" % (len(l_(fp.get("encrypted_binaries"))),
                                                                  self.fv(fp.get("total_binaries")))),
                            (t("report.fp.main"), fp.get("main_encrypted")), ("SC_Info", fp.get("sc_info_present"))])
            enc = [str(x) for x in l_(fp.get("encrypted_binaries"))]
            if enc:
                out += self.bullets([code(x, 100, pipe=False) for x in enc], limit=12)
        cs = d_(prot.get("codesign"))
        if cs:
            out += [self.H(3, "7.3", "codesign"), ""]
            out += self.kv([(t("report.cs.signed"), cs.get("signed")), ("Team ID", cs.get("team_id")),
                            (t("report.cs.type"), cs.get("signature_type")), ("get-task-allow", cs.get("get_task_allow")),
                            ("entitlements", cs.get("entitlements_keys"))])
        hd = d_(prot.get("hardening"))
        if hd:
            out += [self.H(3, "7.4", "hardening"), ""]
            rows = [(t("report.hard.main" if k == "main" else "report.hard.all"),
                     d_(hd.get(k)).get("pie"), d_(hd.get(k)).get("stack_canary"), d_(hd.get(k)).get("arc"),
                     d_(hd.get(k)).get("stripped")) for k in ("main", "all") if hd.get(k)]
            out += self.table([t("report.col.scope"), "PIE", t("report.hard.canary"), "ARC", t("report.macho.col_stripped")], rows)
        hits = []
        for key in ("antidebug", "jailbreak_detect"):
            for h in l_(d_(prot.get(key)).get("hits")):
                if isinstance(h, dict):
                    hits.append((t("report.prot.protect." + key), h.get("kind"), Md(str(code(h.get("ref"), 80)))))
        if hits:
            out += [self.H(3, "7.5", "hits"), ""]
            out += self.para(esc(t("report.protect.hits_note"), nl=" "))
            out += self.table([t("report.col.item"), t("report.col.kind"), t("report.col.ref")], hits)
        return out

    # --- 8. engines --------------------------------------------------------------------------------
    def s8_engine(self) -> List[str]:
        out = [self.H(2, "8", "engine"), ""]
        out += self.s8_1()
        out += self.s8_2()
        out += self.s8_3()
        return out

    def _hit_name(self, h: Mapping[str, Any]) -> str:
        return "%s (%.2f)" % (h.get("name") or h.get("id"), float(h.get("confidence") or 0))

    def s8_1(self) -> List[str]:
        t, r = self.t, self.r
        det, fpd = d_(g(r, "engine_details", "detect")), d_(g(r, "engine_details", "fingerprint"))
        cust = d_(det.get("custom"))
        is_custom = cust.get("verdict") in ("yes", "suspected")
        out = [self.H(3, "8.1", "engine_id"), ""]
        if is_custom:
            out += self._custom_block(cust, det)
        # identification
        out += ["**%s**" % esc(t("report.eng.detect_title"), nl=" "), ""]
        gate, ran = self.gate("engine.detect")
        out += gate
        if ran:
            prim = d_(det.get("primary"))
            if prim:
                out += self.kv([(t("report.eng.primary"), "%s (%s)" % (prim.get("name") or prim.get("id"), prim.get("id"))),
                                (t("report.eng.family"), prim.get("family")), (t("report.col.kind"), prim.get("kind")),
                                (t("report.col.confidence"), self.conf(prim.get("confidence"))),
                                (t("report.eng.confirmed"), prim.get("confirmed")),
                                (t("report.eng.signals"), prim.get("signals_matched")),
                                (t("report.eng.is_game"), det.get("is_game_engine"))])
                evs = [e for e in l_(prim.get("evidence")) if isinstance(e, dict)]
                if evs:
                    out += self.table([t("report.col.kind"), t("report.col.ref"), t("report.col.detail")],
                                      [(e.get("kind"), Md(str(code(e.get("ref"), 80))), clip(e.get("detail"), 100)) for e in evs[:8]])
            else:
                out += self.para(esc(t("report.eng.no_primary"), nl=" "))
            cands = [c for c in l_(det.get("candidates")) if isinstance(c, dict)]
            if cands:
                out += ["**%s**" % esc(t("report.eng.candidates"), nl=" "), ""]
                out += self.table([t("report.col.id"), t("report.col.name"), t("report.eng.family"), t("report.col.kind"),
                                   t("report.col.confidence"), t("report.eng.confirmed")],
                                  [(c.get("id"), c.get("name"), c.get("family"), c.get("kind"), self.conf(c.get("confidence")),
                                    c.get("confirmed")) for c in sorted(cands, key=lambda c: (-float(c.get("confidence") or 0), str(c.get("id"))))])
            wr = d_(det.get("wrapper"))
            if wr:
                rows = []
                if wr.get("host"):
                    rows.append((t("report.eng.host"), self._hit_name(d_(wr["host"]))))
                for e in l_(wr.get("embedded")):
                    if isinstance(e, dict):
                        rows.append((t("report.eng.embedded"), self._hit_name(e)))
                out += ["**%s**" % esc(t("report.eng.wrapper"), nl=" "), ""]
                out += self.table([t("report.col.role"), t("report.col.name")], rows)
            fnd = [f for f in self.findings if f.get("id") in ("engine.primary", "engine.language", "engine.wrapper")]
            if fnd:
                out += self.finding_table(fnd)
        # fingerprint profile
        out += ["**%s**" % esc(t("report.eng.profile_title"), nl=" "), ""]
        gate, ran = self.gate("engine.fingerprint")
        out += gate
        if ran:
            rows = []
            rend = d_(fpd.get("render"))
            dims = [("render", [dict(v, id=v.get("id") or k) for k, v in sorted(rend.items()) if isinstance(v, dict)])]
            for dim in ("shader_formats", "script_vms", "physics", "audio", "animation", "network", "asset_formats", "containers"):
                dims.append((dim, [h for h in l_(fpd.get(dim)) if isinstance(h, dict)]))
            for dim, hits in dims:
                names = [self._hit_name(h) if dim != "containers" else str(h.get("id")) for h in hits]
                evs = [e for h in hits for e in l_(h.get("evidence"))]
                rows.append((t("report.dim." + dim), ", ".join(names) if names else t("report.eng.not_found"),
                             self.ev_cell(evs, 2) if names else "—"))
            host = d_(fpd.get("host"))
            rows.append((t("report.dim.host"), self._host_text(host), "—"))
            out += self.table([t("report.col.dimension"), t("report.col.detected"), t("report.col.evidence")], rows)
            if fpd.get("summary_text"):
                out += self.quote(Md("%s %s" % (esc(t("report.eng.summary_raw"), nl=" "), esc(clip(fpd["summary_text"], 400), nl=" "))))
            conts = [h for h in l_(fpd.get("containers")) if isinstance(h, dict)]
            if conts:
                out += ["**%s**" % esc(t("report.eng.containers"), nl=" "), ""]
                out += self.para(esc(t("report.eng.containers_note"), nl=" "))
                crow = []
                for h in conts:
                    x = d_(h.get("extra"))
                    crow.append((Md(str(code(h.get("id"), 70))), fmt_size(x.get("size")), x.get("magic"),
                                 t("report.container." + str(x.get("verdict")), str(x.get("verdict")))
                                 if x.get("verdict") else None, x.get("compression"),
                                 x.get("entropy"), x.get("xor_hypothesis")))
                out += self.table([t("report.col.path"), t("report.col.size"), t("report.col.magic"), t("report.col.verdict"),
                                   t("report.eng.compression"), t("report.eng.entropy"), t("report.eng.xor")], crow, right=(1,))
            fnd = [f for f in self.findings if f.get("id") in ("engine.fingerprint", "engine.container.unknown")]
            if fnd:
                out += self.finding_table(fnd)
        if not is_custom and cust:
            out += self._custom_block(cust, det)
        return out

    def _host_text(self, host: Mapping[str, Any]) -> str:
        t = self.t
        if not host:
            return t("report.eng.not_found")
        parts = []
        if host.get("thin_uikit_shell") is not None:
            parts.append(t("report.eng.thin_shell") + "=" + self.fv(host.get("thin_uikit_shell")))
        if host.get("cpp_ratio") is not None:
            parts.append("C++ %.0f%%" % (float(host["cpp_ratio"]) * 100))
        if host.get("objc_swift_ratio") is not None:
            parts.append("ObjC/Swift %.0f%%" % (float(host["objc_swift_ratio"]) * 100))
        if host.get("main_loop_hints"):
            parts.append(", ".join(map(str, host["main_loop_hints"])))
        return "; ".join(parts) if parts else t("report.eng.not_found")

    def _custom_block(self, cust: Mapping[str, Any], det: Mapping[str, Any]) -> List[str]:
        t = self.t
        v = str(cust.get("verdict"))
        out: List[str] = []
        if v in ("yes", "suspected"):
            out += self.quote(Md("**%s** %s" % (esc(t("report.custom.callout_title"), nl=" "),
                                                esc(t("report.custom.callout_here", verdict=t("report.verdict." + v),
                                                      conf=self.conf(cust.get("confidence"))), nl=" "))))
        out += ["**%s**" % esc(t("report.custom.title"), nl=" "), ""]
        out += self.para(esc(t("report.custom.disclaimer"), nl=" "))
        out += self.kv([(t("report.col.verdict"), self.badge(v, "engine.custom", risk=False)),
                        (t("report.col.confidence"), self.conf(cust.get("confidence"))),
                        (t("report.custom.open_source_base"), cust.get("open_source_base")),
                        (t("report.custom.deviations"), cust.get("deviations"))])
        cond = self.flatten(cust.get("conditions"))
        if cond:
            out += ["**%s**" % esc(t("report.custom.conditions"), nl=" "), ""]
            out += self.kv(cond, headers=(t("report.col.item"), t("report.col.value")))
        evs = [e for e in l_(cust.get("evidence")) if isinstance(e, dict)]
        if evs:
            out += self.table([t("report.col.kind"), t("report.col.ref"), t("report.col.detail")],
                              [(e.get("kind"), Md(str(code(e.get("ref"), 80))), clip(e.get("detail"), 140)) for e in evs[:10]])
        steps = [s for s in l_(cust.get("next_steps")) if isinstance(s, dict)]
        if steps:
            out += ["**%s**" % esc(t("report.custom.next_steps"), nl=" "), ""]
            for i, s in enumerate(steps[:10], 1):
                text = s.get("text") or ""
                key = s.get("key")
                if key and self.cat.has(str(key), any_lang=True):
                    text = self.cat.t(str(key), text, **{k: v for k, v in d_(s.get("params")).items()
                                                         if k not in ("key", "default")})
                out.append("%d. %s" % (i, esc(clip(text, 300), nl=" ")))
            out.append("")
        fnd = [f for f in self.findings if f.get("id") == "engine.custom"]
        if fnd:
            out += self.finding_table(fnd)
            out += self.finding_details(fnd)
        return out

    # --- 8.2 unity ---------------------------------------------------------------------------------
    def s8_2(self) -> List[str]:
        t, r = self.t, self.r
        u = d_(g(r, "engine_details", "unity"))
        out = [self.H(3, "8.2", "unity"), ""]
        gate, ran = self.gate("engine.unity")
        out += gate
        if not ran:
            out += self.s8_2_1(u)
            return out
        ver, binary, meta = d_(u.get("version")), d_(u.get("binary")), d_(u.get("metadata"))
        out += self.kv([
            (t("report.unity.version"), ver.get("value") or t("report.unity.version_unknown")),
            (t("report.unity.backend"), u.get("backend")),
            (t("report.unity.binary"), Md(str(code(binary.get("path"), 80))) if binary.get("path") else None),
            (t("report.unity.slice"), binary.get("slice")),
            (t("report.unity.binary_encrypted"), binary.get("encrypted")),
            (t("report.unity.precheck"), self._precheck_text(d_(u.get("precheck"))) if u.get("precheck") else None),
        ])
        srcs = [s for s in l_(ver.get("sources")) if isinstance(s, dict)]
        if srcs:
            out += self.table([t("report.col.source"), t("report.col.value"), t("report.col.ref")],
                              [(s.get("source"), s.get("value"), Md(str(code(s.get("ref"), 70)))) for s in srcs])
        if ver.get("conflicts"):
            out += self.para(esc(t("report.unity.version_conflicts"), nl=" "))
            out += self.bullets([self.fv(c) for c in l_(ver.get("conflicts"))], limit=8)
        # metadata
        out += ["**%s**" % esc(t("report.unity.metadata_title"), nl=" "), ""]
        if meta:
            sr = d_(meta.get("string_region"))
            out += self.kv([
                ("path", Md(str(code(meta.get("path"), 80))) if meta.get("path") else None),
                (t("report.unity.present"), meta.get("present")), (t("report.unity.meta_version"), meta.get("version")),
                (t("report.unity.header_ok"), meta.get("header_ok")), (t("report.eng.entropy"), meta.get("entropy")),
                (t("report.unity.string_ok"), meta.get("string_region_ok")),
                (t("report.unity.string_region"), "offset=%s size=%s" % (sr.get("offset"), sr.get("size")) if sr else None),
                (t("report.col.verdict"), self.badge(meta.get("verdict") or "unknown", "unity.metadata.encrypted")),
            ])
            evs = [e for e in l_(meta.get("evidence")) if isinstance(e, dict)]
            if evs:
                out += self.table([t("report.col.kind"), t("report.col.ref"), t("report.col.detail")],
                                  [(e.get("kind"), Md(str(code(e.get("ref"), 80))), clip(e.get("detail"), 120)) for e in evs[:8]])
        else:
            out += [t("report.none"), ""]
        # bundles
        out += ["**%s**" % esc(t("report.unity.bundles_title"), nl=" "), ""]
        b = d_(u.get("bundles"))
        if b:
            out += self.kv([(t("report.unity.bundles_total"), b.get("total")), (t("report.unity.bundles_sampled"), b.get("sampled")),
                            ("Addressables", d_(b.get("addressables")).get("catalog_found")),
                            (t("report.unity.unity_versions"), b.get("unity_versions")),
                            (t("report.unity.compression"), b.get("compression"))])
            by = d_(b.get("by_class"))
            total = sum(int(v or 0) for v in by.values()) or 1
            samples = d_(b.get("samples"))
            out += self.table([t("report.col.category"), t("report.col.count"), t("report.col.percent"), t("report.col.samples")],
                              [(t("report.bundle_class." + k, k), by[k], "%.1f%%" % (int(by[k] or 0) / total * 100.0),
                                Md("; ".join(str(code(x, 50)) for x in l_(samples.get(k))[:3]) or "—"))
                               for k in sorted(by)], right=(1, 2))
            if b.get("paths_sample_file"):
                out += self.para(esc(t("report.unity.paths_in_file", file=b["paths_sample_file"], n=b.get("paths_sample_total")), nl=" "))
        else:
            out += [t("report.unity.no_bundles"), ""]
        bf = [f for f in self.findings if f.get("id") == "unity.assetbundle.encryption"]
        if bf:
            out += self.finding_table(bf)
        # mono
        mono = d_(u.get("mono"))
        if mono and (mono.get("assemblies") or u.get("backend") == "mono"):
            out += ["**%s**" % esc(t("report.unity.mono_title"), nl=" "), ""]
            out += self.kv([(t("report.col.verdict"), self.badge(mono.get("verdict") or "unknown", "unity.mono.dll_encrypted"))])
            out += self.table([t("report.col.path"), t("report.unity.valid_pe")],
                              [(Md(str(code(a.get("path"), 80))), a.get("valid_pe_cli")) for a in l_(mono.get("assemblies"))
                               if isinstance(a, dict)])
        # dump
        out += ["**%s**" % esc(t("report.unity.dump_title"), nl=" "), ""]
        out += self._dump_block(u)
        uf = [f for f in self.findings if str(f.get("id", "")).startswith("unity.") and not str(f.get("id")).startswith("unity.hotfix.")
              and f.get("id") != "unity.assetbundle.encryption"]
        if uf:
            out += ["**%s**" % esc(t("report.unity.findings"), nl=" "), ""]
            out += self.finding_table(uf)
            out += self.finding_details(uf, skip_protection=True)
        out += self.s8_2_1(u)
        return out

    def _precheck_text(self, pre: Mapping[str, Any]) -> str:
        t = self.t
        txt = t("report.unity.ready") if pre.get("ready") else t("report.unity.not_ready")
        if pre.get("error_code"):
            txt += " (%s)" % pre["error_code"]
        if pre.get("reasons"):
            txt += ": " + "; ".join(map(str, pre["reasons"]))
        return txt

    def _dump_block(self, u: Mapping[str, Any]) -> List[str]:
        t = self.t
        ds = dump_state(self.r)
        dump = d_(u.get("dump"))
        out = self.kv([(t("report.unity.dump_state"), t("report.dump." + ds["state"], error=ds.get("error_code") or "-",
                                                         reasons="; ".join(ds.get("reasons") or []) or "-")),
                       (t("report.unity.dump_backend"), ("%s %s" % (dump.get("backend"), dump.get("backend_version") or "")).strip()
                        if dump.get("backend") else None),
                       (t("report.unity.dump_duration"), "%.1f s" % float(dump["duration_s"]) if dump.get("duration_s") else None),
                       (t("report.unity.dump_cached"), dump.get("cached")),
                       (t("report.unity.dump_out"), Md(str(code(dump.get("out_dir")))) if dump.get("out_dir") else None),
                       (t("report.unity.dump_error"), dump.get("error_code")),
                       (t("report.unity.dump_remediation"), clip(dump.get("remediation"), 200) if dump.get("remediation") else None)])
        arts = d_(dump.get("artifacts"))
        if arts:
            out += self.table([t("report.col.name"), t("report.col.path")],
                              [(k, Md(str(code(v)))) for k, v in sorted(arts.items())])
        sm = d_(dump.get("summary"))
        if sm:
            counts = [(k, sm.get(k)) for k in ("assemblies", "classes", "interfaces", "enums", "methods", "fields", "string_literals")
                      if sm.get(k) is not None]
            if counts:
                out += self.table([t("report.col.item"), t("report.col.count")], [(t("report.dumpsum." + k), fmt_num(v)) for k, v in counts],
                                  right=(1,))
            if sm.get("framework_namespaces"):
                out += self.para(esc(t("report.unity.fw_namespaces") + ", ".join(map(str, sm["framework_namespaces"][:30])), nl=" "))
            ob = d_(sm.get("obfuscation"))
            if ob:
                out += self.kv([(t("report.unity.obf_score"), ob.get("score")), (t("report.unity.obf_nonstd"), ob.get("non_standard_ratio")),
                                (t("report.unity.obf_short"), ob.get("short_ratio")), (t("report.unity.obf_nonascii"), ob.get("non_ascii_ratio"))])
        ns = l_(dump.get("namespaces"))
        if ns or dump.get("namespaces_file"):
            total = dump.get("namespaces_total") or len(ns)
            line = t("report.unity.namespaces", n=total)
            if dump.get("namespaces_file"):
                line += " " + t("report.unity.paths_in_file", file=dump["namespaces_file"], n=total)
            out += self.para(esc(line, nl=" "))
        return out

    # --- 8.2.1 hotfix ------------------------------------------------------------------------------
    def _lua_lines(self, lua: Mapping[str, Any]) -> List[str]:
        t = self.t
        out: List[str] = []
        bc = d_(lua.get("bytecode"))
        by = d_(bc.get("by_version"))
        out += ["**%s**" % esc(t("report.lua.title"), nl=" "), ""]
        if by:
            out += self.table([t("report.lua.bc_version"), t("report.col.files")], [(k, by[k]) for k in sorted(by)], right=(1,))
        rv = [x for x in l_(lua.get("runtime_versions")) if isinstance(x, dict)]
        cons = d_(lua.get("consistency"))
        arch = d_(bc.get("arch_bits"))
        files = d_(lua.get("files"))
        rows = [
            (t("report.lua.runtime"), "; ".join("%s %s (%s, %.2f)" % (x.get("flavor"), x.get("version"), x.get("source"),
                                                                        float(x.get("confidence") or 0)) for x in rv) if rv else None),
            (t("report.lua.arch"), "; ".join("%s-bit: %s" % (k, arch[k]) for k in sorted(arch)) if arch else None),
            (t("report.lua.stripped"), bc.get("stripped_count")),
            (t("report.lua.invalid"), bc.get("invalid")),
            (t("report.lua.files"), "; ".join("%s=%s" % (t("report.fmt." + k, k), files[k]) for k in
                                              ("plain", "bytecode", "compressed", "encrypted_suspected", "total") if k in files) or None),
            (t("report.lua.consistency"), (t("report.lua.consistent") if cons.get("ok") else t("report.lua.inconsistent"))
             if cons else None),
            (t("report.lua.consistency_notes"), cons.get("notes")),
            (t("report.lua.custom"), self.badge("suspected" if lua.get("custom_lua_suspected") else "no", "unity.hotfix.script_protection")
             if "custom_lua_suspected" in lua else None),
            (t("report.lua.dialect"), lua.get("dialect_hints")),
        ]
        out += self.kv(rows)
        if cons and not cons.get("ok"):
            out += self.quote(Md("**%s** %s" % (esc(t("report.lua.warn_title"), nl=" "), esc(t("report.lua.warn"), nl=" "))))
        return out

    @staticmethod
    def _looks_like_lua(d: Any) -> bool:
        return isinstance(d, dict) and bool({"runtime_versions", "bytecode", "consistency", "custom_lua_suspected"} & set(d))

    def s8_2_1(self, unity: Mapping[str, Any]) -> List[str]:
        t, r = self.t, self.r
        out = [self.H(4, "8.2.1", "hotfix"), ""]
        gate, ran = self.gate("engine.unity.hotfix")
        out += gate
        if not ran:
            return out
        h = d_(unity.get("hotfix")) if unity else d_(g(r, "engine_details", "unity", "hotfix"))
        fw = [f for f in l_(h.get("frameworks")) if isinstance(f, dict)]
        out += ["**%s**" % esc(t("report.hot.frameworks"), nl=" "), ""]
        if fw:
            out += self.table([t("report.col.name"), t("report.col.kind"), t("report.col.confidence"), t("report.hot.version_hint"),
                               t("report.col.evidence")],
                              [(f.get("name") or f.get("id"), t("report.hotkind." + str(f.get("kind")), str(f.get("kind"))),
                                self.conf(f.get("confidence")), f.get("version_hint"), self.ev_cell(f.get("evidence"), 2))
                               for f in sorted(fw, key=lambda f: (str(f.get("kind")), -float(f.get("confidence") or 0), str(f.get("id"))))])
        else:
            out += [t("report.hot.none"), ""]
        # storage + format stats
        st, lua, js = d_(h.get("storage")), d_(h.get("lua")), d_(h.get("js"))
        cs = [a for a in l_(d_(h.get("csharp")).get("assemblies")) if isinstance(a, dict)]
        if st:
            sc = d_(st.get("scanned"))
            samp = "%s / %s" % (self.fv(sc.get("bundles_sampled")), self.fv(sc.get("total"))) if sc else None
            if sc and sc.get("total"):
                samp += " (%.0f%%)" % (float(sc.get("bundles_sampled") or 0) / float(sc["total"]) * 100.0)
            out += ["**%s**" % esc(t("report.hot.storage"), nl=" "), ""]
            out += self.kv([(t("report.hot.loose"), st.get("loose")), (t("report.hot.in_bundles"), st.get("in_bundles")),
                            (t("report.hot.in_serialized"), st.get("in_serialized")), (t("report.hot.sampled"), samp)])
        lf, jf = d_(lua.get("files")), d_(js.get("files"))
        fmt_rows = []
        if lf:
            fmt_rows.append(("Lua", lf.get("plain"), lf.get("bytecode"), lf.get("compressed"), lf.get("encrypted_suspected"), lf.get("total")))
        if jf and jf.get("total"):
            fmt_rows.append(("JS", jf.get("plain"), jf.get("bytecode"), jf.get("compressed"), jf.get("encrypted_suspected"), jf.get("total")))
        if cs:
            fm = {}
            for a in cs:
                fm[str(a.get("format"))] = fm.get(str(a.get("format")), 0) + 1
            fmt_rows.append(("C#", fm.get("pe_cli", 0), None, fm.get("compressed", 0), fm.get("encrypted_suspected", 0), len(cs)))
        if fmt_rows:
            out += ["**%s**" % esc(t("report.hot.formats"), nl=" "), ""]
            out += self.table([t("report.col.type"), t("report.fmt.plain"), t("report.fmt.bytecode"), t("report.fmt.compressed"),
                               t("report.fmt.encrypted_suspected"), t("report.fmt.total")], fmt_rows, right=(1, 2, 3, 4, 5))
        if lua:
            out += self._lua_lines(lua)
        if cs:
            out += ["**%s**" % esc(t("report.hot.csharp"), nl=" "), ""]
            out += self.table([t("report.col.name"), t("report.col.source"), t("report.col.size"), t("report.col.format"), "CLR",
                               t("report.col.kind"), t("report.hot.asm_refs")],
                              [(a.get("name"), t("report.hotsrc." + str(a.get("source")), str(a.get("source"))), fmt_size(a.get("size")),
                                t("report.csfmt." + str(a.get("format")), str(a.get("format"))), a.get("clr"),
                                t("report.cskind." + str(a.get("kind")), str(a.get("kind"))),
                                Md(esc(", ".join(map(str, l_(a.get("asm_refs"))[:5])) + (" ..." if len(l_(a.get("asm_refs"))) > 5 else "") or "—")))
                               for a in sorted(cs, key=lambda a: (str(a.get("kind")), str(a.get("name"))))], right=(2,))
        if js and (js.get("backends") or js.get("formats") or jf.get("total")):
            out += ["**%s**" % esc(t("report.hot.js"), nl=" "), ""]
            out += self.kv([(t("report.hot.js_backends"), [("%s (%.2f)" % (b.get("id"), float(b.get("confidence") or 0)))
                                                           for b in l_(js.get("backends")) if isinstance(b, dict)]),
                            (t("report.hot.js_formats"), js.get("formats"))])
        ru = d_(h.get("resource_update"))
        if ru:
            out += ["**%s**" % esc(t("report.hot.resource"), nl=" "), ""]
            rfw = [x.get("name") or x.get("id") if isinstance(x, dict) else x for x in l_(ru.get("frameworks"))]
            out += self.kv([(t("report.hot.res_frameworks"), rfw), (t("report.hot.res_catalogs"), ru.get("catalogs")),
                            (t("report.hot.res_manifests"), ru.get("manifests")), (t("report.hot.res_hosts"), ru.get("hosts"))])
        sp = d_(h.get("script_protection"))
        out += ["**%s**" % esc(t("report.hot.protection"), nl=" "), ""]
        if sp:
            out += self.table([t("report.col.type"), t("report.col.verdict")],
                              [(n, self.badge(sp.get(k) or "unknown", "unity.hotfix.script_protection"))
                               for k, n in (("lua", "Lua"), ("js", "JS"), ("csharp", "C#")) if k in sp])
        out += self.para(esc(t("report.hot.protection_note"), nl=" "))
        if h.get("summary_text"):
            out += self.quote(Md("%s %s" % (esc(t("report.eng.summary_raw"), nl=" "), esc(clip(h["summary_text"], 400), nl=" "))))
        hf = [f for f in self.findings if str(f.get("id", "")).startswith("unity.hotfix.")]
        if hf:
            out += self.finding_table(hf)
            out += self.finding_details(hf, skip_protection=True)
        return out

    # --- 8.3 other engines -------------------------------------------------------------------------
    def s8_3(self) -> List[str]:
        t, r = self.t, self.r
        ed = d_(r.get("engine_details"))
        out = [self.H(3, "8.3", "other"), ""]
        gate, ran = self.gate("engine.other")
        out += gate
        if not ran:
            return out
        engines = sorted(k for k in ed if k not in ("fingerprint", "detect", "unity", "_checkers") and isinstance(ed[k], dict))
        checkers = d_(ed.get("_checkers"))
        if not engines:
            out += self.para(esc(t("report.other.none"), nl=" "))
        for i, eid in enumerate(engines, 1):
            data = ed[eid]
            out += ["#### 8.3.%d %s" % (i, esc(self.engine_name(eid), nl=" ")), ""]
            out += self._engine_data(eid, data)
            fnd = [f for f in self.findings if ("engine:%s" % eid) in (f.get("tags") or [])]
            if fnd:
                out += self.finding_table(fnd)
                out += self.finding_details(fnd, skip_protection=True)
        if checkers:
            out += ["#### 8.3.%d %s" % (len(engines) + 1, esc(t("report.other.checkers"), nl=" ")), ""]
            out += self.table([t("report.col.id"), t("report.col.status"), t("report.col.reason"), t("report.col.duration")],
                              [(k, t("report.status." + str(d_(v).get("status")), str(d_(v).get("status"))),
                                clip(d_(v).get("reason") or d_(v).get("error"), 100) or None, "%.2fs" % float(d_(v).get("duration_s") or 0))
                               for k, v in sorted(checkers.items())])
        return out

    def _engine_data(self, eid: str, data: Mapping[str, Any]) -> List[str]:
        t = self.t
        out: List[str] = []
        skip = set()
        if eid == "cocos":
            out += self.kv([(t("report.cocos.variant"), data.get("variant")), (t("report.cocos.version_hint"), data.get("version_hint"))])
            skip |= {"variant", "version_hint"}
            sc = d_(data.get("scripts"))
            if sc:
                out += ["**%s**" % esc(t("report.cocos.scripts"), nl=" "), ""]
                out += self.table([t("report.fmt.plain"), t("report.fmt.bytecode"), t("report.fmt.encrypted_suspected")],
                                  [(sc.get("plain"), sc.get("bytecode"), sc.get("suspected_encrypted"))], right=(0, 1, 2))
                rest = self.flatten({k: v for k, v in sc.items() if k not in ("plain", "bytecode", "suspected_encrypted", "samples", "lua", "js")})
                if rest:
                    out += self.kv(rest)
                samples = [Md(str(code(x, 90, pipe=False))) for x in l_(sc.get("samples"))]
                if samples:
                    out += self.para(esc(t("report.cocos.samples"), nl=" "))
                    out += self.bullets(samples, limit=6)
                for key in ("lua", "js"):
                    if self._looks_like_lua(sc.get(key)):
                        out += self._lua_lines(sc[key])
                skip.add("scripts")
            res = self.flatten(data.get("resources"))
            if res:
                out += ["**%s**" % esc(t("report.cocos.resources"), nl=" "), ""]
                out += self.kv(res)
                skip.add("resources")
            xx = self.flatten(data.get("xxtea_hint"))
            if xx:
                out += ["**%s**" % esc(t("report.cocos.xxtea"), nl=" "), ""]
                out += self.para(esc(t("report.cocos.xxtea_note"), nl=" "))
                out += self.kv(xx)
                skip.add("xxtea_hint")
            bundles = [b for b in l_(data.get("bundles")) if isinstance(b, dict)]
            if bundles:
                out += ["**%s**" % esc(t("report.cocos.bundles"), nl=" "), ""]
                cols = sorted({k for b in bundles for k, v in b.items() if not isinstance(v, (dict, list))})[:6]
                out += self.table(cols, [[b.get(c) for c in cols] for b in bundles])
                skip.add("bundles")
        elif self._looks_like_lua(data):
            out += self._lua_lines(data)
            skip |= {"runtime_versions", "bytecode", "consistency", "custom_lua_suspected", "files", "dialect_hints"}
        rows = self.flatten(data, skip=skip)
        if rows:
            out += self.kv(rows)
        elif not out:
            out += [t("report.none"), ""]
        return out

    # --- 9. privacy --------------------------------------------------------------------------------
    def _perm_text(self, p: Mapping[str, Any]) -> Any:
        loc = d_(p.get("localized"))
        order = (["zh-Hans", "zh-Hant", "zh", "zh_CN", "zh-CN", "en", "Base"] if self.lang == "zh" else ["en", "Base", "zh-Hans"])
        for k in order:
            if loc.get(k):
                return loc[k]
        return p.get("description") or (next(iter(loc.values())) if loc else None)

    def s9_privacy(self) -> List[str]:
        t, r = self.t, self.r
        pv = d_(r.get("privacy"))
        out = [self.H(2, "9", "privacy"), ""]
        gate, ran = self.gate("meta")
        out += gate
        perms = [p for p in l_(pv.get("permissions")) if isinstance(p, dict)]
        lvl = {"high": 0, "medium": 1, "low": 2}
        if ran or perms:
            out += [self.H(3, "9.1", "permissions"), ""]
            out += self.table([t("report.col.key"), t("report.col.meaning"), t("report.col.level"), t("report.priv.declared")],
                              [(Md(str(code(p.get("key"), 60))), p.get("meaning_zh") if self.lang == "zh" else p.get("meaning_en"),
                                t("report.level." + str(p.get("level")), str(p.get("level"))) if p.get("level") else None,
                                clip(self._perm_text(p), 100) if self._perm_text(p) else None)
                               for p in sorted(perms, key=lambda p: (lvl.get(str(p.get("level")), 3), str(p.get("key"))))])
            out += [self.H(3, "9.2", "schemes"), ""]
            out += self.kv([(t("report.priv.url_schemes"), sorted(map(str, l_(pv.get("url_schemes"))))),
                            (t("report.priv.query_schemes"), sorted(map(str, l_(pv.get("query_schemes")))))])
            ats = d_(pv.get("ats"))
            out += [self.H(3, "9.3", "ats"), ""]
            out += self.kv([(t("report.priv.ats_arbitrary"), ats.get("allows_arbitrary_loads")),
                            (t("report.priv.ats_domains"), sorted(map(str, l_(ats.get("exception_domains")))))])
        tr = [x for x in l_(pv.get("trackers")) if isinstance(x, dict)]
        out += [self.H(3, "9.4", "trackers"), ""]
        gate2, ran2 = self.gate("libs")
        out += gate2
        if ran2 or tr:
            out += self.table([t("report.col.id"), t("report.col.name"), t("report.col.tags")],
                              [(x.get("id"), x.get("name"), x.get("tags")) for x in sorted(tr, key=lambda x: str(x.get("id")))])
        return out

    # --- 10. appendix --------------------------------------------------------------------------------
    def s10_appendix(self) -> List[str]:
        t, r = self.t, self.r
        out = [self.H(2, "10", "appendix"), ""]
        out += [self.H(3, "10.1", "stages"), ""]
        rows = []
        names = list(self.stages) if self.stages else []
        names.sort(key=lambda n: ([i for i, x in enumerate(_STAGE_POS) if x == n] or [99])[0])
        for n in names:
            s = self.stages[n]
            note = self.note(n)
            raw = s.get("reason") or s.get("error")
            rows.append((Md(str(code(n))), t("report.badge.status." + str(s.get("status")), str(s.get("status"))),
                         "%.2fs" % float(s.get("duration_s") or 0), note.text or "—", note.hint or "—",
                         Md(str(code(clip(raw, 60)))) if raw else "—"))
        out += self.table([t("report.col.stage"), t("report.col.status"), t("report.col.duration"), t("report.col.explanation"),
                           t("report.col.advice"), t("report.col.raw")], rows, right=(2,))
        out += [self.H(3, "10.2", "warnings"), ""]
        warns = [str(w) for w in l_(r.get("warnings"))]
        out += self.bullets([clip(w, 300) for w in warns], limit=60) if warns else [t("report.none"), ""]
        out += [self.H(3, "10.3", "tools"), ""]
        red = d_(r.get("redaction"))
        cfg = d_(r.get("config"))
        dump = d_(g(r, "engine_details", "unity", "dump"))
        arts = d_(r.get("artifacts"))
        out += self.kv([
            (t("report.tools.tool"), "%s %s" % (g(r, "tool", "name", default=""), g(r, "tool", "version", default=""))),
            (t("report.tools.schema"), r.get("schema_version")),
            (t("report.tools.redaction"), "%s%s" % (t("report.yes") if red.get("applied") else t("report.no"),
                                                    (" (%s)" % ", ".join("%s=%s" % (k, v) for k, v in sorted(d_(red.get("counts")).items())))
                                                    if red.get("counts") else "")),
            (t("report.tools.config"), "; ".join("%s=%s" % (k, self.fv(cfg.get(k))) for k in ("lang", "formats", "offline", "redact",
                                                                                          "signature_integrity") if k in cfg)),
            (t("report.tools.il2cpp"), self.fv(d_(cfg.get("il2cpp")).get("enabled")) if cfg.get("il2cpp") else None),
            (t("report.tools.dumper"), ("%s %s" % (dump.get("backend"), dump.get("backend_version") or "")).strip() if dump.get("backend") else None),
            (t("report.tools.artifacts"), Md(", ".join(str(code(v)) for _, v in sorted(arts.items())) or "—")),
        ])
        out += [self.H(3, "10.4", "limits"), ""]
        lim = self.cat.raw("report.limits", [])
        out += self.bullets([str(x) for x in lim] if isinstance(lim, list) else [])
        out += [self.H(3, "10.5", "heuristics"), ""]
        fl = findings_of(r)
        n_susp = sum(1 for f in fl if f.get("verdict") == "suspected")
        n_unk = sum(1 for f in fl if f.get("verdict") == "unknown")
        n_heur = sum(1 for f in fl for e in l_(f.get("evidence")) if isinstance(e, dict) and e.get("kind") == "heuristic")
        out += self.para(esc(t("report.heur.stats", n=len(fl), susp=n_susp, unk=n_unk, heur=n_heur), nl=" "))
        hl = self.cat.raw("report.heur.points", [])
        out += self.bullets([str(x) for x in hl] if isinstance(hl, list) else [])
        return out


_STAGE_POS = ("ingest", "inventory", "meta", "macho", "engine.fingerprint", "engine.detect", "engine.other",
              "engine.unity", "engine.unity.hotfix", "libs", "protect", "classify", "report")


def render_markdown(report: Mapping[str, Any], catalog: Catalog, *, summary: Optional[Mapping[str, Any]] = None) -> str:
    """Render the report dict to Markdown text (LF line endings, trailing newline).

    Chapters: 1 summary, 2 basic info, 3 project type, 4 structure, 5 resources, 6 libraries,
    7 encryption & protection, 8 engines (8.1 identification & profile, 8.2 Unity with 8.2.1 hot update,
    8.3 other engines), 9 privacy, 10 appendix.
    """
    return _R(report, catalog, summary).render()
