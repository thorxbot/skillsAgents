"""Single-file HTML report: a converter for the Markdown subset produced by ``render_md`` plus inline CSS/JS.

No external resources (no CDN, fonts, images). Light / dark follows ``prefers-color-scheme``; each
top-level chapter is a collapsible ``<details>``; tables sort by clicking a header. All text is
HTML-escaped; the only markup comes from the converter itself.
"""
from __future__ import annotations

import html
import re
from typing import Any, List, Mapping, Optional

from .i18n import Catalog
from .render_md import split_row

__all__ = ["render_html", "markdown_to_html"]

_CODE_RE = re.compile(r"(?<!`)(`+)(?!`)(.+?)(?<!`)\1(?!`)")
_ESC_RE = re.compile(r"\\([\\`*_{}\[\]()#+\-.!|<>~])")
_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
_EM_RE = re.compile(r"\*(?!\s)(.+?)(?<!\s)\*")
_SEP_RE = re.compile(r"^\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$")
_BR = ""
_PH0 = 0xE100


def _inline_text(s: str) -> str:
    """Escape / format one non-code text segment."""
    stash: List[str] = []

    def keep(m: "re.Match[str]") -> str:
        stash.append(m.group(1))
        return chr(_PH0 + len(stash) - 1)

    s = s.replace("<br>", _BR)
    s = _ESC_RE.sub(keep, s)
    s = html.escape(s, quote=False)
    s = _BOLD_RE.sub(r"<strong>\1</strong>", s)
    s = _EM_RE.sub(r"<em>\1</em>", s)
    s = s.replace(_BR, "<br>")
    return "".join(html.escape(stash[ord(ch) - _PH0], quote=False) if _PH0 <= ord(ch) < _PH0 + len(stash) else ch
                   for ch in s)


def _inline(s: str) -> str:
    out, pos = [], 0
    for m in _CODE_RE.finditer(s):
        out.append(_inline_text(s[pos:m.start()]))
        body = m.group(2).replace("\\|", "|")
        if body.startswith(" ") and body.endswith(" ") and body.strip():
            body = body[1:-1]
        out.append("<code>%s</code>" % html.escape(body, quote=False))
        pos = m.end()
    out.append(_inline_text(s[pos:]))
    return "".join(out)


def _table(lines: List[str]) -> str:
    head = split_row(lines[0])
    aligns = []
    for c in split_row(lines[1]):
        aligns.append("right" if c.endswith(":") and not c.startswith(":") else "")
    parts = ['<div class="tw"><table class="sortable"><thead><tr>']
    for i, h in enumerate(head):
        parts.append("<th%s>%s</th>" % (' class="r"' if i < len(aligns) and aligns[i] else "", _inline(h)))
    parts.append("</tr></thead><tbody>")
    for ln in lines[2:]:
        cells = split_row(ln)
        cells += [""] * (len(head) - len(cells))
        parts.append("<tr>" + "".join('<td%s>%s</td>' % (' class="r"' if i < len(aligns) and aligns[i] else "", _inline(c))
                                      for i, c in enumerate(cells[:len(head)])) + "</tr>")
    parts.append("</tbody></table></div>")
    return "".join(parts)


def _list(lines: List[str]) -> str:
    """Nested ``-`` / ``1.`` lists (indent = 2 spaces per level)."""
    out: List[str] = []
    stack: List[tuple] = []     # (indent, tag)
    for ln in lines:
        m = re.match(r"^(\s*)(-|\d+\.)\s+(.*)$", ln)
        if not m:
            continue
        indent, marker, text = len(m.group(1)), m.group(2), m.group(3)
        tag = "ol" if marker[0].isdigit() else "ul"
        while stack and indent < stack[-1][0]:
            out.append("</li></%s>" % stack.pop()[1])
        if stack and indent == stack[-1][0]:
            out.append("</li>")
        elif not stack or indent > stack[-1][0]:
            out.append("<%s>" % tag)
            stack.append((indent, tag))
        out.append("<li>%s" % _inline(text))
    while stack:
        out.append("</li></%s>" % stack.pop()[1])
    return "".join(out)


def markdown_to_html(md: str) -> str:
    """Convert the Markdown subset used by the report to an HTML fragment (chapters become ``<details>``)."""
    lines = md.split("\n")
    out: List[str] = []
    open_sec = False
    i = 0
    n = len(lines)
    while i < n:
        ln = lines[i]
        if ln.startswith("```"):
            j = i + 1
            while j < n and not lines[j].startswith("```"):
                j += 1
            out.append("<pre><code>%s</code></pre>" % html.escape("\n".join(lines[i + 1:j]), quote=False))
            i = j + 1
            continue
        m = re.match(r"^(#{1,6})\s+(.*)$", ln)
        if m:
            level = len(m.group(1))
            if level == 2:
                if open_sec:
                    out.append("</details>")
                out.append('<details open class="sec"><summary><h2>%s</h2></summary>' % _inline(m.group(2)))
                open_sec = True
            else:
                out.append("<h%d>%s</h%d>" % (level, _inline(m.group(2)), level))
            i += 1
            continue
        if ln.startswith("|") and i + 1 < n and _SEP_RE.match(lines[i + 1]):
            j = i + 2
            while j < n and lines[j].startswith("|"):
                j += 1
            out.append(_table(lines[i:j]))
            i = j
            continue
        if ln.startswith(">"):
            j = i
            buf = []
            while j < n and lines[j].startswith(">"):
                buf.append(lines[j][1:].strip())
                j += 1
            out.append("<blockquote>%s</blockquote>" % _inline(" ".join(buf)))
            i = j
            continue
        if re.match(r"^\s*(-|\d+\.)\s+", ln):
            j = i
            while j < n and (re.match(r"^\s*(-|\d+\.)\s+", lines[j]) or (lines[j].startswith("  ") and lines[j].strip())):
                j += 1
            out.append(_list(lines[i:j]))
            i = j
            continue
        if ln.strip():
            j = i
            buf = []
            while j < n and lines[j].strip() and not re.match(r"^(#{1,6}\s|\||>|```|\s*(-|\d+\.)\s)", lines[j]):
                buf.append(lines[j])
                j += 1
            out.append("<p>%s</p>" % _inline(" ".join(buf)))
            i = max(j, i + 1)
            continue
        i += 1
    if open_sec:
        out.append("</details>")
    return "\n".join(out)


_CSS = """
:root{--bg:#fff;--fg:#1d2330;--mut:#5b6577;--line:#d9deea;--card:#f5f7fb;--acc:#2456d6;--warn:#fff4e0;--warnb:#e0a030}
@media (prefers-color-scheme:dark){:root{--bg:#12151c;--fg:#e4e8f1;--mut:#9aa5b8;--line:#2c3446;--card:#1a1f2b;--acc:#7aa2ff;--warn:#2b2414;--warnb:#a97d1d}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 -apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
main{max-width:1180px;margin:0 auto;padding:20px 16px 60px}h1{font-size:1.6rem;margin:.3em 0}h2{display:inline;font-size:1.25rem}
h3{font-size:1.08rem;margin:1.2em 0 .4em}h4{font-size:1rem;margin:1em 0 .3em;color:var(--mut)}
details.sec{border:1px solid var(--line);border-radius:8px;margin:14px 0;padding:0 14px 10px;background:var(--card)}
details.sec>summary{cursor:pointer;padding:10px 0;list-style:none;font-weight:600}details.sec>summary::-webkit-details-marker{display:none}
details.sec>summary::before{content:"\\25B8  ";color:var(--acc)}details.sec[open]>summary::before{content:"\\25BE  "}
.tw{overflow-x:auto;margin:.5em 0}table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{border:1px solid var(--line);padding:5px 9px;text-align:left;vertical-align:top;word-break:break-word}
th{background:var(--bg);position:sticky;top:0;cursor:pointer;user-select:none;white-space:nowrap}th.r,td.r{text-align:right}
th.asc::after{content:" \\25B2";font-size:.7em}th.desc::after{content:" \\25BC";font-size:.7em}
code{font:.86em ui-monospace,Menlo,Consolas,monospace;background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:0 4px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:10px;overflow-x:auto}pre code{border:0;padding:0}
blockquote{margin:.6em 0;padding:.5em .9em;border-left:4px solid var(--warnb);background:var(--warn);border-radius:0 6px 6px 0}
.bar{position:sticky;top:0;z-index:2;background:var(--bg);padding:6px 0;border-bottom:1px solid var(--line);display:flex;gap:8px}
button{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:3px 10px;cursor:pointer}
"""

_JS = """
(function(){
  var q=function(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s))};
  function num(t){var m=String(t).replace(/,/g,'').match(/^\\s*(-?\\d+(?:\\.\\d+)?)\\s*(B|KB|MB|GB|TB|%|s)?/i);
    if(!m)return null;var v=parseFloat(m[1]),u=(m[2]||'').toUpperCase(),k={B:0,KB:1,MB:2,GB:3,TB:4}[u];
    return k===undefined?v:v*Math.pow(1024,k)}
  q('table.sortable').forEach(function(tb){
    q('th',tb).forEach(function(th,i){
      th.addEventListener('click',function(){
        var asc=!th.classList.contains('asc');
        q('th',tb).forEach(function(x){x.classList.remove('asc','desc')});
        th.classList.add(asc?'asc':'desc');
        var body=tb.tBodies[0],rows=q('tr',body);
        rows.sort(function(a,b){
          var x=a.cells[i]?a.cells[i].textContent:'',y=b.cells[i]?b.cells[i].textContent:'';
          var nx=num(x),ny=num(y),c;
          if(nx!==null&&ny!==null)c=nx-ny;else c=x.localeCompare(y,undefined,{numeric:true});
          return asc?c:-c});
        rows.forEach(function(r){body.appendChild(r)})})})});
  q('[data-act]').forEach(function(b){b.addEventListener('click',function(){
    var open=b.getAttribute('data-act')==='open';q('details.sec').forEach(function(d){d.open=open})})});
})();
"""


def render_html(markdown_text: str, catalog: Optional[Catalog] = None, *, title: Optional[str] = None) -> str:
    """Wrap the converted Markdown in a self-contained HTML page."""
    lang = catalog.lang if catalog else "en"
    t = catalog.t if catalog else (lambda key, default="", **kw: default or key)
    if title is None:
        m = re.search(r"^#\s+(.*)$", markdown_text, re.MULTILINE)
        title = re.sub(r"\\(.)", r"\1", m.group(1)) if m else "ipa-analyzer report"
    body = markdown_to_html(markdown_text)
    bar = ('<div class="bar"><button type="button" data-act="open">%s</button>'
           '<button type="button" data-act="close">%s</button></div>'
           % (html.escape(t("report.html.expand_all", "Expand all")), html.escape(t("report.html.collapse_all", "Collapse all"))))
    return ("<!doctype html>\n<html lang=\"%s\">\n<head>\n<meta charset=\"utf-8\">\n"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
            "<title>%s</title>\n<style>%s</style>\n</head>\n<body>\n<main>\n%s\n%s\n</main>\n<script>%s</script>\n</body>\n</html>\n"
            % (html.escape(lang), html.escape(title, quote=False), _CSS, bar, body, _JS))
