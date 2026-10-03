"""HTML report: self-contained, collapsible chapters, sortable tables, escaping."""
from __future__ import annotations

import re

import pytest

from fixtures.sample_report import make_catalog, render
from ipa_analyzer.report import markdown_to_html, render_html

_JS_LINES_MAX = 150


@pytest.fixture()
def page(fixture_name, lang):
    return render_html(render(fixture_name, lang), make_catalog(lang))


def test_page_is_self_contained(page):
    assert page.startswith("<!doctype html>")
    assert not re.search(r"<(script|link|img|iframe)[^>]+(src|href)=", page, re.I)
    assert "@import" not in page and "url(" not in page
    assert not re.search(r"https?://", page)
    assert page.count("<script>") == 1 and page.count("<style>") == 1


def test_chapters_are_collapsible_and_tables_sortable(page):
    assert page.count('<details open class="sec">') == 10
    assert page.count("</details>") == 10
    assert 'class="sortable"' in page
    assert "prefers-color-scheme:dark" in page
    js = page.split("<script>")[1].split("</script>")[0]
    assert len([ln for ln in js.split("\n") if ln.strip()]) < _JS_LINES_MAX


def test_html_is_well_balanced(page):
    for tag in ("table", "thead", "tbody", "tr", "details", "blockquote", "ul", "pre", "div"):
        assert len(re.findall(r"<%s[ >]" % tag, page)) == page.count("</%s>" % tag), tag
    rows = re.findall(r"<tr>(.*?)</tr>", page, re.S)
    assert rows


def test_table_cells_match_header_counts(page):
    for tbl in re.findall(r"<table.*?</table>", page, re.S):
        head = len(re.findall(r"<th[ >]", tbl))
        for tr in re.findall(r"<tbody>(.*?)</tbody>", tbl, re.S)[0].split("</tr>")[:-1]:
            assert len(re.findall(r"<td[ >]", tr)) == head


def test_content_is_escaped():
    md = ("# T <b>x</b>\n\n## 1. S\n\n| a | b |\n| --- | ---: |\n| `<i>` | \\<script>alert(1)\\</script> \\| pipe |\n\n"
          "- item & more\n  - nested **bold**\n\n> quote <img src=x>\n\n```text\n<tag>\n```\n")
    out = markdown_to_html(md)
    assert "<script>" not in out and "<img" not in out and "<i>" not in out
    assert "&lt;script&gt;" in out and "&lt;i&gt;" in out and "&amp; more" in out
    assert "<strong>bold</strong>" in out and "<td class=\"r\">" in out
    assert "<ul><li>item &amp; more<ul><li>nested" in out
    assert "| pipe" in out                       # escaped pipe restored
    assert "<pre><code>&lt;tag&gt;" in out


def test_title_and_lang_attributes():
    md = "# My App \\| x\n\n## 1. A\n\ntext\n"
    out = render_html(md, make_catalog("en"))
    assert "<title>My App | x</title>" in out and '<html lang="en">' in out
    assert 'lang="zh"' in render_html(md, make_catalog("zh"))


def test_empty_and_odd_markdown_do_not_crash():
    for md in ("", "\n\n", "no heading", "| a |\n| --- |", "```\nunterminated"):
        render_html(md)
