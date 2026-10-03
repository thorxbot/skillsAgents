"""Markdown renderer: chapters, not-run notices, leak-free text, table integrity, escaping."""
from __future__ import annotations

import copy
import re

import pytest

from fixtures.sample_report import (CHAPTERS, LEAK_PATTERN, SUBSECTIONS, assert_tables_consistent, make_catalog, render,
                                    report_dict)
from ipa_analyzer.report import render_markdown
from ipa_analyzer.report.render_md import Md, code, esc, fmt_size, split_row

LEAK_RE = re.compile(LEAK_PATTERN)


def chapter(md, n):
    """Text of chapter ``n`` (``## n.``) up to the next chapter."""
    body = md.split("\n## %d. " % n)[1]
    return body.split("\n## %d. " % (n + 1))[0] if n < 10 else body


def section(md, start, end=None):
    body = md.split(start, 1)[1]
    return body.split(end, 1)[0] if end else body


def test_all_chapters_present_for_every_fixture_and_language(fixture_name, lang):
    md = render(fixture_name, lang)
    for h in CHAPTERS + SUBSECTIONS:
        assert re.search(r"^%s" % re.escape(h), md, re.MULTILINE), (fixture_name, lang, h)
    # fixed chapter order
    pos = [md.index("\n" + h) for h in CHAPTERS]
    assert pos == sorted(pos)
    assert md.endswith("\n") and "\r" not in md and "\n\n\n" not in md


def test_no_leaked_python_values_and_consistent_tables(fixture_name, lang):
    md = render(fixture_name, lang)
    assert not LEAK_RE.findall(md), LEAK_RE.findall(md)
    assert assert_tables_consistent(md) >= 3


def test_executive_summary_is_short(fixture_name, lang):
    md = render(fixture_name, lang)
    block = chapter(md, 1)
    rows = [ln for ln in block.split("\n") if ln.startswith("|")]
    assert 2 + 11 <= len(rows) <= 2 + 15


def test_skipped_and_failed_stages_are_visible_with_reason(lang):
    md = render("custom_engine", lang)
    not_run = "未执行" if lang == "zh" else "Not run"
    assert md.count(not_run) >= 4
    assert "struct.error" in md and "KeyError" in md          # failed stages: error shown
    assert ("已通过 --skip 禁用" if lang == "zh" else "disabled with --skip") in md
    appendix = md.split("### 10.1")[1].split("### 10.2")[0]
    for stage in ("meta", "macho", "protect", "engine.other", "engine.unity", "libs"):
        assert "`%s`" % stage in appendix
    assert "disabled by --skip" in appendix                   # raw record kept next to the explanation


def test_unity_stages_on_non_unity_package_fold_to_a_plain_message(lang):
    want = "不是 Unity 应用,已跳过" if lang == "zh" else "not a Unity app, skipped"
    for name in ("custom_engine", "cocos_lua"):
        md = render(name, lang)
        hot = section(md, "#### 8.2.1", "\n### 8.3 ")
        assert want in hot and "dependency" not in hot
        assert want in section(md, "\n### 8.2 ", "#### 8.2.1")


def test_dependency_chain_is_collapsed_to_the_root_cause(lang):
    md = render("ingest_only", lang)
    hot = section(md, "#### 8.2.1", "\n### 8.3 ")
    assert "inventory" in hot and "dependency" not in hot
    assert "OSError" in hot                                       # root failure reason surfaced
    # hotfix would otherwise read "dependency engine.unity skipped"
    assert "engine.unity skipped" not in hot


def test_missing_stage_without_record_says_so():
    rd = report_dict("full_success")
    rd["stages"] = [s for s in rd["stages"] if s["name"] != "libs"]
    md = render_markdown(rd, make_catalog("zh"), summary=rd["summary"])
    assert "未执行:无此阶段的运行记录" in chapter(md, 6)


def test_custom_engine_gets_a_prominent_callout(lang):
    md = render("custom_engine", lang)
    sec81 = section(md, "\n### 8.1 ", "\n### 8.2 ")
    assert sec81.split("\n", 1)[1].lstrip().startswith(">")                         # callout is the first thing in 8.1
    assert "NeoX" not in md and "网易" not in md                  # no vendor assertions
    assert ("不构成对引擎归属或厂商的断言" if lang == "zh" else "not an assertion about who built the engine") in sec81
    assert md.index("Inspect res/data0.npk") < md.index(("**识别结果**" if lang == "zh" else "**Identification**"))
    summary = chapter(md, 1)
    assert ("见 8.1" in summary) or ("see 8.1" in summary)
    assert "疑似自研" in summary or "in-house" in summary


def test_known_engine_has_no_custom_callout():
    md = render("full_success", "zh")
    assert "注意:疑似自研引擎" not in md


def test_engine_profile_table_has_all_dimensions(lang):
    md = render("full_success", lang)
    prof = section(md, "\n### 8.1 ", "\n### 8.2 ")
    for dim in ("render", "shader_formats", "script_vms", "physics", "audio", "animation", "network", "asset_formats", "containers", "host"):
        assert make_catalog(lang).t("report.dim." + dim) in prof


def test_hotfix_section_contents(lang):
    md = render("full_success", lang)
    hot = section(md, "#### 8.2.1", "\n### 8.3 ")
    for needle in ("ToLua", "HybridCLR", "Addressables", "luajit_2.1", "cdn.example.com", "HotUpdate", "mscorlib", "v4.0.30319",
                   "64-bit", "puc 5.1"):
        assert needle in hot, needle
    t = make_catalog(lang).t
    assert t("report.lua.warn_title") in hot                       # consistency warning
    assert t("report.hot.protection_note")[:12] in hot


def test_unity_dump_and_bundle_tables(lang):
    md = render("full_success", lang)
    unity = section(md, "\n### 8.2 ", "#### 8.2.1")
    for needle in ("2021.3.21f1", "il2cpp", "Il2CppDumper 6.7.40", "il2cpp/dump.cs", "4,200", "details/unity-bundle-paths.json".replace("details/", "")):
        assert needle in unity or needle == "unity-bundle-paths.json"


def test_cocos_section_reuses_lua_profile(lang):
    md = render("cocos_lua", lang)
    sec = section(md, "\n### 8.3 ", "\n## 9. ")
    assert "cocos2d-x-lua" in sec and "180" in sec and "XXTEA" in sec
    assert make_catalog(lang).t("report.lua.title") in sec


def test_libs_grouped_and_unknown_separate(lang):
    md = render("full_success", lang)
    libs = chapter(md, 6)
    assert "AppLovinSDK" in libs and "libmystery.dylib" in libs
    known, unknown = libs.split("### 6.2")
    assert "libmystery" not in known and "AppLovinSDK" not in unknown
    assert "libX\\|Y" in libs                                    # pipe in a name is escaped


def test_pipes_backticks_and_newlines_in_cells():
    assert esc("a|b") == "a\\|b"
    assert esc("a`b") == "a\\`b"
    assert esc("line1\nline2") == "line1<br>line2"
    assert esc("x\r\ny") == "x<br>y"
    assert esc("*bold*") == "\\*bold\\*"
    assert esc("<redacted>") == "\\<redacted>"
    assert esc("1 < 2 > 0") == "1 < 2 > 0"
    assert esc("C:\\path\\*") == "C:\\path\\\\\\*"
    assert esc(None) == "" and esc("a\x00b\x07c") == "abc"
    assert code("a|b") == "`a\\|b`"
    assert code("a`b") == "``a`b``"
    assert code("`edge`") == "`` `edge` ``"
    assert code("") == "\u2014" and code(None) == "\u2014"
    assert code("x" * 100, maxlen=10).endswith("\u2026`")
    assert code("a|b", pipe=False) == "`a|b`"


def test_split_row_roundtrip_with_escaped_pipes_and_code():
    row = "| a\\|b | `x\\|y` | plain |"
    assert split_row(row) == ["a\\|b", "`x\\|y`", "plain"]
    assert split_row("| `` `q` `` | z |") == ["`` `q` ``", "z"]
    assert split_row("|  |") == [""]


def test_hostile_values_do_not_break_tables():
    rd = copy.deepcopy(report_dict("full_success"))
    rd["libraries"][0]["name"] = "evil|name\nwith `tick` <script>alert(1)</script> *x*"
    rd["libraries"][0]["purpose_zh"] = "用途|含\n换行"
    rd["app"]["selected_name"] = "A|B"
    md = render_markdown(rd, make_catalog("zh"), summary=rd["summary"])
    assert assert_tables_consistent(md) >= 3
    assert not re.search(r"(?<!\\)<script", md)


def test_render_is_deterministic_and_input_not_mutated():
    rd = report_dict("full_success")
    before = copy.deepcopy(rd)
    cat = make_catalog("zh")
    a = render_markdown(rd, cat, summary=rd["summary"])
    b = render_markdown(rd, cat, summary=rd["summary"])
    assert a == b and rd == before


def test_renders_even_from_an_empty_or_minimal_report():
    for rd in ({}, {"stages": []}, {"stages": [{"name": "ingest", "status": "ok", "duration_s": 0}], "findings": None}):
        md = render_markdown(rd, make_catalog("zh"))
        for h in CHAPTERS:
            assert h in md
        assert not LEAK_RE.findall(md)
        assert assert_tables_consistent(md) >= 1


def test_english_catalog_has_no_cjk_in_static_text():
    md = render("ingest_only", "en")
    assert not re.search(r"[\u4e00-\u9fff]", md)


def test_fmt_size():
    assert fmt_size(0) == "0 B" and fmt_size(1023) == "1023 B" and fmt_size(1024) == "1.0 KB"
    assert fmt_size(5 * 1024 ** 3) == "5.0 GB" and fmt_size(None) == "\u2014" and fmt_size("x") == "\u2014"


def test_bar_and_percent_columns_sum():
    md = render("full_success", "zh")
    sec = section(md, "### 5.1", "### 5.2")
    assert "\u2588" in sec and "%" in sec


def test_localized_finding_text_is_interpolated():
    md = render("full_success", "zh")
    assert "识别为 Unity 2021.3.21f1(来源:globalgamemanagers, unityfs_header)" in md
    md = render("full_success", "en")
    assert "Detected Unity 2021.3.21f1 (sources: globalgamemanagers, unityfs_header)" in md


def test_md_helper_type():
    assert isinstance(code("x"), Md)
