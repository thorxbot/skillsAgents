"""i18n loader: merging, conflicts, fallbacks, interpolation, and coverage of the report.json catalog."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from ipa_analyzer.report.i18n import (Catalog, I18nConflictError, I18nError, load_catalog, render_template)
from ipa_analyzer.report.summary import PROTECTION_ORDER, RISK_FINDING_IDS

SRC = Path(__file__).resolve().parents[3] / "src" / "ipa_analyzer"
DATA = Path(__file__).resolve().parents[3] / "data" / "i18n"


def _write(base: Path, lang: str, name: str, data) -> None:
    d = base / "i18n" / lang
    d.mkdir(parents=True, exist_ok=True)
    (d / (name + ".json")).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def test_merges_files_of_one_language(tmp_path):
    _write(tmp_path, "zh", "a", {"a.one": "1", "meta.identity": {"title": "身份"}})
    _write(tmp_path, "zh", "b", {"b.two": "2"})
    _write(tmp_path, "en", "a", {"a.one": "one"})
    cat = load_catalog("zh", data_dir=tmp_path)
    assert cat.t("a.one") == "1" and cat.t("b.two") == "2"
    assert cat.t("missing.key") == "missing.key" and cat.t("missing.key", "dflt") == "dflt"
    assert cat.raw("meta.identity")["title"] == "身份"


def test_key_conflict_is_reported_with_both_files(tmp_path):
    _write(tmp_path, "zh", "alpha", {"shared.key": "x", "alpha.only": "1"})
    _write(tmp_path, "zh", "beta", {"shared.key": "y"})
    with pytest.raises(I18nConflictError) as exc:
        load_catalog("zh", data_dir=tmp_path)
    msg = str(exc.value)
    assert "shared.key" in msg and "alpha.json" in msg and "beta.json" in msg
    assert exc.value.conflicts == [("zh", "shared.key", "alpha.json", "beta.json")]


def test_key_conflict_warn_mode_keeps_first_and_warns(tmp_path):
    _write(tmp_path, "zh", "alpha", {"shared.key": "x"})
    _write(tmp_path, "zh", "beta", {"shared.key": "y"})
    cat = load_catalog("zh", data_dir=tmp_path, on_conflict="warn")
    assert cat.t("shared.key") == "x"
    assert any("shared.key" in w and "alpha.json" in w and "beta.json" in w for w in cat.warnings)


def test_same_key_in_different_languages_is_not_a_conflict(tmp_path):
    _write(tmp_path, "zh", "a", {"k": "中"})
    _write(tmp_path, "en", "b", {"k": "en"})
    assert load_catalog("zh", data_dir=tmp_path).t("k") == "中"


def test_bad_json_raises_or_warns(tmp_path):
    d = tmp_path / "i18n" / "zh"
    d.mkdir(parents=True)
    (d / "broken.json").write_text("{not json", encoding="utf-8")
    (d / "list.json").write_text("[1]", encoding="utf-8")
    with pytest.raises(I18nError):
        load_catalog("zh", data_dir=tmp_path)
    cat = load_catalog("zh", data_dir=tmp_path, on_conflict="warn")
    assert len([w for w in cat.warnings if "broken.json" in w or "list.json" in w]) == 2


def test_finding_text_fallback_chain_and_warning(tmp_path):
    _write(tmp_path, "zh", "x", {"a.b": {"title": "中文标题 {n}", "summary": "摘要 {n}"}})
    _write(tmp_path, "en", "x", {"a.c": {"title": "English C {n}", "remediation": "do {n}"}})
    cat = load_catalog("zh", data_dir=tmp_path)
    fb = {"id": "a.b", "title": "fallback", "summary": "s", "remediation": "r", "params": {"n": 3}}
    t = cat.finding_text(fb)
    assert (t.title, t.summary, t.remediation, t.localized) == ("中文标题 3", "摘要 3", "r", True)
    # no zh entry, English entry exists -> English text, flagged as not localised
    t = cat.finding_text({"id": "a.c", "title": "fb", "params": {"n": 1}})
    assert (t.title, t.remediation, t.localized) == ("English C 1", "do 1", False)
    # nowhere -> the Finding's own English text
    t = cat.finding_text({"id": "z.z", "title": "built-in", "summary": "sum {x}", "params": {"x": "y"}})
    assert (t.title, t.summary, t.localized) == ("built-in", "sum y", False)
    warns = cat.collect_warnings()
    assert len(warns) == 1 and "a.c" in warns[0] and "z.z" in warns[0] and "'zh'" in warns[0]


def test_english_catalog_never_warns_about_missing_findings(tmp_path):
    _write(tmp_path, "en", "x", {"x.y": "z"})
    cat = load_catalog("en", data_dir=tmp_path)
    cat.finding_text({"id": "q.q", "title": "t"})
    assert cat.collect_warnings() == []


@pytest.mark.parametrize("template,params,expected", [
    ("a {x} b", {"x": 1}, "a 1 b"),
    ("{x:.2f}", {"x": 0.12345}, "0.12"),
    ("{missing} stays", {}, "{missing} stays"),
    ("{x}", {"x": ["a", "b"]}, "a, b"),
    ("{x}", {"x": None}, "-"),
    ("{x}", {"x": {"k": 1}}, "k=1"),
    ("{{literal}} {x}", {"x": "v"}, "{literal} v"),
    ("{x:.2f} {y}", {"x": "text", "y": 2}, "text 2"),         # bad format spec -> graceful fallback
    ("{x.__class__}", {"x": "s"}, "{x.__class__}"),             # attribute access is refused
    ("{x[0]}", {"x": "s"}, "{x[0]}"),
    ("", {"x": 1}, ""),
])
def test_render_template(template, params, expected):
    assert render_template(template, params) == expected


def test_t_interpolates_only_when_needed():
    cat = Catalog.from_mapping("zh", {"zh": {"a": "x {n}", "b": "no {braces here"}, "en": {}})
    assert cat.t("a", n=3) == "x 3"
    assert cat.t("b") == "no {braces here"


# --- the real catalog ----------------------------------------------------------------------------------
def _keys(lang):
    return json.loads((DATA / lang / "report.json").read_text(encoding="utf-8"))


def test_zh_and_en_have_identical_key_sets():
    zh, en = _keys("zh"), _keys("en")
    assert set(zh) == set(en)
    assert all(k.startswith("report.") for k in zh)


def test_every_literal_key_used_in_source_exists():
    keys = set(_keys("zh"))
    missing = []
    files = list((SRC / "report").glob("*.py")) + [SRC / "analyzers" / "report_stage.py"]
    for f in files:
        for m in re.finditer(r'"(report\.[A-Za-z0-9_.]*[A-Za-z0-9_])"', f.read_text(encoding="utf-8")):
            if m.group(1) not in keys and m.group(1) not in ("report.json", "report.md", "report.html", "report.schema.json"):
                missing.append((f.name, m.group(1)))
    assert missing == []


def test_dynamic_key_families_are_complete():
    keys = set(_keys("zh"))
    need = []
    for v in ("yes", "no", "suspected", "unknown", "n/a", "na"):
        need.append("report.verdict." + v)
    for v in ("yes", "no", "suspected", "unknown", "na"):
        need += ["report.badge.risk." + v, "report.badge.info." + v]
    for s in ("ok", "partial", "skipped", "failed"):
        need += ["report.badge.status." + s, "report.status." + s]
    need += ["report.conf." + c for c in ("high", "medium", "low", "very_low")]
    need += ["report.category." + c for c in ("game", "media", "lifestyle", "social", "utility", "finance", "education",
                                               "health_fitness", "shopping", "travel", "news_reading", "other", "unknown")]
    need += ["report.dist." + c for c in ("appstore", "adhoc", "enterprise", "development", "unsigned_or_repackaged", "unknown")]
    need += ["report.scope." + c for c in ("all", "partial", "none", "unknown")]
    need += ["report.dump." + c for c in ("dumped", "failed", "ready", "blocked", "disabled", "not_unity", "unknown")]
    need += ["report.risk." + c for c in ("fairplay_encrypted", "metadata_encrypted", "assetbundle_encrypted", "script_protection",
                                          "resource_encrypted", "custom_engine", "unsigned_or_repackaged", "antidebug",
                                          "jailbreak_detect", "stage_failed", "unknown_libs", "trackers", "high_permissions")]
    need += ["report.lang." + c for c in ("objc", "swift", "c", "cpp", "csharp", "lua", "javascript", "typescript", "dart",
                                           "python", "java", "kotlin", "rust", "go")]
    need += ["report.prot." + i for i in PROTECTION_ORDER if i in RISK_FINDING_IDS and i not in ("protect.fairplay", "unity.binary.fairplay")]
    need += ["report.dim." + c for c in ("render", "shader_formats", "script_vms", "physics", "audio", "animation", "network",
                                          "asset_formats", "containers", "host")]
    need += ["report.bundle_class." + c for c in ("standard", "offset_prefix", "xor_simple", "high_entropy_unknown", "other", "unknown")]
    need += ["report.h." + c for c in ("summary", "basic", "type", "structure", "resources", "libs", "protect", "engine", "privacy", "appendix")]
    missing = [k for k in need if k not in keys]
    assert missing == []
    assert isinstance(_keys("zh")["report.limits"], list) and isinstance(_keys("en")["report.limits"], list)


def test_report_catalog_does_not_clash_with_other_modules():
    """Every module file may define its own keys only; ``report.*`` belongs to report.json (merged without conflicts)."""
    for lang in ("zh", "en"):
        cat = load_catalog(lang, on_conflict="raise")      # raises I18nConflictError on any clash
        assert cat.has("report.title", any_lang=True)
