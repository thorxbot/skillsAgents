"""End-to-end invariants for every synthetic whole-package IPA, through the no-install CLI entry point.

DoD 1 (CLI produces ``report.md`` + ``report.json`` that pass the schema) and the F-RPT rules: all 13 stages are
listed, skipped / failed stages carry a reason that is visible in the Markdown report, chapters 1-10 exist.
"""
from __future__ import annotations

import json
import re

import pytest

from fixtures.full_ipa_builders import FIXTURES
from fixtures.e2e_support import BROKEN, GOOD, STAGE_ORDER

# exit codes (CONTRACT-FREEZE 8): 0 ok, 2 invalid input
EXPECTED_EXIT = {"broken_truncated": 2, "broken_not_zip": 2, "broken_no_payload": 2}
CHAPTERS = ["## %d. " % n for n in range(1, 11)]


def test_fixture_list_matches_the_work_package_prompt():
    required = {"unity_il2cpp_plain", "unity_il2cpp_encrypted_binary", "unity_il2cpp_meta_xor", "unity_mono",
                "native_swift_app", "unity_hybridclr", "unity_ilruntime", "unity_xlua_lua53", "unity_tolua_luajit",
                "unity_lua_mixed_versions", "unity_lua_tampered", "unity_puerts_quickjs", "unity_addressables_remote",
                "unity_hotdll_encrypted", "custom_engine", "cocos_cpp_lua_plain", "cocos_lua_xxtea", "cocos_js_jsc",
                "cocos_creator3", "egret_app", "laya_app", "flutter_app", "media_app"}
    assert required <= set(FIXTURES)
    assert {"broken_truncated", "broken_not_zip", "broken_no_payload", "broken_zipslip"} <= set(FIXTURES)


def test_fixtures_are_deterministic(tmp_path):
    from fixtures.full_ipa_builders import build_fixture

    for name in ("unity_il2cpp_plain", "custom_engine", "unity_xlua_lua53", "cocos_creator3_wrapped"):
        a = build_fixture(name, tmp_path / "a").read_bytes()
        b = build_fixture(name, tmp_path / "b").read_bytes()
        assert a == b, name


@pytest.mark.parametrize("name", GOOD)
def test_good_fixture_runs_clean(runs, check_report, name):
    r = runs.cli(name)
    assert r.returncode == EXPECTED_EXIT.get(name, 0), r.proc.stderr[-2000:]
    assert r.report is not None and r.md is not None
    assert check_report(r.report) == []
    assert [s["name"] for s in r.report["stages"]] == STAGE_ORDER
    assert not [s for s in r.report["stages"] if s["status"] == "failed"], r.report["stages"]
    # stage lines and the final report line are printed on stdout
    assert "report:" in r.proc.stdout and "stages:" in r.proc.stdout
    assert r.report["schema_version"] == "1.0" and r.report["input"]["sha256"]


@pytest.mark.parametrize("name", GOOD)
def test_markdown_has_all_chapters_and_summary(runs, name):
    md = runs.cli(name).md
    for chap in CHAPTERS:
        assert chap in md, (name, chap)
    assert "### 10.1" in md
    summary = md.split("## 2. ")[0]
    assert "执行摘要" in summary and summary.count("\n") <= 40         # F-RPT: the summary stays short


@pytest.mark.parametrize("name", GOOD + BROKEN)
def test_skipped_and_failed_stages_have_visible_reasons(runs, name):
    r = runs.cli(name)
    assert r.report is not None, (name, r.proc.stdout[-500:], r.proc.stderr[-500:])
    appendix = r.md.split("### 10.1", 1)[1].split("### 10.2", 1)[0]
    for st in r.report["stages"]:
        if st["status"] == "skipped":
            assert st.get("reason"), (name, st)
            assert st["reason"] in appendix, (name, st["name"], st["reason"])
        elif st["status"] == "failed":
            assert st.get("error"), (name, st)
            row = [ln for ln in appendix.splitlines() if "`%s`" % st["name"] in ln]
            assert row and "失败" in row[0], (name, st["name"])
        elif st["status"] == "partial":
            assert st.get("reason") or st.get("warnings"), (name, st)


@pytest.mark.parametrize("name", BROKEN)
def test_broken_inputs_never_crash(runs, check_report, name):
    r = runs.cli(name)
    assert r.returncode == EXPECTED_EXIT.get(name, 0), (name, r.proc.stderr[-1500:])
    assert "Traceback" not in r.proc.stderr and "Traceback" not in r.proc.stdout
    assert r.report is not None and check_report(r.report) == []
    assert [s["name"] for s in r.report["stages"]] == STAGE_ORDER
    if EXPECTED_EXIT.get(name):
        ing = r.stage("ingest")
        assert ing["status"] == "failed" and ing["error"].startswith("InvalidInput")
        assert r.stage("report")["status"] == "ok"                # the report is still written
        assert all(s["status"] in ("skipped", "ok", "partial") for s in r.report["stages"] if s["name"] != "ingest")
        assert "未成功阶段" in r.md                                  # and says what is missing


def test_zip_slip_entries_are_reported_and_never_written(runs, tmp_path):
    r = runs.cli("broken_zipslip", "--extract", "all")
    assert r.returncode == 0
    assert any("unsafe" in w for w in r.report["warnings"]), r.report["warnings"]
    out = r.out_base
    created = {p.name for p in out.parent.rglob("*") if p.is_file()}
    assert not ({"evil.txt", "evil2.txt", "evil3.txt", "evil4.txt"} & created)
    ipa_dir = runs.ipas["broken_zipslip"].parent
    assert not (ipa_dir.parent / "evil.txt").exists() and not (ipa_dir / "evil.txt").exists()
    assert not any(re.search(r"evil\d?\.txt", p.name) for p in runs.base.rglob("*"))


def test_report_json_is_valid_utf8_with_lf_endings(runs):
    for name in ("media_app", "unity_il2cpp_plain"):
        raw = runs.cli(name).report_path.read_bytes()
        assert b"\r" not in raw and raw.endswith(b"\n")
        raw.decode("utf-8")
        md = runs.cli(name).md_path.read_bytes()
        assert b"\r" not in md


def test_purchaser_fields_are_redacted_everywhere(runs):
    r = runs.cli("media_app")
    blob = r.report_path.read_text(encoding="utf-8") + r.md
    for secret in ("private-mail.example", "Secret Person Name"):
        assert secret not in blob
    assert r.report["redaction"]["applied"] is True and "apple-id" in r.report["redaction"]["fields"]
    # --no-redact is an explicit opt-out
    raw = runs.cli("media_app", "--no-redact")
    assert raw.returncode == 0 and "redaction" in raw.report
    assert raw.report["redaction"]["applied"] is False


def test_english_report_is_available(runs):
    r = runs.cli("custom_engine", "--lang", "en")
    assert r.returncode == 0 and r.md.splitlines()[0].startswith("# ") and "分析报告" not in r.md.splitlines()[0]
    assert "## 1." in r.md and "## 10." in r.md


def test_only_json_format_still_writes_json(runs):
    r = runs.cli("flutter_app", "--format", "json")
    assert r.returncode == 0 and r.report is not None and r.md is None


def test_unknown_stage_name_is_a_usage_error(runs):
    r = runs.cli("flutter_app", "--stages", "no.such.stage")
    assert r.returncode == 1 and r.report is None


def test_stage_selection_marks_the_rest_as_not_selected(runs):
    r = runs.cli("flutter_app", "--stages", "meta")
    assert r.returncode == 0
    by = {s["name"]: s for s in r.report["stages"]}
    assert by["meta"]["status"] == "ok" and by["ingest"]["status"] == "ok"
    assert by["libs"]["status"] == "skipped" and by["libs"]["reason"] == "not selected by --stages"
    assert by["report"]["status"] == "ok"
    skipped = r.report["stages"]
    assert all(s["reason"] for s in skipped if s["status"] == "skipped")
    assert json.loads(json.dumps(r.report)) == r.report
