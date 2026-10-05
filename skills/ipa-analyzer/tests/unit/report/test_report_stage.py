"""The ``report`` stage: files written, redaction, formats, failures, exit-code decision, CLI integration."""
from __future__ import annotations

import io
import json
import re
from pathlib import Path

import pytest

from fixtures.sample_report import EMAIL, FIXTURE_NAMES, UDID_NEW, UDID_OLD, build_ctx
from ipa_analyzer import cli
from ipa_analyzer.analyzers import report_stage
from ipa_analyzer.analyzers.report_stage import ReportStage
from ipa_analyzer.config import Config
from ipa_analyzer.context import AnalysisContext
from ipa_analyzer.models import Status

PERSONAL = ("alice", "bob", "carol", "dave", EMAIL, UDID_OLD, UDID_NEW)


def _run(name, tmp_path, **cfg):
    ctx = build_ctx(name, tmp_path, **cfg)
    res = ReportStage().run(ctx)
    return ctx, res


def _all_text(ctx):
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(ctx.out_dir.rglob("*")) if p.is_file() and p.suffix in (".json", ".md", ".html"))


def test_stage_registration_matches_contract():
    from ipa_analyzer.pipeline import ensure_analyzers_loaded

    spec = ensure_analyzers_loaded().get("report")
    assert spec.always_run and not spec.requires
    assert set(spec.after) == {"ingest", "inventory", "meta", "macho", "engine.fingerprint", "engine.detect", "engine.other",
                               "cocos.decrypt", "engine.unity", "engine.unity.hotfix", "libs", "protect", "classify"}


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_writes_all_requested_formats_and_registers_artifacts(name, tmp_path, capsys):
    ctx, res = _run(name, tmp_path, formats=("md", "json", "html"))
    assert res.status == Status.OK
    for f in ("report.json", "report.md", "report.html"):
        assert (ctx.out_dir / f).is_file() and ctx.artifacts[f] == f
    assert res.data["files"]["report.json"] == "report.json"
    assert res.data["formats"] == ["json", "md", "html"]
    assert (ctx.out_dir / "inventory.json").is_file() or name == "ingest_only"
    doc = json.loads((ctx.out_dir / "report.json").read_text(encoding="utf-8"))
    assert doc["artifacts"]["report.md"] == "report.md" and doc["artifacts"]["report.json"] == "report.json"
    assert res.data["validation"]["ok"] is True, res.data["validation"]
    printed = capsys.readouterr().out
    assert printed.startswith("==") and "FairPlay" in printed


def test_json_always_written_and_md_only_when_requested(tmp_path):
    ctx, res = _run("full_success", tmp_path, formats=("json",))
    assert (ctx.out_dir / "report.json").is_file()
    assert not (ctx.out_dir / "report.md").exists() and not (ctx.out_dir / "report.html").exists()
    assert res.data["formats"] == ["json"]


def test_large_tables_go_to_side_files(tmp_path):
    ctx, res = _run("full_success", tmp_path)
    side = ctx.out_dir / "details" / "unity-namespaces.json"
    assert side.is_file() and len(json.loads(side.read_text(encoding="utf-8"))) == 155
    doc = json.loads((ctx.out_dir / "report.json").read_text(encoding="utf-8"))
    assert doc["engine_details"]["unity"]["dump"]["namespaces_file"] == "details/unity-namespaces.json"
    assert "details/unity-namespaces.json" in res.data["files"]


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_default_run_leaves_no_personal_data_anywhere(name, tmp_path):
    ctx, res = _run(name, tmp_path, formats=("md", "json", "html"))
    text = _all_text(ctx)
    for needle in PERSONAL:
        assert needle not in text, needle
    doc = json.loads((ctx.out_dir / "report.json").read_text(encoding="utf-8"))
    assert doc["redaction"]["applied"] is True and doc["redaction"]["counts"]


def test_no_redact_keeps_original_values(tmp_path):
    ctx, res = _run("full_success", tmp_path, redact=False, formats=("md", "json"))
    text = _all_text(ctx)
    assert "/Users/alice/Downloads/DemoGame.ipa" in text and EMAIL in text
    doc = json.loads((ctx.out_dir / "report.json").read_text(encoding="utf-8"))
    assert doc["redaction"]["applied"] is True        # meta had already blanked purchaser fields itself
    assert doc["redaction"]["counts"] == {}
    ctx2, _ = _run("ingest_only", tmp_path / "x", redact=False)
    assert json.loads((ctx2.out_dir / "report.json").read_text(encoding="utf-8"))["redaction"]["applied"] is False


def test_output_is_reproducible_apart_from_time(tmp_path):
    docs = []
    for i in range(2):
        ctx, _ = _run("full_success", tmp_path / str(i), formats=("md", "json", "html"))
        md = (ctx.out_dir / "report.md").read_text(encoding="utf-8")
        js = (ctx.out_dir / "report.json").read_text(encoding="utf-8")
        stamp = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"     # generated_at has 1 s resolution: two runs may straddle a second
        md = re.sub(stamp, "T", re.sub(r"\d+\.\d+s", "0s", md))
        js = re.sub(r'"duration_s": [\d.]+', '"duration_s": 0', re.sub(stamp, "T", re.sub(r'"output_dir": "[^"]*"', "", js)))
        docs.append((md, js))
    assert docs[0] == docs[1]


def test_exit_code_decision_is_returned_not_executed(tmp_path):
    _, ok = _run("full_success", tmp_path / "a")
    assert ok.data["exit_code"] == 0 and ok.data["failed_stages"] == []
    _, bad = _run("custom_engine", tmp_path / "b")
    assert bad.data["exit_code"] == 3 and bad.data["failed_stages"] == ["meta", "macho", "protect"]
    # skipped / partial alone never raise it
    from ipa_analyzer.report import exit_code_for
    assert exit_code_for([{"status": "skipped"}, {"status": "partial"}]) == 0
    assert exit_code_for([{"status": "failed"}]) == 3


def test_stage_never_raises_when_everything_upstream_is_missing(tmp_path):
    ctx = AnalysisContext(Config(output_dir=tmp_path), tmp_path / "x.ipa")
    res = ReportStage().run(ctx)               # not even bound: the stage binds an output directory itself
    assert res.status == Status.OK
    doc = json.loads((ctx.out_dir / "report.json").read_text(encoding="utf-8"))
    assert doc["stages"][-1]["name"] == "report"
    assert (ctx.out_dir / "report.md").is_file()


def test_markdown_failure_degrades_to_partial_but_keeps_json(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("render exploded")

    monkeypatch.setattr(report_stage, "render_markdown", boom)
    ctx, res = _run("full_success", tmp_path, formats=("md", "json", "html"))
    assert res.status == Status.PARTIAL and "md" in res.reason
    assert (ctx.out_dir / "report.json").is_file() and not (ctx.out_dir / "report.md").exists()
    doc = json.loads((ctx.out_dir / "report.json").read_text(encoding="utf-8"))
    assert any("render exploded" in w for w in doc["warnings"])


def test_enrich_failure_is_a_warning(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise ValueError("bad enrich")

    monkeypatch.setattr(report_stage, "enrich_report", boom)
    ctx, res = _run("full_success", tmp_path)
    assert res.status == Status.OK and any("bad enrich" in w for w in res.warnings)
    assert (ctx.out_dir / "report.md").is_file()


def test_schema_problems_are_warnings_not_errors(tmp_path, monkeypatch):
    from ipa_analyzer.report.schema import ValidationOutcome

    monkeypatch.setattr(report_stage, "validate", lambda rd: ValidationOutcome(errors=["$: broken thing"], validator="builtin"))
    ctx, res = _run("full_success", tmp_path)
    assert res.status == Status.OK
    doc = json.loads((ctx.out_dir / "report.json").read_text(encoding="utf-8"))
    assert any("does not match the schema" in w and "broken thing" in w for w in doc["warnings"])


def test_missing_zh_texts_produce_one_aggregated_warning(tmp_path, monkeypatch):
    # use an empty data dir so no finding has a zh text
    from ipa_analyzer.report import i18n

    real = i18n.load_catalog
    data = tmp_path / "data"
    (data / "i18n" / "zh").mkdir(parents=True)
    (data / "i18n" / "zh" / "report.json").write_text(
        (Path(i18n.__file__).resolve().parents[3] / "data" / "i18n" / "zh" / "report.json").read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(report_stage, "load_catalog", lambda lang, **kw: real(lang, data_dir=data, **kw))
    ctx, res = _run("full_success", tmp_path / "out", lang="zh")
    msgs = [w for w in res.warnings if w.startswith("i18n:")]
    assert len(msgs) == 1 and "classify.category" in msgs[0] and "'zh'" in msgs[0]


def test_console_summary_survives_a_narrow_encoding(tmp_path, monkeypatch):
    class Ascii(io.TextIOWrapper):
        pass

    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="ascii", errors="strict")
    monkeypatch.setattr("sys.stdout", stream)
    ctx, res = _run("full_success", tmp_path)
    stream.flush()
    assert res.status == Status.OK and raw.getvalue()


def test_inventory_file_from_inventory_stage_is_not_overwritten(tmp_path):
    ctx = build_ctx("full_success", tmp_path)
    (ctx.out_dir / "inventory.json").write_text('{"files": ["full list"]}', encoding="utf-8")
    ReportStage().run(ctx)
    assert (ctx.out_dir / "inventory.json").read_text(encoding="utf-8") == '{"files": ["full list"]}'
    assert ctx.artifacts["inventory.json"] == "inventory.json"


def test_cli_with_only_the_report_stage(make_zip, tmp_path, capsys):
    zp = make_zip({"Payload/A.app/Info.plist": b"x"})
    out = tmp_path / "out"
    code = cli.main(["analyze", str(zp), "-o", str(out), "--stages", "report", "--format", "md,json,html"])
    assert code == 0
    d = next(out.glob("*"))
    md = (d / "report.md").read_text(encoding="utf-8")
    assert "未被 --stages 选中" in md and "## 10." in md
    assert (d / "report.html").is_file()
    doc = json.loads((d / "report.json").read_text(encoding="utf-8"))
    assert {s["name"]: s["status"] for s in doc["stages"]}["report"] == "ok"
    assert "== " in capsys.readouterr().out


def test_cli_exit_code_3_and_report_written_when_a_stage_fails(make_zip, tmp_path, monkeypatch):
    import dataclasses

    from ipa_analyzer import pipeline

    reg = pipeline.ensure_analyzers_loaded()

    def boom(ctx):
        raise RuntimeError("synthetic crash")

    monkeypatch.setitem(reg._specs, "classify", dataclasses.replace(reg.get("classify"), run=boom))
    out = tmp_path / "out"
    code = cli.main(["analyze", str(make_zip({"Payload/A.app/x": b"1"})), "-o", str(out)])
    assert code == 3
    d = next(out.glob("*"))
    assert "synthetic crash" in (d / "report.md").read_text(encoding="utf-8")
