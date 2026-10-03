"""End-to-end skeleton smoke tests: CLI -> pipeline -> report.json (all stages are stubs)."""
from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import sys

import pytest

from conftest import SCRIPT_PATH
from ipa_analyzer import cli, pipeline
from ipa_analyzer.models import Status, StageResult

STUB_NAMES = ["ingest", "inventory", "meta", "macho", "engine.fingerprint", "engine.detect", "engine.other",
              "engine.unity", "engine.unity.hotfix", "libs", "protect", "classify", "report"]


def _find_report(out_dir):
    reports = list(out_dir.glob("*/report.json"))
    assert len(reports) == 1, reports
    return reports[0]


def test_analyze_empty_zip_produces_valid_report(make_zip, tmp_path, check_report, capsys):
    zp = make_zip({}, "empty.zip")
    out = tmp_path / "out"
    code = cli.main(["analyze", str(zp), "-o", str(out)])
    assert code == 0, capsys.readouterr()
    report = json.loads(_find_report(out).read_text(encoding="utf-8"))
    assert check_report(report) == []
    assert sorted(s["name"] for s in report["stages"]) == sorted(STUB_NAMES)
    assert {s["status"] for s in report["stages"]} == {"skipped"}
    assert all(s["reason"] for s in report["stages"])
    assert report["input"]["kind"] is None and report["input"]["sha256"]
    assert report["tool"]["name"] == "ipa-analyzer"
    # work dir is cleaned unless --keep-workdir
    assert not list(out.glob("*/work"))
    printed = capsys.readouterr().out
    assert "report:" in printed and "skipped" in printed


def test_all_13_stubs_run_in_dependency_order(make_zip, tmp_path):
    out = tmp_path / "out"
    assert cli.main(["analyze", str(make_zip({})), "-o", str(out)]) == 0
    report = json.loads(_find_report(out).read_text(encoding="utf-8"))
    order = [s["name"] for s in report["stages"]]
    assert len(order) == 13 and set(order) == set(STUB_NAMES) and order[0] == "ingest" and order[-1] == "report"
    reg = pipeline.ensure_analyzers_loaded()
    pos = {n: i for i, n in enumerate(order)}
    for s in reg.specs():
        for d in s.requires + s.after:
            assert pos[d] < pos[s.name]


def test_report_json_is_deterministic_apart_from_time(make_zip, tmp_path):
    zp = make_zip({"Payload/A.app/Info.plist": b"x"})
    docs = []
    for i in range(2):
        out = tmp_path / ("out%d" % i)
        assert cli.main(["analyze", str(zp), "-o", str(out)]) == 0
        d = json.loads(_find_report(out).read_text(encoding="utf-8"))
        d.pop("generated_at")
        d["config"]["output_dir"] = ""
        for s in d["stages"]:
            s["duration_s"] = 0
        docs.append(d)
    assert docs[0] == docs[1]


def test_stage_exception_skips_downstream_and_exit_code_3(make_zip, tmp_path, monkeypatch, check_report, capsys):
    reg = pipeline.ensure_analyzers_loaded()

    def ok_ingest(ctx):
        return StageResult.ok("ingest", {"kind": "zip", "path": str(ctx.input_path), "size": 1,
                                         "sha256": "ab" * 32, "app_root": "", "app_name_dir": "", "entries": 0,
                                         "warnings": []})

    def boom(ctx):
        raise RuntimeError("synthetic crash")

    monkeypatch.setitem(reg._specs, "ingest", dataclasses.replace(reg.get("ingest"), run=ok_ingest))
    monkeypatch.setitem(reg._specs, "inventory", dataclasses.replace(reg.get("inventory"), run=boom))
    out = tmp_path / "out"
    code = cli.main(["analyze", str(make_zip({})), "-o", str(out)])
    assert code == 3
    report = json.loads(_find_report(out).read_text(encoding="utf-8"))
    assert check_report(report) == []
    st = {s["name"]: s for s in report["stages"]}
    assert st["inventory"]["status"] == "failed" and "synthetic crash" in st["inventory"]["error"]
    for dep in ("macho", "engine.fingerprint", "engine.detect", "libs", "protect", "engine.unity"):
        assert st[dep]["status"] == "skipped", dep
    assert st["macho"]["reason"] == "dependency inventory failed"
    assert st["ingest"]["status"] == "ok" and "report" in st       # report still ran / listed


def test_invalid_input_exit_codes(tmp_path, capsys):
    assert cli.main(["analyze", str(tmp_path / "missing.ipa"), "-o", str(tmp_path / "o")]) == 2
    empty = tmp_path / "zero.ipa"
    empty.write_bytes(b"")
    assert cli.main(["analyze", str(empty), "-o", str(tmp_path / "o")]) == 2


def test_usage_errors_exit_1(tmp_path, capsys):
    assert cli.main([]) == 1
    assert cli.main(["analyze"]) == 1
    assert cli.main(["analyze", "x.ipa", "--lang", "fr"]) == 1
    assert cli.main(["analyze", "x.ipa", "--format", "pdf"]) == 1
    assert cli.main(["bogus"]) == 1
    assert cli.main(["analyze", str(tmp_path), "--stages", "nonsense", "-o", str(tmp_path / "o")]) == 1
    assert cli.main(["analyze", str(tmp_path), "--max-extract-size", "huge"]) == 1


def test_help_and_version_exit_0(capsys):
    assert cli.main(["--help"]) == 0
    assert cli.main(["analyze", "--help"]) == 0
    assert cli.main(["--version"]) == 0
    assert "ipa-analyzer" in capsys.readouterr().out


def test_doctor_offline(capsys):
    assert cli.main(["doctor", "--offline"]) == 0
    out = capsys.readouterr().out
    for key in ("python", "platform", "dotnet", "cache dir", "stages", "engine checkers"):
        assert key in out
    assert cli.main(["doctor", "--offline", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert any(c["name"] == "network" and c["level"] == "skip" for c in data["checks"])


def test_tools_stub_subcommands(capsys):
    assert cli.main(["tools", "list"]) == 0
    assert cli.main(["tools", "install", "il2cppdumper", "--offline"]) in (0, 1, 4)
    assert cli.main(["tools"]) == 1


def test_stages_and_skip_flags(make_zip, tmp_path):
    out = tmp_path / "out"
    assert cli.main(["analyze", str(make_zip({})), "-o", str(out), "--stages", "meta", "--skip", "classify"]) == 0
    report = json.loads(_find_report(out).read_text(encoding="utf-8"))
    st = {s["name"]: s for s in report["stages"]}
    assert st["classify"]["reason"] == "disabled by --skip"
    assert st["libs"]["reason"] == "not selected by --stages"
    assert st["meta"]["reason"] == "dependency ingest skipped" and st["ingest"]["reason"] == "not implemented"


def test_keep_workdir_flag_keeps_it(make_zip, tmp_path):
    out = tmp_path / "out"
    assert cli.main(["analyze", str(make_zip({})), "-o", str(out), "--keep-workdir"]) == 0
    # stubs never create a workdir; the flag must at least not break the run
    assert _find_report(out).is_file()


def test_script_entry_point_runs_without_install(make_zip, tmp_path):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    r = subprocess.run([sys.executable, str(SCRIPT_PATH), "analyze", str(make_zip({})), "-o", str(tmp_path / "o")],
                       capture_output=True, text=True, encoding="utf-8", timeout=120, env=env)
    assert r.returncode == 0, r.stderr
    assert "report:" in r.stdout
    h = subprocess.run([sys.executable, str(SCRIPT_PATH), "--help"], capture_output=True, text=True,
                       encoding="utf-8", timeout=60, env=env)
    assert h.returncode == 0 and "analyze" in h.stdout


def test_import_has_no_warnings():
    r = subprocess.run([sys.executable, "-W", "error", "-c", "import ipa_analyzer, ipa_analyzer.cli, "
                        "ipa_analyzer.pipeline, ipa_analyzer.engines.api, ipa_analyzer.il2cpp, ipa_analyzer.ingest"],
                       capture_output=True, text=True, timeout=60,
                       env={**os.environ, "PYTHONPATH": str(SCRIPT_PATH.parents[1] / "src")})
    assert r.returncode == 0, r.stderr


def test_report_schema_catches_broken_report(make_zip, tmp_path, check_report):
    out = tmp_path / "out"
    cli.main(["analyze", str(make_zip({})), "-o", str(out)])
    report = json.loads(_find_report(out).read_text(encoding="utf-8"))
    broken = dict(report)
    del broken["findings"]
    assert any("findings" in e for e in check_report(broken))
    bad_stage = json.loads(json.dumps(report))
    bad_stage["stages"][0]["status"] = "weird"
    assert check_report(bad_stage)
    bad_f = json.loads(json.dumps(report))
    bad_f["findings"].append({"id": "Bad ID", "verdict": "maybe", "confidence": 3, "title": "x"})
    assert len(check_report(bad_f)) >= 3


def test_ingest_invalid_input_exits_2_but_writes_report(make_zip, tmp_path, monkeypatch, check_report):
    from ipa_analyzer.errors import InvalidInput

    reg = pipeline.ensure_analyzers_loaded()

    def bad(ctx):
        raise InvalidInput("not an ipa")

    monkeypatch.setitem(reg._specs, "ingest", dataclasses.replace(reg.get("ingest"), run=bad))
    out = tmp_path / "out"
    assert cli.main(["analyze", str(make_zip({})), "-o", str(out)]) == 2
    report = json.loads(_find_report(out).read_text(encoding="utf-8"))
    assert check_report(report) == []
    st = {s["name"]: s for s in report["stages"]}
    assert st["ingest"]["status"] == "failed" and "not an ipa" in st["ingest"]["error"]
    assert st["inventory"]["reason"] == "dependency ingest failed"


def test_cycle_in_registry_is_fatal_exit_4(make_zip, tmp_path, monkeypatch, capsys):
    reg = pipeline.ensure_analyzers_loaded()
    monkeypatch.setitem(reg._specs, "ingest", dataclasses.replace(reg.get("ingest"), requires=("inventory",)))
    assert cli.main(["analyze", str(make_zip({})), "-o", str(tmp_path / "o")]) == 4
    assert "cycle" in capsys.readouterr().err
