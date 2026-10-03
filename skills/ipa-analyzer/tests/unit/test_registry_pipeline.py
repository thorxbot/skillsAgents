from __future__ import annotations

import pytest

from ipa_analyzer import pipeline
from ipa_analyzer.config import Config
from ipa_analyzer.context import AnalysisContext
from ipa_analyzer.errors import CycleError, InvalidInput, RegistryError, UsageError
from ipa_analyzer.models import Finding, Status, StageResult, Verdict
from ipa_analyzer.registry import Registry, register


def _ctx(tmp_path, **cfg_kw):
    return AnalysisContext(Config(output_dir=tmp_path / "out", **cfg_kw), tmp_path / "in.zip",
                           out_dir=tmp_path / "o", workdir=tmp_path / "w")


def _reg(spec):
    """spec: {name: (requires, after, behaviour)}; behaviour in ok|skip|fail|raise|invalid."""
    r = Registry()
    log = []

    def make(name, beh):
        def run(ctx):
            log.append(name)
            if beh == "raise":
                raise RuntimeError("boom")
            if beh == "invalid":
                raise InvalidInput("bad zip")
            if beh == "skip":
                return StageResult.skipped(name, "nothing to do")
            if beh == "fail":
                return StageResult.failed(name, "explicit failure")
            return StageResult.ok(name, {"v": name}, [Finding("t.%s" % name.replace(".", "_"), Verdict.NO, 1, "t")])
        return run

    for name, (req, aft, beh, *rest) in spec.items():
        register(name, req, aft, always_run=bool(rest and rest[0]), registry=r)(make(name, beh))
    return r, log


def test_order_respects_requires_and_after():
    r, log = _reg({"c": (["b"], [], "ok"), "b": ([], ["a"], "ok"), "a": ([], [], "ok"), "d": ([], ["c"], "ok")})
    assert r.order() == ["a", "b", "c", "d"]


def test_duplicate_name_is_rejected_with_clear_message():
    r = Registry()
    register("x", registry=r)(lambda ctx: None)
    with pytest.raises(RegistryError, match="duplicate stage name 'x'"):
        register("x", registry=r)(lambda ctx: None)


def test_cycle_detected():
    r, _ = _reg({"a": (["b"], [], "ok"), "b": (["c"], [], "ok"), "c": ([], ["a"], "ok")})
    with pytest.raises(CycleError) as ei:
        r.validate()
    assert set(ei.value.cycle) == {"a", "b", "c"} and "->" in str(ei.value)


def test_self_dependency_rejected():
    with pytest.raises(RegistryError):
        register("a", ["a"], registry=Registry())(lambda ctx: None)


def test_unknown_requires_is_error_unless_import_failures():
    r, _ = _reg({"a": (["ghost"], [], "ok")})
    with pytest.raises(RegistryError, match="unknown stage 'ghost'"):
        r.validate()
    r.record_import_failure("broken", "ImportError: x")
    r.validate()


def test_pipeline_runs_in_order_and_collects(tmp_path):
    r, log = _reg({"b": (["a"], [], "ok"), "a": ([], [], "ok"),
                   "report": ([], [], "ok", True)})
    ctx = _ctx(tmp_path)
    out = pipeline.run(ctx, r)
    assert log == ["a", "b", "report"]
    assert [x.status for x in out.stage_results] == [Status.OK] * 3
    assert ctx.results["a"] == {"v": "a"} and len(ctx.findings) == 3
    assert not out.failed


def test_exception_isolated_and_downstream_skipped_report_still_runs(tmp_path):
    r, log = _reg({"a": ([], [], "raise"), "b": (["a"], [], "ok"), "c": (["b"], [], "ok"),
                   "soft": ([], ["a"], "ok"), "report": ([], ["a", "b", "c", "soft"], "ok", True)})
    ctx = _ctx(tmp_path)
    out = pipeline.run(ctx, r)
    st = {x.name: x for x in out.stage_results}
    assert st["a"].status is Status.FAILED and "RuntimeError: boom" in st["a"].error
    assert st["b"].status is Status.SKIPPED and st["b"].reason == "dependency a failed"
    assert st["c"].status is Status.SKIPPED and st["c"].reason == "dependency b skipped"
    assert st["soft"].status is Status.OK          # soft dependency does not gate
    assert st["report"].status is Status.OK and "report" in log
    assert "a" not in ctx.results and "soft" in ctx.results
    assert out.failed == ["a"] and not out.invalid_input


def test_explicit_failed_and_skipped_statuses_gate_dependents(tmp_path):
    r, _ = _reg({"a": ([], [], "fail"), "b": (["a"], [], "ok"), "s": ([], [], "skip"), "t": (["s"], [], "ok")})
    st = {x.name: x for x in pipeline.run(_ctx(tmp_path), r).stage_results}
    assert st["b"].reason == "dependency a failed" and st["t"].reason == "dependency s skipped"


def test_invalid_input_flag(tmp_path):
    r, _ = _reg({"a": ([], [], "invalid")})
    out = pipeline.run(_ctx(tmp_path), r)
    assert out.invalid_input and out.stage_results[0].status is Status.FAILED


def test_bad_return_and_non_json_data_fail_the_stage(tmp_path):
    r = Registry()
    register("none", registry=r)(lambda ctx: None)
    register("obj", registry=r)(lambda ctx: StageResult.ok("obj", {"x": object()}))
    st = {x.name: x for x in pipeline.run(_ctx(tmp_path), r).stage_results}
    assert st["none"].status is Status.FAILED and "StageResult" in st["none"].error
    assert st["obj"].status is Status.FAILED and "JSON" in st["obj"].error


def test_stage_data_is_normalised_to_json_types(tmp_path):
    from pathlib import Path
    r = Registry()
    register("p", registry=r)(lambda ctx: StageResult.ok("p", {"path": Path("a/b"), "t": (1, 2), "e": Verdict.NO}))
    ctx = _ctx(tmp_path)
    pipeline.run(ctx, r)
    assert ctx.results["p"] == {"path": "a/b", "t": [1, 2], "e": "no"}


def test_skip_and_stages_selection(tmp_path):
    spec = {"a": ([], [], "ok"), "b": (["a"], [], "ok"), "c": (["b"], [], "ok"), "d": ([], [], "ok"),
            "report": ([], ["a", "b", "c", "d"], "ok", True)}
    r, log = _reg(spec)
    ctx = _ctx(tmp_path, stages=("b",))
    st = {x.name: x for x in pipeline.run(ctx, r).stage_results}
    assert st["a"].status is Status.OK and st["b"].status is Status.OK      # hard dep pulled in
    assert st["c"].status is Status.SKIPPED and st["c"].reason == "not selected by --stages"
    assert st["d"].reason == "not selected by --stages" and st["report"].status is Status.OK

    r2, _ = _reg(spec)
    st2 = {x.name: x for x in pipeline.run(_ctx(tmp_path, skip=("a",)), r2).stage_results}
    assert st2["a"].reason == "disabled by --skip" and st2["b"].reason == "dependency a skipped"
    assert st2["d"].status is Status.OK


def test_unknown_stage_name_in_selection_is_usage_error(tmp_path):
    r, _ = _reg({"a": ([], [], "ok")})
    with pytest.raises(UsageError):
        pipeline.run(_ctx(tmp_path, stages=("zzz",)), r)
    with pytest.raises(UsageError):
        pipeline.run(_ctx(tmp_path, skip=("zzz",)), r)


def test_cycle_stops_before_running_anything(tmp_path):
    r, log = _reg({"a": (["b"], [], "ok"), "b": (["a"], [], "ok")})
    with pytest.raises(CycleError):
        pipeline.run(_ctx(tmp_path), r)
    assert log == []


def test_always_run_runs_even_if_nothing_else_does(tmp_path):
    r, log = _reg({"a": ([], [], "raise"), "report": (["a"], [], "ok", True)})
    out = pipeline.run(_ctx(tmp_path), r)
    assert log == ["a", "report"]       # always_run ignores failed hard dependencies
    assert out.stage_results[-1].status is Status.OK


def test_class_registration_and_unknown_dependency_skips(tmp_path):
    r = Registry()

    @register("k", requires=["ghost"], registry=r)
    class K:
        def run(self, ctx):
            raise AssertionError("must not run")

    r.record_import_failure("broken", "ImportError: nope")
    out = pipeline.run(_ctx(tmp_path), r)
    st = {x.name: x for x in out.stage_results}
    assert st["k"].reason == "dependency ghost not available"
    assert st["import:broken"].status is Status.FAILED and "ImportError: nope" in st["import:broken"].error


# --- the real stage table -----------------------------------------------------------------------
EXPECTED_STAGES = {
    "ingest": ((), ()),
    "inventory": (("ingest",), ()),
    "meta": (("ingest",), ()),
    "macho": (("inventory",), ()),
    "engine.fingerprint": (("inventory",), ("macho", "meta")),
    "engine.detect": (("inventory",), ("macho", "meta", "engine.fingerprint")),
    "engine.other": (("engine.detect",), ()),
    "engine.unity": (("engine.detect", "inventory"), ("macho", "meta")),
    "engine.unity.hotfix": (("engine.unity",), ("inventory", "macho")),
    "libs": (("inventory",), ("macho", "engine.fingerprint", "engine.unity", "engine.unity.hotfix", "engine.other")),
    "protect": (("inventory",), ("macho", "engine.unity", "engine.unity.hotfix", "engine.other", "libs")),
    "classify": ((), ("meta", "engine.detect", "engine.fingerprint", "libs")),
}


def test_stub_stage_table_matches_contract():
    reg = pipeline.ensure_analyzers_loaded()
    assert not reg.import_failures
    assert set(reg.names()) == set(EXPECTED_STAGES) | {"report"}
    assert len(reg) == 13
    for name, (req, aft) in EXPECTED_STAGES.items():
        spec = reg.get(name)
        assert (spec.requires, spec.after) == (req, aft), name
        assert not spec.always_run
    rep = reg.get("report")
    assert rep.always_run and set(rep.after) == set(EXPECTED_STAGES) and rep.requires == ()


def test_real_registry_plan_is_valid_topological_order():
    reg = pipeline.ensure_analyzers_loaded()
    order = reg.order()
    assert order[-1] == "report" and order[0] == "ingest"
    pos = {n: i for i, n in enumerate(order)}
    for s in reg.specs():
        for d in s.requires + s.after:
            assert pos[d] < pos[s.name], (d, s.name)
    assert order == reg.order()            # deterministic
