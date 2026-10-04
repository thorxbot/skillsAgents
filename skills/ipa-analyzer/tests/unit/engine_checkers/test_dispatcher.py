from __future__ import annotations

import ast
import json
import string
from pathlib import Path

import pytest

from fixtures import engine_checker_builder as B
from ipa_analyzer.analyzers.engines_other import EngineOtherStage
from ipa_analyzer.engines import api
from ipa_analyzer.engines.api import CheckerResult, register_checker
from ipa_analyzer.models import Finding, Status, Verdict
from ipa_analyzer.util.paths import resource_dir

SRC = Path(__file__).resolve().parents[3] / "src" / "ipa_analyzer"


def test_stage_skipped_when_nothing_applies(runner):
    r = runner.run({"Info.plist": b"x"})
    assert r.status == Status.SKIPPED and "no engine checker applies" in r.res.reason


def test_stage_skipped_without_detect_result(tmp_path):
    ctx = B.make_ctx(tmp_path, {"a.js": B.JS_PLAIN})
    ctx.results.pop("engine.detect")
    assert EngineOtherStage().run(ctx).status == Status.SKIPPED
    ctx.close()


@pytest.fixture()
def temp_checkers(monkeypatch):
    monkeypatch.setattr(api, "_CHECKERS", dict(api._CHECKERS))
    return api._CHECKERS


def test_checker_exception_is_isolated_partial(runner, temp_checkers):
    @register_checker("zz_boom")
    class Boom:
        def applies(self, ctx, detect):
            return True

        def run(self, ctx, detect):
            raise RuntimeError("boom")

    r = runner.run(B.cocos2dx_cpp_files())
    assert r.status == Status.PARTIAL
    meta = r.data["_checkers"]
    assert meta["zz_boom"]["status"] == "failed" and "boom" in meta["zz_boom"]["error"]
    assert meta["cocos"]["status"] == "ok" and "cocos" in r.data      # the others still ran
    assert any(f.id == "engine.resource.encrypted" for f in r.res.findings)


def test_applies_exception_is_isolated(runner, temp_checkers):
    @register_checker("zz_bad_applies")
    class BadApplies:
        def applies(self, ctx, detect):
            raise ValueError("nope")

        def run(self, ctx, detect):  # pragma: no cover
            raise AssertionError

    r = runner.run(B.cocos2dx_cpp_files())
    assert r.status == Status.PARTIAL and r.data["_checkers"]["zz_bad_applies"]["status"] == "failed"


def test_new_checker_is_one_file_one_decorator(runner, temp_checkers):
    @register_checker("zz_new")
    class New:
        def applies(self, ctx, detect):
            return detect.has("zz_engine")

        def run(self, ctx, detect):
            return CheckerResult(findings=[Finding("engine.script.encrypted", Verdict.NO, 0.5, "t", tags=["engine:zz_new"])],
                                 data={"hello": 1})

    r = runner.run({"a.txt": "x"}, detect=["zz_engine"])
    assert r.status == Status.OK and r.data["zz_new"] == {"hello": 1}
    assert r.data["_checkers"]["zz_new"]["status"] == "ok"


def test_partial_checker_status_propagates_and_skipped_has_no_data(runner, temp_checkers):
    @register_checker("zz_part")
    class Part:
        def applies(self, ctx, detect):
            return True

        def run(self, ctx, detect):
            return CheckerResult(data={"x": 1}, status=Status.PARTIAL, reason="half", warnings=["w1"])

    @register_checker("zz_skip")
    class Skip:
        def applies(self, ctx, detect):
            return True

        def run(self, ctx, detect):
            return CheckerResult(status=Status.SKIPPED, reason="nothing")

    r = runner.run({"a.txt": "x"})
    assert r.status == Status.PARTIAL and "zz_part" in r.data and "zz_skip" not in r.data
    assert r.data["_checkers"]["zz_skip"]["reason"] == "nothing"
    assert any("w1" in w for w in r.res.warnings)


def test_fallback_checkers_yield_to_dedicated(runner):
    r = runner.run(B.cocos2dx_lua_files("luac51"))          # layout alone selects the Cocos checker
    meta = r.data["_checkers"]
    assert meta["cocos"]["status"] == "ok" and meta["lua"]["status"] == "skipped" and "superseded" in meta["lua"]["reason"]
    assert r.status == Status.OK


def test_result_is_json_serialisable(runner):
    r = runner.run(B.cocos_creator3x_files(wrapped=True), detect=["cocos_creator_3x"])
    json.dumps(r.data)
    from ipa_analyzer.models import to_jsonable
    json.dumps(to_jsonable(r.data))


def test_stage_table_unchanged():
    from ipa_analyzer.registry import get_registry
    spec = get_registry().get("engine.other")
    assert spec.requires == ("engine.detect",) and spec.after == ()


# --- zh templates only use parameters every producer provides ---------------------------------------------------
def test_i18n_templates_match_params(runner):
    zh = json.loads((resource_dir("data") / "i18n" / "zh" / "engine_checkers.json").read_text(encoding="utf-8"))
    en = json.loads((resource_dir("data") / "i18n" / "en" / "engine_checkers.json").read_text(encoding="utf-8"))
    assert set(zh) == set(en) and all(set(v) == {"title", "summary", "remediation"} for v in zh.values())
    cases = [(B.cocos2dx_lua_files("xxtea"), ["cocos2dx_lua"]), (B.cocos2dx_cpp_files(), []), (B.unreal_files(version=8), ["unreal"]),
             ({"game.pck": B.godot_pck()}, []), (B.rn_files(kind="hermes"), []), (B.flutter_files(), []), (B.defold_files(), []),
             (B.gamemaker_files(), []), (B.love_files(), []), (B.xamarin_files(), []), (B.web_files(), []), (B.egret_files(), []),
             (B.custom_wrapper_files(), []), ({"a.lua": B.LUA_PLAIN}, []), (B.solar2d_files(), [])]
    seen = set()
    for files, det in cases:
        for f in runner.run(files, detect=det).res.findings:
            seen.add(f.id)
            for lang in (zh, en):
                tpl = lang[f.id]
                for text in (tpl["title"], tpl["summary"], tpl["remediation"]):
                    for _, name, _, _ in string.Formatter().parse(text):
                        if name:
                            assert name in f.params, "%s: template uses {%s}, params %s" % (f.id, name, sorted(f.params))
    assert seen == set(zh)


# --- structural rules ---------------------------------------------------------------------------------------------
def test_checkers_do_not_import_each_other():
    d = SRC / "engines" / "checkers"
    names = {p.stem for p in d.glob("*.py")}
    for p in d.glob("*.py"):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.ImportFrom):
                mods.append(("." * node.level) + (node.module or ""))
                mods.extend(a.name for a in node.names if node.level == 1 and not node.module)
            elif isinstance(node, ast.Import):
                mods.extend(a.name for a in node.names)
            for m in mods:
                last = m.rsplit(".", 1)[-1]
                assert not (last in names and last != p.stem and "checkers" in m + "." + last), "%s imports %s" % (p.name, m)
                assert not (m.startswith(".") and not m.startswith("..") and m.lstrip(".") in names), "%s imports sibling %s" % (p.name, m)


def test_sources_parse_as_python39():
    for sub in ("engines/checkers", "engines/formats", "analyzers"):
        for p in (SRC / sub).glob("*.py"):
            ast.parse(p.read_text(encoding="utf-8"), feature_version=(3, 9))
    for p in (Path(__file__).resolve().parents[2] / "fixtures").glob("engine_checker_builder.py"):
        ast.parse(p.read_text(encoding="utf-8"), feature_version=(3, 9))


def test_checks_json_sections_cover_all_checkers():
    from ipa_analyzer.engines.formats import common
    sections = set(common.load_checks())
    for c in api.get_checkers():
        if c.engine_id == "example":
            continue
        assert c.engine_id in sections or c.engine_id in ("cocos",) or c.engine_id in sections, c.engine_id
