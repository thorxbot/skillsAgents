from __future__ import annotations

import pytest

from ipa_analyzer.engines import api
from ipa_analyzer.errors import RegistryError
from ipa_analyzer.models import Evidence


def test_example_checker_discovered_and_inert():
    checkers = {c.engine_id: c for c in api.get_checkers()}
    assert "example" in checkers
    assert not api.checker_import_failures()
    assert isinstance(checkers["example"], api.EngineChecker)
    assert checkers["example"].applies(None, api.DetectResult()) is False


def test_register_checker_duplicate_and_reserved():
    reg = {}

    @api.register_checker("x1", registry=reg)
    class A:
        def applies(self, ctx, detect):
            return True

        def run(self, ctx, detect):
            return api.CheckerResult()

    assert reg["x1"].engine_id == "x1"
    with pytest.raises(RegistryError):
        api.register_checker("x1", registry=reg)(A)
    with pytest.raises(RegistryError):
        api.register_checker("_hidden", registry=reg)(A)


def test_checker_discovery_isolates_import_failures(tmp_path, monkeypatch):
    pkg = tmp_path / "fakecheckers"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "good.py").write_text("X = 1\n", encoding="utf-8")
    (pkg / "bad.py").write_text("raise ImportError('nope')\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    from ipa_analyzer.engines import checkers
    failed = checkers.discover("fakecheckers")
    assert failed == ["bad"]
    assert "nope" in api.checker_import_failures()["bad"]
    api._CHECKER_IMPORT_FAILURES.pop("bad", None)


def test_dataclass_roundtrips():
    sig = api.EngineSignature(id="unity", name="Unity", signals=[api.SignalSpec("file", "Data/", 0.3, strong=True)],
                              sources=["x"])
    assert api.EngineSignature.from_dict(sig.to_dict()) == sig

    fp = api.FingerprintResult(
        render={"metal": api.FingerprintHit("metal", 0.9, evidence=[Evidence("symbol", "MTLCreateSystemDefaultDevice")])},
        script_vms=[api.FingerprintHit("lua", 0.8, extra={"version": "5.3"})], host={"cpp_ratio": 0.7},
        summary_text="s")
    assert api.FingerprintResult.from_dict(fp.to_dict()) == fp
    assert list(fp.to_dict())[:2] == ["render", "shader_formats"]

    det = api.DetectResult(
        primary=api.EngineMatch("unity", "Unity", 0.95, confirmed=True),
        candidates=[api.EngineMatch("unity", "Unity", 0.95, confirmed=True), api.EngineMatch("cocos2dx_cpp", confidence=0.2)],
        custom={"verdict": "no", "confidence": 0.9}, is_game_engine=True)
    assert api.DetectResult.from_dict(det.to_dict()) == det
    assert det.primary_id == "unity" and det.has("cocos2dx_cpp") and not det.has("godot")
    assert det.candidate_ids(confirmed_only=True) == ["unity"]
    empty = api.DetectResult.from_dict({})
    assert empty.primary is None and empty.custom["verdict"] == "unknown"
