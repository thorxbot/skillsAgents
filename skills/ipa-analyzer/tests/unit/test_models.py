from __future__ import annotations

import json
import math
import plistlib
from datetime import datetime
from pathlib import Path

import pytest

from ipa_analyzer.models import (Evidence, Finding, Report, Status, StageResult, Verdict, dumps_json, to_jsonable)


def test_finding_roundtrip_and_key_order():
    f = Finding(id="protect.fairplay", verdict="yes", confidence=0.9, title="t",
                evidence=[Evidence("macho", "Payload/A.app/A", "cryptid=1")], tags=["x"], params={"b": 1, "a": 2})
    d = f.to_dict()
    assert list(d) == ["id", "verdict", "confidence", "title", "summary", "params", "evidence", "remediation", "tags"]
    assert d["verdict"] == "yes"
    assert Finding.from_dict(json.loads(json.dumps(d))) == f


def test_finding_confidence_clamped_and_nan():
    assert Finding("a.b", Verdict.NO, 7, "t").confidence == 1.0
    assert Finding("a.b", Verdict.NO, -1, "t").confidence == 0.0
    assert Finding("a.b", Verdict.NO, math.nan, "t").confidence == 0.0
    with pytest.raises(ValueError):
        Finding("a.b", "maybe", 0.5, "t")


def test_stage_result_helpers_and_roundtrip():
    r = StageResult.skipped("x", "because")
    assert r.status is Status.SKIPPED and r.reason == "because"
    r2 = StageResult.partial("y", {"k": [1]}, warnings=["w"], reason="r")
    assert StageResult.from_dict(r2.to_dict()) == r2
    assert "data" not in r2.summary_dict() and r2.summary_dict()["finding_ids"] == []
    assert StageResult.failed("z", "boom").error == "boom"


def test_to_jsonable_conversions():
    out = to_jsonable({"p": Path("a/b"), "s": {3, 1}, "t": (1, 2), "e": Verdict.YES, "b": b"\x01\xff",
                       "d": datetime(2020, 1, 2, 3, 4, 5), "uid": plistlib.UID(5), "n": float("inf"), 7: "x"})
    assert out["p"] == "a/b" and out["s"] == [1, 3] and out["t"] == [1, 2] and out["e"] == "yes"
    assert out["b"] == "01ff" and out["d"].startswith("2020-01-02") and out["uid"] == 5 and out["n"] is None
    assert out["7"] == "x"
    with pytest.raises(TypeError):
        to_jsonable({"x": object()})
    with pytest.raises(TypeError):
        to_jsonable({(1, 2): 1})


def test_to_jsonable_sort_keys():
    assert list(to_jsonable({"b": {"z": 1, "a": 2}, "a": 1}, sort_keys=True)) == ["a", "b"]


def test_report_defaults_and_stability():
    r = Report(tool={"name": "t", "version": "1"}, generated_at="now", app={"z": 1, "a": 2})
    d = r.to_dict()
    assert list(d)[:3] == ["schema_version", "tool", "generated_at"]
    assert list(d["app"]) == ["a", "z"]
    assert "summary" not in d and "config" not in d
    assert r.to_json().endswith("\n") and "\r" not in r.to_json()
    again = Report.from_dict(json.loads(r.to_json()))
    assert again.to_dict() == d


def test_report_with_findings_in_protection():
    f = Finding("protect.fairplay", Verdict.NO, 0.8, "t")
    r = Report(findings=[f], protection={"findings": [f], "extra": {"b": 1, "a": 2}})
    d = r.to_dict()
    assert d["protection"]["findings"][0]["id"] == "protect.fairplay"
    assert list(d["findings"][0])[0] == "id"


def test_dumps_json_is_deterministic():
    assert dumps_json({"b": 1, "a": 2}, sort_keys=True) == dumps_json({"a": 2, "b": 1}, sort_keys=True)
