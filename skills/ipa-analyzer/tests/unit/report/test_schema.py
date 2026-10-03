"""Schema validation: built-in validator subset, jsonschema parity when installed, report fixtures."""
from __future__ import annotations

import copy
import json

import pytest

from fixtures.sample_report import FIXTURE_NAMES, report_dict
from ipa_analyzer.report.schema import (load_schema, validate, validate_builtin, validate_jsonschema)


@pytest.fixture(scope="module")
def schema():
    return load_schema()


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_fixtures_are_valid(name, schema):
    errors = validate_builtin(report_dict(name), schema)
    assert errors == []
    out = validate(report_dict(name))
    assert out.ok and out.validator in ("jsonschema", "builtin")


def test_missing_required_field_is_detected(schema):
    rd = report_dict("full_success")
    del rd["findings"]
    errs = validate_builtin(rd, schema)
    assert any("findings" in e and "required" in e for e in errs)
    assert not validate(rd).ok


def test_bad_values_are_detected(schema):
    rd = copy.deepcopy(report_dict("full_success"))
    rd["stages"][0]["status"] = "weird"
    rd["findings"][0]["id"] = "Bad ID"
    rd["findings"][0]["confidence"] = 3
    rd["unexpected"] = 1
    rd["findings"][1]["verdict"] = "maybe"
    errs = validate_builtin(rd, schema)
    joined = "\n".join(errs)
    for needle in ("status", "Bad ID", "maximum", "unexpected", "maybe"):
        assert needle in joined


def test_wrong_top_level_type(schema):
    assert validate_builtin([], schema)
    assert validate_builtin({"schema_version": 1}, schema)


def test_builtin_supports_oneof_anyof_const_and_refs():
    sch = {"definitions": {"S": {"type": "string", "minLength": 2}},
           "type": "object", "properties": {
               "a": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
               "b": {"anyOf": [{"$ref": "#/definitions/S"}, {"type": "null"}]},
               "c": {"const": 5}, "d": {"type": "array", "items": {"enum": [1, 2]}, "minItems": 1}},
           "additionalProperties": False}
    assert validate_builtin({"a": 1, "b": None, "c": 5, "d": [1, 2]}, sch) == []
    assert validate_builtin({"a": 1.5}, sch)              # matches neither alternative
    assert validate_builtin({"b": "x"}, sch)              # too short
    assert validate_builtin({"c": 6}, sch)
    assert validate_builtin({"d": []}, sch)
    assert validate_builtin({"d": [3]}, sch)
    assert validate_builtin({"zzz": 1}, sch)              # additionalProperties false
    assert validate_builtin({"a": True}, sch)             # bool is not an integer


def test_integer_and_number_semantics():
    assert validate_builtin(3, {"type": "integer"}) == []
    assert validate_builtin(3.0, {"type": "integer"}) == []
    assert validate_builtin(3.5, {"type": "integer"})
    assert validate_builtin(True, {"type": "number"})


def test_missing_schema_file_raises_in_loader_but_validate_degrades(tmp_path, monkeypatch):
    with pytest.raises(OSError):
        load_schema(tmp_path / "nope.json")
    monkeypatch.setenv("IPA_ANALYZER_SCHEMAS_DIR", str(tmp_path))
    out = validate({"a": 1})
    assert out.skipped_reason and out.validator == "none" and not out.ok


def test_jsonschema_agrees_with_builtin_when_installed(schema):
    pytest.importorskip("jsonschema")
    good = report_dict("full_success")
    broken = copy.deepcopy(good)
    del broken["warnings"]
    assert validate_jsonschema(good, schema) == []
    assert validate_jsonschema(broken, schema)
    assert bool(validate_builtin(broken, schema)) == bool(validate_jsonschema(broken, schema))
