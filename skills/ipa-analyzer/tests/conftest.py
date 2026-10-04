"""Shared pytest configuration: markers, skip rules and small helpers.

Builders for fixtures live in ``tests/fixtures/*.py`` and are imported as ``fixtures.<module>``
(``pythonpath`` in pyproject.toml contains ``tests``).
"""
from __future__ import annotations

import json
import os
import re
import sys
import zipfile
from pathlib import Path
from typing import Any, Dict, List

import pytest

SKILL_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = SKILL_ROOT / "schemas" / "report.schema.json"
SCRIPT_PATH = SKILL_ROOT / "scripts" / "ipa_analyze.py"


# Environment variables that change where tools / data are looked up or which host tools are found.
_HOST_ENV_VARS = ("IPA_ANALYZER_DATA_DIR", "IPA_ANALYZER_SCHEMAS_DIR", "IPA_ANALYZER_REFERENCES_DIR",
                  "IL2CPPDUMPER_PATH", "CPP2IL_PATH", "IL2CPPINSPECTOR_PATH",
                  "DOTNET_ROOT", "DOTNET_ROOT_X64", "DOTNET_ROOT_ARM64", "DOTNET_ROLL_FORWARD", "XDG_CACHE_HOME",
                  "XDG_CONFIG_HOME")


@pytest.fixture(autouse=True)
def _isolated_user_dirs(tmp_path_factory, monkeypatch):
    """Never touch the developer's real cache / tool directory or pick up host tools.

    ``IPA_ANALYZER_HOME`` (cache root and user-data dir) points at a fresh temporary directory and the
    variables that redirect resource or tool lookups are removed. Tests that need specific values set
    them themselves with ``monkeypatch`` (that runs after this fixture).
    """
    monkeypatch.setenv("IPA_ANALYZER_HOME", str(tmp_path_factory.mktemp("ipa-home")))
    for var in _HOST_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    yield


def pytest_addoption(parser):
    parser.addoption("--runslow", action="store_true", default=False, help="also run tests marked slow")


def pytest_collection_modifyitems(config, items):
    run_slow = config.getoption("--runslow") or os.environ.get("IPA_TEST_SLOW") == "1"
    run_net = os.environ.get("IPA_TEST_NETWORK") == "1"
    for item in items:
        if "slow" in item.keywords and not run_slow:
            item.add_marker(pytest.mark.skip(reason="slow test: use --runslow"))
        if "network" in item.keywords and not run_net:
            item.add_marker(pytest.mark.skip(reason="network test: set IPA_TEST_NETWORK=1"))
        if "macos_only" in item.keywords and sys.platform != "darwin":
            item.add_marker(pytest.mark.skip(reason="macOS only"))


# --- minimal JSON Schema (draft-07 subset) validator -------------------------------------------
def _type_ok(value: Any, t: str) -> bool:
    if t == "object":
        return isinstance(value, dict)
    if t == "array":
        return isinstance(value, list)
    if t == "string":
        return isinstance(value, str)
    if t == "boolean":
        return isinstance(value, bool)
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if t == "null":
        return value is None
    raise ValueError("unsupported type " + t)


def validate_schema(instance: Any, schema: Dict[str, Any], root: Dict[str, Any] = None, path: str = "$") -> List[str]:
    """Return a list of error strings (empty = valid). Supports the subset used by report.schema.json."""
    root = root or schema
    errs: List[str] = []
    if "$ref" in schema:
        ref = schema["$ref"]
        assert ref.startswith("#/"), ref
        node: Any = root
        for part in ref[2:].split("/"):
            node = node[part]
        return validate_schema(instance, node, root, path)
    if "enum" in schema and instance not in schema["enum"]:
        errs.append("%s: %r not in enum %r" % (path, instance, schema["enum"]))
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(instance, t) for t in types):
            return errs + ["%s: expected %s, got %s" % (path, types, type(instance).__name__)]
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errs.append("%s: %r < minimum %r" % (path, instance, schema["minimum"]))
        if "maximum" in schema and instance > schema["maximum"]:
            errs.append("%s: %r > maximum %r" % (path, instance, schema["maximum"]))
    if isinstance(instance, str) and "pattern" in schema and not re.search(schema["pattern"], instance):
        errs.append("%s: %r does not match %r" % (path, instance, schema["pattern"]))
    if isinstance(instance, dict):
        for req in schema.get("required", []):
            if req not in instance:
                errs.append("%s: missing required property %r" % (path, req))
        props = schema.get("properties", {})
        for k, v in instance.items():
            if k in props:
                errs += validate_schema(v, props[k], root, "%s.%s" % (path, k))
            else:
                ap = schema.get("additionalProperties", True)
                if ap is False:
                    errs.append("%s: unexpected property %r" % (path, k))
                elif isinstance(ap, dict):
                    errs += validate_schema(v, ap, root, "%s.%s" % (path, k))
    if isinstance(instance, list) and "items" in schema:
        for i, v in enumerate(instance):
            errs += validate_schema(v, schema["items"], root, "%s[%d]" % (path, i))
    return errs


@pytest.fixture(scope="session")
def report_schema() -> Dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture()
def check_report(report_schema):
    """Callable: validate a report dict against the schema (jsonschema if installed, else the minimal validator)."""

    def _check(report: Dict[str, Any]) -> List[str]:
        errors = validate_schema(report, report_schema)
        try:
            import jsonschema  # type: ignore

            try:
                jsonschema.validate(report, report_schema)
            except jsonschema.ValidationError as exc:   # pragma: no cover - only with jsonschema installed
                errors.append("jsonschema: " + exc.message)
        except ImportError:
            pass
        return errors

    return _check


@pytest.fixture()
def make_zip(tmp_path):
    """Create a zip with the given ``{name: bytes|str}`` entries and return its path."""

    def _make(files: Dict[str, Any] = None, name: str = "sample.ipa") -> Path:
        p = tmp_path / name
        with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
            for n, data in (files or {}).items():
                zf.writestr(n, data if isinstance(data, bytes) else str(data).encode("utf-8"))
        return p

    return _make
