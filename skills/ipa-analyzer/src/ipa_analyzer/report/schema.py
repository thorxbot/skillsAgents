"""``report.json`` schema validation.

Uses the optional ``jsonschema`` package when it is installed; otherwise a small built-in validator
for the draft-07 subset the report schema needs (``type``, ``required``, ``properties``, ``items``,
``enum``, ``const``, ``additionalProperties``, ``pattern``, ``minimum``/``maximum``, ``minLength``,
``minItems``, ``$ref`` into ``#/definitions``, ``oneOf`` / ``anyOf`` / ``allOf``).

Validation problems are *warnings*: they never stop report output.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..util.paths import resource_dir

log = logging.getLogger(__name__)

SCHEMA_FILENAME = "report.schema.json"

__all__ = ["ValidationOutcome", "load_schema", "validate", "validate_builtin", "validate_jsonschema"]


@dataclass
class ValidationOutcome:
    errors: List[str] = field(default_factory=list)
    validator: str = "builtin"        # "jsonschema" | "builtin" | "none"
    skipped_reason: Optional[str] = None

    @property
    def ok(self) -> bool:
        return not self.errors and self.skipped_reason is None


def load_schema(path: Optional[Path] = None) -> Dict[str, Any]:
    p = Path(path) if path is not None else resource_dir("schemas") / SCHEMA_FILENAME
    with open(p, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("schema must be a JSON object: %s" % p)
    return data


# --- built-in validator --------------------------------------------------------------------------
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
        return (isinstance(value, int) and not isinstance(value, bool)) or (isinstance(value, float) and value.is_integer())
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if t == "null":
        return value is None
    raise ValueError("unsupported schema type %r" % t)


def _resolve(ref: str, root: Dict[str, Any]) -> Any:
    if not ref.startswith("#/"):
        raise ValueError("only local $ref values are supported: %r" % ref)
    node: Any = root
    for part in ref[2:].split("/"):
        node = node[part.replace("~1", "/").replace("~0", "~")]
    return node


def _validate(inst: Any, schema: Any, root: Dict[str, Any], path: str, errs: List[str], depth: int = 0) -> None:
    if schema is True or schema == {}:
        return
    if schema is False:
        errs.append("%s: no value is allowed here" % path)
        return
    if not isinstance(schema, dict) or depth > 64:
        return
    if "$ref" in schema:
        _validate(inst, _resolve(schema["$ref"], root), root, path, errs, depth + 1)
        return
    if "const" in schema and inst != schema["const"]:
        errs.append("%s: expected constant %r" % (path, schema["const"]))
    if "enum" in schema and inst not in schema["enum"]:
        errs.append("%s: %r is not one of %r" % (path, inst, schema["enum"]))
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(inst, t) for t in types):
            errs.append("%s: expected %s, got %s" % (path, "/".join(types), type(inst).__name__))
            return
    if isinstance(inst, (int, float)) and not isinstance(inst, bool):
        if "minimum" in schema and inst < schema["minimum"]:
            errs.append("%s: %r is below the minimum %r" % (path, inst, schema["minimum"]))
        if "maximum" in schema and inst > schema["maximum"]:
            errs.append("%s: %r is above the maximum %r" % (path, inst, schema["maximum"]))
    if isinstance(inst, str):
        if "pattern" in schema and not re.search(schema["pattern"], inst):
            errs.append("%s: %r does not match %r" % (path, inst, schema["pattern"]))
        if "minLength" in schema and len(inst) < schema["minLength"]:
            errs.append("%s: shorter than %d characters" % (path, schema["minLength"]))
    if isinstance(inst, dict):
        for req in schema.get("required", []):
            if req not in inst:
                errs.append("%s: missing required property %r" % (path, req))
        props = schema.get("properties", {})
        addl = schema.get("additionalProperties", True)
        for k, v in inst.items():
            if k in props:
                _validate(v, props[k], root, "%s.%s" % (path, k), errs, depth + 1)
            elif addl is False:
                errs.append("%s: unexpected property %r" % (path, k))
            elif isinstance(addl, dict):
                _validate(v, addl, root, "%s.%s" % (path, k), errs, depth + 1)
    if isinstance(inst, list):
        if "minItems" in schema and len(inst) < schema["minItems"]:
            errs.append("%s: fewer than %d items" % (path, schema["minItems"]))
        if "items" in schema and isinstance(schema["items"], dict):
            for i, v in enumerate(inst):
                _validate(v, schema["items"], root, "%s[%d]" % (path, i), errs, depth + 1)
    if "allOf" in schema:
        for sub in schema["allOf"]:
            _validate(inst, sub, root, path, errs, depth + 1)
    for kw in ("oneOf", "anyOf"):
        if kw in schema:
            matches = 0
            for sub in schema[kw]:
                sub_errs: List[str] = []
                _validate(inst, sub, root, path, sub_errs, depth + 1)
                if not sub_errs:
                    matches += 1
            if (kw == "oneOf" and matches != 1) or (kw == "anyOf" and matches < 1):
                errs.append("%s: matches %d of the %s alternatives" % (path, matches, kw))


def validate_builtin(instance: Any, schema: Dict[str, Any]) -> List[str]:
    """Error strings (empty = valid) from the built-in validator."""
    errs: List[str] = []
    _validate(instance, schema, schema, "$", errs)
    return errs


def validate_jsonschema(instance: Any, schema: Dict[str, Any]) -> Optional[List[str]]:
    """Errors from the ``jsonschema`` package, or ``None`` if it is not installed."""
    try:
        import jsonschema  # type: ignore
    except ImportError:
        return None
    try:
        cls = jsonschema.validators.validator_for(schema)
        validator = cls(schema)
        out = []
        for e in sorted(validator.iter_errors(instance), key=lambda e: [str(p) for p in e.absolute_path]):
            loc = "$" + "".join("[%d]" % p if isinstance(p, int) else ".%s" % p for p in e.absolute_path)
            out.append("%s: %s" % (loc, e.message))
        return out
    except Exception as exc:  # noqa: BLE001 - a broken optional dependency must not block the report
        log.debug("jsonschema validation failed unexpectedly", exc_info=True)
        return ["jsonschema could not validate: %s" % exc]


def validate(report: Dict[str, Any], schema: Optional[Dict[str, Any]] = None, *,
             prefer_jsonschema: bool = True) -> ValidationOutcome:
    """Validate a report dict. Never raises; a missing / unreadable schema yields ``skipped_reason``."""
    if schema is None:
        try:
            schema = load_schema()
        except (OSError, ValueError) as exc:
            return ValidationOutcome(validator="none", skipped_reason="schema unavailable: %s" % exc)
    if prefer_jsonschema:
        js = validate_jsonschema(report, schema)
        if js is not None:
            return ValidationOutcome(errors=js, validator="jsonschema")
    return ValidationOutcome(errors=validate_builtin(report, schema), validator="builtin")
