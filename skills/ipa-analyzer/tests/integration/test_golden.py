"""Golden-file comparison of the end-to-end results (time / duration / temporary paths ignored).

The golden file of a fixture is a *projection* of ``report.json`` (verdicts, stage statuses and reasons, engine and
classification answers, the unity / hot-update headline fields), not the whole report: it stays small, diffs
readably and does not depend on the machine.  After an intended behaviour change regenerate with::

    IPA_UPDATE_GOLDEN=1 python -m pytest tests/integration/test_golden.py
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

import pytest

from fixtures.full_ipa_builders import FIXTURES

GOLDEN_DIR = Path(__file__).resolve().parent / "golden"
UPDATE = os.environ.get("IPA_UPDATE_GOLDEN") == "1"


def project(run) -> Dict[str, Any]:
    rep = run.report
    out: Dict[str, Any] = {
        "exit_code": run.returncode,
        "stages": [[s["name"], s["status"], (s.get("reason") or "") if s["status"] != "failed" else s["error"].split(":")[0]]
                   for s in rep["stages"]],
        "findings": [[f["id"], f["verdict"], round(f["confidence"], 2), sorted(f.get("tags", []))] for f in rep["findings"]],
        "classification": [rep["classification"].get("category"), rep["classification"].get("subcategory")],
        "warnings": sorted(rep["warnings"]),
        "libraries": sorted(i["id"] for i in rep["libraries"]),
    }
    det = rep["engine_details"].get("detect")
    if det:
        out["engine"] = {"primary": (det["primary"] or {}).get("id"),
                         "confirmed": sorted(c["id"] for c in det["candidates"] if c["confirmed"]),
                         "custom": (det["custom"] or {}).get("verdict"), "is_game_engine": det["is_game_engine"],
                         "languages": sorted(x["lang"] for x in det["languages"])}
    unity = rep["engine_details"].get("unity")
    if unity:
        out["unity"] = {"backend": unity.get("backend"), "version": unity["version"]["value"],
                        "metadata": [unity["metadata"].get("version"), unity["metadata"].get("verdict")],
                        "bundles": {k: v for k, v in unity["bundles"]["by_class"].items() if v},
                        "precheck": [unity["precheck"]["ready"], unity["precheck"]["error_code"]],
                        "dump": [unity["dump"].get("ok"), unity["dump"].get("error_code")]}
        hot = unity.get("hotfix")
        if hot:
            out["hotfix"] = {"frameworks": sorted(f["id"] for f in hot["frameworks"] if f["confidence"] >= 0.5),
                             "lua_by_version": hot["lua"]["bytecode"]["by_version"],
                             "lua_consistent": hot["lua"]["consistency"]["ok"],
                             "protection": hot["script_protection"],
                             "assemblies": sorted([a["name"], a["format"], a["kind"]] for a in hot["csharp"]["assemblies"])}
    return out


def dump(obj: Dict[str, Any]) -> str:
    """Deterministic, diff-friendly text: one line per list element."""
    lines = []
    for key in sorted(obj):
        val = obj[key]
        if isinstance(val, list) and val and isinstance(val[0], list):
            body = ",\n".join("  " + json.dumps(v, ensure_ascii=False) for v in val)
            lines.append("%s: [\n%s\n]" % (json.dumps(key), body))
        else:
            lines.append("%s: %s" % (json.dumps(key), json.dumps(val, ensure_ascii=False, sort_keys=True)))
    return "{\n" + ",\n".join(lines) + "\n}\n"


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_golden(runs, name):
    run = runs.cli(name)
    assert run.report is not None
    got = project(run)
    text = dump(got)
    assert str(runs.base) not in text and str(runs.base).replace("\\", "/") not in text, "temporary path leaked into the projection"
    path = GOLDEN_DIR / (name + ".json")
    if UPDATE:
        GOLDEN_DIR.mkdir(exist_ok=True)
        with open(str(path), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        return
    assert path.is_file(), "no golden file for %s (run with IPA_UPDATE_GOLDEN=1)" % name
    want = json.loads(path.read_text(encoding="utf-8"))
    assert got == json.loads(text) and json.loads(text) == want, "golden mismatch for %s" % name


def test_no_stale_golden_files():
    assert {p.stem for p in GOLDEN_DIR.glob("*.json")} <= set(FIXTURES)
