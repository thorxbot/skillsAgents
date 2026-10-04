"""report.json: stable order, shuffle invariance, externalised tables, golden files."""
from __future__ import annotations

import copy
import json
import os
import random
from pathlib import Path

import pytest

from fixtures.sample_report import FIXTURE_NAMES, build_ctx, build_report
from ipa_analyzer.report import canonicalize, externalize_large, render_json
from ipa_analyzer.report.render_json import TOP_LEVEL_ORDER

GOLDEN = Path(__file__).parent / "golden"


def _shuffle(obj, rng, lists=True):
    """Shuffle dict key order everywhere and the order of order-insensitive lists."""
    if isinstance(obj, dict):
        items = [(k, _shuffle(v, rng, lists)) for k, v in obj.items()]
        rng.shuffle(items)
        return dict(items)
    if isinstance(obj, list):
        items = [_shuffle(v, rng, lists) for v in obj]
        return items
    return obj


def _shuffle_unordered_lists(d, rng):
    for path in (("libraries",), ("structure", "binaries"), ("structure", "nested_units"), ("resources", "by_category"),
                 ("resources", "by_ext"), ("resources", "top_files"), ("resources", "localizations"),
                 ("privacy", "permissions"), ("privacy", "url_schemes"), ("privacy", "trackers"),
                 ("engine_details", "detect", "candidates"), ("structure", "tree", "children"),
                 ("app", "extensions"), ("app", "devices"), ("engine_details", "unity", "bundles", "paths_sample"),
                 ("engine_details", "unity", "dump", "namespaces")):
        cur = d
        for p in path:
            cur = cur.get(p) if isinstance(cur, dict) else None
        if isinstance(cur, list):
            rng.shuffle(cur)
    return d


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_output_is_independent_of_input_order(name):
    base = build_report(name).to_dict()
    expected = render_json(base)
    for seed in range(5):
        rng = random.Random(seed)
        shuffled = _shuffle_unordered_lists(_shuffle(copy.deepcopy(base), rng), rng)
        assert render_json(shuffled) == expected


def test_top_level_key_order_and_report_object_equivalence():
    rep = build_report("full_success")
    text = render_json(rep)
    assert text.endswith("\n") and "\r" not in text
    d = json.loads(text)
    assert list(d) == [k for k in TOP_LEVEL_ORDER if k in d]
    assert render_json(rep.to_dict()) == text
    assert list(d["findings"][0]) == ["id", "verdict", "confidence", "title", "summary", "params", "evidence", "remediation", "tags"]
    assert list(d["stages"][0])[:3] == ["name", "status", "duration_s"]


def test_stage_and_finding_order_are_preserved():
    rd = build_report("full_success").to_dict()
    out = json.loads(render_json(rd))
    assert [s["name"] for s in out["stages"]] == [s["name"] for s in rd["stages"]]
    assert [f["id"] for f in out["findings"]] == [f["id"] for f in rd["findings"]]


def test_canonicalize_sorts_collections():
    rd = canonicalize(build_report("full_success").to_dict())
    sizes = [c["size"] for c in rd["resources"]["by_category"]]
    assert sizes == sorted(sizes, reverse=True)
    libs = [(x["category"], x["name"].lower()) for x in rd["libraries"]]
    assert libs == sorted(libs)
    kids = rd["structure"]["tree"]["children"]
    assert [k["size"] for k in kids] == sorted((k["size"] for k in kids), reverse=True)


def test_externalize_large_tables():
    rd = canonicalize(build_report("full_success").to_dict())
    n_ns = len(rd["engine_details"]["unity"]["dump"]["namespaces"])
    n_paths = len(rd["engine_details"]["unity"]["bundles"]["paths_sample"])
    side = externalize_large(rd)
    u = rd["engine_details"]["unity"]
    assert u["dump"]["namespaces_total"] == n_ns and len(u["dump"]["namespaces"]) == 100
    assert u["dump"]["namespaces_file"] == "details/unity-namespaces.json"
    assert len(side["details/unity-namespaces.json"]) == n_ns
    assert u["bundles"]["paths_sample_total"] == n_paths and len(u["bundles"]["paths_sample"]) == 50
    assert set(side) == {"details/unity-namespaces.json", "details/unity-bundle-paths.json"}


def test_externalize_noop_for_small_or_missing_data():
    rd = canonicalize(build_report("cocos_lua").to_dict())
    assert externalize_large(rd) == {}
    assert externalize_large({}) == {}


def _normalise(d):
    d = copy.deepcopy(d)
    d["generated_at"] = ""
    d["tool"]["version"] = ""
    for s in d["stages"]:
        s["duration_s"] = 0
    d["config"]["output_dir"] = ""
    return d


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_golden_report_json(name, tmp_path, capsys):
    """Run the real report stage on the fixture (English, so other WPs' i18n files do not matter)."""
    from ipa_analyzer.analyzers.report_stage import ReportStage

    ctx = build_ctx(name, tmp_path, lang="en", formats=("md", "json"))
    res = ReportStage().run(ctx)
    assert res.status.value == "ok", res
    got = _normalise(json.loads((ctx.out_dir / "report.json").read_text(encoding="utf-8")))
    golden = GOLDEN / (name + ".report.json")
    if os.environ.get("IPA_UPDATE_GOLDEN") == "1" or not golden.exists():
        with open(str(golden), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(got, ensure_ascii=False, indent=2) + "\n")
    assert got == json.loads(golden.read_text(encoding="utf-8"))
