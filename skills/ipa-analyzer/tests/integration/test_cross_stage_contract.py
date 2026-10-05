"""Cross-stage consistency: the frozen contract (docs/CONTRACT-FREEZE.md) against the running code.

* stage names / dependencies (section 2) -- also parsed from the document itself when the repository ``docs/`` is next to the skill
* ``ctx.results`` keys follow the stage status and have the documented shape (section 4)
* every Finding ID (frozen table, static scan of the source, observed in the 28 end-to-end runs) has Chinese text
* the library entry point and the CLI produce the same findings
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Dict, List, Set

import pytest

from ipa_analyzer import pipeline
from ipa_analyzer.util.paths import resource_dir
from fixtures.e2e_support import GOOD, STAGE_ORDER

SKILL_ROOT = Path(__file__).resolve().parents[2]
SRC = SKILL_ROOT / "src" / "ipa_analyzer"
FREEZE_DOC = SKILL_ROOT.parent.parent / "docs" / "CONTRACT-FREEZE.md"

# CONTRACT-FREEZE section 2 (requires, after)
STAGES = {
    "ingest": ((), ()),
    "inventory": (("ingest",), ()),
    "meta": (("ingest",), ()),
    "macho": (("inventory",), ()),
    "engine.fingerprint": (("inventory",), ("macho", "meta")),
    "engine.detect": (("inventory",), ("macho", "meta", "engine.fingerprint")),
    "engine.other": (("engine.detect",), ()),
    "cocos.decrypt": (("inventory",), ("macho", "engine.other")),
    "engine.unity": (("engine.detect", "inventory"), ("macho", "meta")),
    "engine.unity.hotfix": (("engine.unity",), ("inventory", "macho")),
    "libs": (("inventory",), ("macho", "engine.fingerprint", "engine.unity", "engine.unity.hotfix", "engine.other")),
    "protect": (("inventory",), ("macho", "engine.unity", "engine.unity.hotfix", "engine.other", "libs")),
    "classify": ((), ("meta", "engine.detect", "engine.fingerprint", "libs")),
}

# CONTRACT-FREEZE section 5 (frozen) + the additions that section 13 / the work packages made (all need zh text)
FROZEN_FINDINGS = {
    "meta": ["meta.identity", "meta.distribution", "meta.permissions", "meta.fairplay_container", "meta.signature_integrity"],
    "macho": ["macho.summary"],
    "engine.fingerprint": ["engine.fingerprint", "engine.container.unknown"],
    "engine.detect": ["engine.primary", "engine.language", "engine.custom", "engine.wrapper"],
    "engine.other": ["engine.pak.encrypted", "engine.script.encrypted", "engine.resource.encrypted", "engine.hermes",
                     "engine.flutter_aot", "engine.cocos.variant"],
    "cocos.decrypt": ["engine.cocos.decrypt"],
    "engine.unity": ["unity.detected", "unity.version", "unity.backend", "unity.metadata.present", "unity.metadata.encrypted",
                     "unity.binary.fairplay", "unity.il2cpp.precheck", "unity.il2cpp.dump", "unity.il2cpp.names_obfuscated",
                     "unity.assetbundle.encryption", "unity.mono.dll_encrypted"],
    "engine.unity.hotfix": ["unity.hotfix.framework", "unity.hotfix.lua", "unity.hotfix.lua_version", "unity.hotfix.csharp_dll",
                            "unity.hotfix.js", "unity.hotfix.resource_update", "unity.hotfix.script_protection"],
    "libs": ["libs.summary", "libs.unknown"],
    "protect": ["protect.fairplay", "protect.codesign", "protect.stripped", "protect.antidebug", "protect.jailbreak_detect",
               "protect.obfuscation", "protect.packer"],
    "classify": ["classify.category"],
    "inventory": ["inventory.summary"],                      # section 13.3 addition
}
ALL_FROZEN = {fid for ids in FROZEN_FINDINGS.values() for fid in ids}
ID_RE = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)+$")

# CONTRACT-FREEZE section 4: keys that must exist in ctx.results[stage] when the stage is ok / partial
RESULT_KEYS = {
    "ingest": {"kind", "path", "size", "sha256", "app_root", "app_name_dir", "entries", "warnings"},
    "inventory": {"files", "files_total", "files_truncated", "inventory_file", "by_category", "by_ext", "top_files",
                  "localizations", "archives", "nested_units", "tree", "structure_hints"},
    "meta": {"identity", "distribution", "provision", "itunes", "fairplay_container", "permissions", "url_schemes",
             "query_schemes", "ats", "extensions", "background_modes", "capabilities", "sdk", "redaction", "warnings"},
    "macho": {"binaries", "summary"},
    "engine.fingerprint": {"render", "shader_formats", "script_vms", "physics", "audio", "animation", "network",
                           "asset_formats", "containers", "host", "summary_text"},
    "engine.detect": {"primary", "candidates", "wrapper", "custom", "languages", "is_game_engine", "extra"},
    "engine.other": {"_checkers"},
    "cocos.decrypt": {"enabled", "sign", "candidates", "key_recovery"},
    "engine.unity": {"version", "backend", "binary", "metadata", "bundles", "mono", "precheck", "dump"},
    "engine.unity.hotfix": {"frameworks", "lua", "js", "csharp", "resource_update", "storage", "script_protection", "summary_text"},
    "libs": {"items", "unknown", "by_category", "privacy_tags"},
    "protect": {"fairplay", "codesign", "hardening", "antidebug", "jailbreak_detect", "obfuscation", "packer"},
    "classify": {"category", "subcategory", "confidence", "scores", "evidence", "runner_up"},
    "report": {"files", "formats"},
}
NESTED_KEYS = {
    ("macho", "binaries"): {"path", "rel", "role", "kind", "size", "is_fat", "slices", "dylibs", "rpaths", "parse_warnings"},
    ("engine.detect", "custom"): {"verdict", "confidence", "evidence", "profile_ref", "conditions", "next_steps", "deviations",
                                  "open_source_base"},
    ("engine.fingerprint", "host"): {"thin_uikit_shell", "cpp_ratio", "objc_swift_ratio", "main_loop_hints"},
    ("engine.unity", "metadata"): {"path", "present", "version", "header_ok", "entropy", "string_region_ok", "string_region",
                                   "verdict", "evidence"},
    ("engine.unity", "precheck"): {"ready", "error_code", "reasons"},
    ("engine.unity.hotfix", "lua"): {"runtime_versions", "bytecode", "files", "dialect_hints", "consistency", "custom_lua_suspected"},
    ("engine.unity.hotfix", "script_protection"): {"lua", "js", "csharp"},
    ("protect", "fairplay"): {"verdict", "scope", "encrypted_binaries", "total_binaries", "main_encrypted", "sc_info_present"},
    ("protect", "codesign"): {"signed", "team_id", "signature_type", "get_task_allow", "entitlements_keys"},
}
SLICE_KEYS = {"arch", "filetype", "platform", "min_os", "sdk", "uuid", "encrypted", "cryptid", "cryptsize", "is_pie", "stripped",
              "has_swift", "has_objc", "has_cpp", "signed", "team_id", "entitlements_keys"}
REPORT_TOP = {"schema_version", "tool", "generated_at", "input", "app", "classification", "structure", "resources", "libraries",
              "protection", "engine_details", "privacy", "stages", "findings", "warnings", "redaction"}
SAMPLE = ["unity_il2cpp_plain", "unity_xlua_lua53", "custom_engine", "cocos_lua_xxtea", "native_swift_app", "media_app",
          "flutter_app", "unity_il2cpp_encrypted_binary"]


def zh_catalog() -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    for p in sorted((Path(resource_dir("data")) / "i18n" / "zh").glob("*.json")):
        out.update(json.loads(p.read_text(encoding="utf-8")))
    return out


def static_finding_ids() -> Set[str]:
    """First argument / ``id=`` of every ``Finding(...)`` call in the source that is a plain string literal."""
    found: Set[str] = set()
    for f in SRC.rglob("*.py"):
        if f.name == "models.py":
            continue
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) == "Finding":
                cands = list(node.args[:1]) + [kw.value for kw in node.keywords if kw.arg == "id"]
                for c in cands:
                    if isinstance(c, ast.Constant) and isinstance(c.value, str):
                        found.add(c.value)
    return found


# -------------------------------------------------------------------------------------------- stage table
def test_stage_table_matches_the_frozen_contract():
    reg = pipeline.ensure_analyzers_loaded()
    assert not reg.import_failures
    assert set(reg.names()) == set(STAGES) | {"report"}
    for name, (req, aft) in STAGES.items():
        spec = reg.get(name)
        assert (tuple(spec.requires), tuple(spec.after)) == (req, aft), name
        assert spec.always_run is False
    rep = reg.get("report")
    assert rep.always_run and rep.requires == () and set(rep.after) == set(STAGES)
    assert reg.order() == STAGE_ORDER


@pytest.mark.skipif(not FREEZE_DOC.is_file(), reason="repository docs/ not next to the skill (installed copy)")
def test_stage_table_matches_the_document_text():
    text = FREEZE_DOC.read_text(encoding="utf-8")
    sec = text.split("## 2. 阶段表", 1)[1].split("\n## 3.", 1)[0]
    rows = {}
    for line in sec.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 5 and cells[0].startswith("`") and cells[1].endswith(".py"):
            names = lambda c: tuple(x.strip(" `") for x in re.split(r"[,、]", c) if x.strip(" `") not in ("", "–", "-"))  # noqa: E731
            rows[cells[0].strip("`")] = (names(cells[3]), names(cells[4]))
    assert set(rows) == set(STAGES) | {"report"}
    for name, (req, aft) in STAGES.items():
        assert rows[name] == (req, aft), name
    assert "(`always_run=True`)" in text or "always_run=True" in text


@pytest.mark.skipif(not FREEZE_DOC.is_file(), reason="repository docs/ not next to the skill (installed copy)")
def test_frozen_finding_table_matches_the_document_text():
    text = FREEZE_DOC.read_text(encoding="utf-8")
    sec = text.split("## 5. Finding ID 表", 1)[1].split("\n## 6.", 1)[0]
    doc_ids = set(re.findall(r"`([a-z0-9_]+(?:\.[a-z0-9_]+)+)`", sec.split("ID 格式", 1)[0]))
    doc_ids -= {"unity.hotupdate"}                           # named as the replaced legacy ID
    frozen_in_doc = {f for f in ALL_FROZEN if f != "inventory.summary"}
    assert doc_ids == frozen_in_doc, (sorted(doc_ids ^ frozen_in_doc))


# --------------------------------------------------------------------------------------- ctx.results keys
@pytest.mark.parametrize("name", SAMPLE)
def test_results_keys_follow_stage_status_and_shape(runs, name):
    ctx = runs.lib(name)
    status = {n: r.status.value for n, r in ctx.stage_results.items()}
    assert list(ctx.stage_results) == STAGE_ORDER
    keys = set(ctx.results)
    expected = {n for n, s in status.items() if s in ("ok", "partial")}
    assert keys == expected, (sorted(keys ^ expected), status)
    for stage, required in RESULT_KEYS.items():
        if stage in keys:
            missing = required - set(ctx.results[stage])
            assert not missing, (name, stage, sorted(missing))
    for (stage, key), required in NESTED_KEYS.items():
        if stage in keys and ctx.results[stage].get(key):
            obj = ctx.results[stage][key]
            for item in (obj if isinstance(obj, list) else [obj]):
                assert required <= set(item), (name, stage, key, sorted(required - set(item)))
    for b in (ctx.results["macho"]["binaries"] if "macho" in keys else []):
        for s in b["slices"]:
            assert SLICE_KEYS <= set(s), (name, sorted(SLICE_KEYS - set(s)))
    json.dumps(dict(ctx.results.items()))                    # everything is JSON-serialisable


def test_unity_read_alias_and_skipped_stages_have_no_key(runs):
    unity = runs.lib("unity_il2cpp_plain")
    assert unity.results["unity"] is unity.results["engine.unity"] and "unity" not in list(unity.results)
    other = runs.lib("flutter_app")
    assert "engine.unity" not in other.results and other.results.get("engine.unity") is None
    assert other.stage_status("engine.unity").value == "skipped" and other.stage_results["engine.unity"].reason


def test_stage_paths_are_archive_names_and_outputs_are_relative(runs):
    ctx = runs.lib("unity_il2cpp_plain")
    for b in ctx.results["macho"]["binaries"]:
        assert b["path"].startswith("Payload/Game.app/") and not b["path"].startswith("/")
        assert ctx.source.stat(b["path"]).size == b["size"]            # usable as a source key
    assert ctx.results["inventory"]["inventory_file"] == "inventory.json" and (ctx.out_dir / "inventory.json").is_file()
    unity = ctx.results["engine.unity"]
    assert unity["binary"]["path"].startswith("Payload/Game.app/Frameworks/UnityFramework.framework/")
    assert unity["metadata"]["path"].endswith("global-metadata.dat") and unity["dump"]["out_dir"] == "il2cpp"


def test_report_json_top_level_matches_the_contract(runs):
    r = runs.cli("unity_il2cpp_plain")
    assert set(r.report) - {"summary", "artifacts", "config", "details"} == REPORT_TOP
    assert set(r.report["engine_details"]) >= {"fingerprint", "detect", "unity"} and "hotfix" in r.report["engine_details"]["unity"]
    assert {"tree", "nested_units", "binaries", "languages", "engine"} <= set(r.report["structure"])
    assert set(r.report["protection"]) >= {"findings"} and set(r.report["privacy"]) >= {"permissions", "url_schemes",
                                                                                         "query_schemes", "ats", "trackers"}
    assert all(f["id"] in {x["id"] for x in r.report["findings"]} for f in r.report["protection"]["findings"])
    assert {"report.json", "report.md"} <= set(r.report["artifacts"])
    assert "libs" in r.report["summary"] and {"unknown", "by_category", "privacy_tags"} <= set(r.report["summary"]["libs"])


# ----------------------------------------------------------------------------------------- Finding IDs / i18n
def observed_finding_ids(runs) -> Set[str]:
    ids: Set[str] = set()
    for name in GOOD:
        ids |= {f["id"] for f in runs.cli(name).report["findings"]}
    return ids


def test_all_finding_ids_have_chinese_text(runs):
    zh = zh_catalog()
    sets = {"frozen (CONTRACT-FREEZE 5)": ALL_FROZEN, "static scan of Finding(...) calls": static_finding_ids(),
            "observed in the 24 end-to-end runs": observed_finding_ids(runs)}
    problems: List[str] = []
    for label, ids in sets.items():
        for fid in sorted(ids):
            entry = zh.get(fid)
            if not isinstance(entry, dict):
                problems.append("%s: %s has no zh i18n entry" % (label, fid))
            elif not (entry.get("title") and entry.get("summary")):
                problems.append("%s: %s lacks title/summary" % (label, fid))
    assert not problems, "\n" + "\n".join(problems)


def test_finding_ids_are_well_formed_and_frozen_or_documented_additions(runs):
    observed = observed_finding_ids(runs)
    assert all(ID_RE.match(i) for i in observed | static_finding_ids() | ALL_FROZEN)
    unexpected = (observed | static_finding_ids()) - ALL_FROZEN
    assert not unexpected, "IDs that are neither frozen nor listed in this test as additions: %s" % sorted(unexpected)
    # each frozen ID belongs to one stage: no other stage may emit it (cocos / pak / script ids are shared by design)
    shared = {"engine.cocos.variant", "engine.pak.encrypted", "engine.script.encrypted", "engine.resource.encrypted",
              "engine.hermes", "engine.flutter_aot"}
    for name in SAMPLE:
        ctx = runs.lib(name)
        for stage, res in ctx.stage_results.items():
            for f in res.findings:
                owners = [s for s, ids in FROZEN_FINDINGS.items() if f.id in ids]
                assert stage in owners or f.id in shared, (name, stage, f.id)


def test_findings_always_have_valid_verdict_confidence_and_evidence_kinds(runs):
    verdicts = {"yes", "no", "suspected", "unknown", "n/a"}
    for name in GOOD:
        for f in runs.cli(name).report["findings"]:
            assert f["verdict"] in verdicts and 0.0 <= f["confidence"] <= 1.0
            assert f["title"], (name, f["id"])
            for ev in f["evidence"]:
                assert ev["kind"] and "ref" in ev
            if f["id"] in ("protect.antidebug", "protect.jailbreak_detect"):
                assert f["verdict"] in ("suspected", "no", "unknown", "n/a")        # feature hits, never a conclusion


def test_no_untranslated_placeholders_in_reports(runs):
    """A missing translation key or an unfilled ``{param}`` would show up as raw ``report.xxx`` / ``{name}`` text."""
    for name in GOOD:
        for lang in ("zh", "en"):
            md = runs.cli(name).md if lang == "zh" else runs.cli(name, "--lang", "en").md
            text = re.sub(r"`[^`\n]*`", "", md)                         # inline code (paths, ids, raw reasons) is allowed
            assert not re.search(r"\{[a-z_]+\}", text), (name, lang, re.findall(r"\{[a-z_]+\}", text)[:5])
            leaked = [t for t in re.findall(r"\breport\.[a-z_]+(?:\.[a-z_0-9]+)+", text) if t not in ("report.json", "report.md")]
            assert not leaked, (name, lang, leaked[:5])
            assert "None" not in text and "[]" not in text and "{}" not in text, (name, lang)


# ------------------------------------------------------------------------------------------- library == CLI
@pytest.mark.parametrize("name", SAMPLE)
def test_library_and_cli_agree(runs, name):
    ctx = runs.lib(name)
    cli = runs.cli(name)
    lib_report = json.loads((ctx.out_dir / "report.json").read_text(encoding="utf-8"))

    def proj(rep):
        return ([(f["id"], f["verdict"], round(f["confidence"], 2), tuple(f.get("tags", []))) for f in rep["findings"]],
                [(s["name"], s["status"], s.get("reason")) for s in rep["stages"]])

    assert proj(lib_report) == proj(cli.report)
    assert lib_report["input"]["sha256"] == cli.report["input"]["sha256"]
