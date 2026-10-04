"""The two write-back loops SKILL.md tells the agent to perform must really work end to end:

* unknown library -> entry in ``libs.user.json`` -> next run identifies it (``--libs-user`` or the user data folder)
* in-house engine -> ``engines.user.d/<id>.json`` -> next run names the engine and no longer says "custom"
"""
from __future__ import annotations

import json
import plistlib

from fixtures.e2e_support import run_cli
from fixtures.ipa_builder import build_ipa
from fixtures.macho_builder import build_macho


def native_app_with_unknown_sdk(path):
    fw = lambda n: build_macho(arch="arm64", filetype="dylib", strings=[n], code_signature=True)    # noqa: E731
    files = {"Info.plist": plistlib.dumps({"CFBundleExecutable": "Notes", "CFBundleIdentifier": "com.example.notes"}),
             "Notes": build_macho(arch="arm64", strings=["x"], objc_classes=["AppDelegate"]),
             "Frameworks/AcmeQuuxKit.framework/AcmeQuuxKit": fw("AcmeQuuxKit"),
             "Frameworks/FirebaseCore.framework/FirebaseCore": fw("FirebaseCore")}
    return build_ipa(path, files, app_name="Notes")


def test_unknown_library_is_listed_without_a_guessed_purpose_then_resolved_by_libs_user_json(tmp_path, runs):
    ipa = native_app_with_unknown_sdk(tmp_path / "notes.ipa")
    first = run_cli(ipa, tmp_path / "o1", runs.home, [], name="unknown-lib")
    unknown = {u["name"]: u for u in first.report["summary"]["libs"]["unknown"]}
    assert "AcmeQuuxKit" in unknown and first.verdict("libs.unknown") == "unknown"
    assert not any(i["id"].startswith("acme") for i in first.report["libraries"])         # no invented purpose
    assert "libs.user.json" in first.finding("libs.unknown")["remediation"]               # the instruction SKILL.md relies on

    user = tmp_path / "libs.user.json"
    user.write_text(json.dumps({"version": 1, "libs": [{
        "id": "acme_quux", "name": "Acme Quux Kit", "vendor": "Acme", "category": "other",
        "purpose_zh": "示例:Acme 的内部工具包(测试夹具)", "purpose_en": "Acme internal toolkit (test fixture)",
        "tags": [], "match": {"framework": ["AcmeQuuxKit"]}, "sources": ["https://example.invalid/acmequuxkit"]}]}),
        encoding="utf-8")
    second = run_cli(ipa, tmp_path / "o2", runs.home, ["--libs-user", str(user)], name="resolved-lib")
    assert second.returncode == 0
    items = {i["id"]: i for i in second.report["libraries"]}
    assert items["acme_quux"]["purpose_en"].startswith("Acme internal") and items["acme_quux"]["confidence"] >= 0.5
    assert "AcmeQuuxKit" not in {u["name"] for u in second.report["summary"]["libs"]["unknown"]}
    assert "firebase_core" in items                                                       # shipped entries are kept


def test_libs_user_json_in_the_user_data_folder_is_picked_up_without_a_flag(tmp_path, runs):
    ipa = native_app_with_unknown_sdk(tmp_path / "notes.ipa")
    home = tmp_path / "ipa-home"
    home.mkdir()
    (home / "libs.user.json").write_text(json.dumps([{
        "id": "acme_quux", "name": "Acme Quux Kit", "vendor": "Acme", "category": "other", "purpose_zh": "示例", "purpose_en": "example",
        "tags": [], "match": {"framework": ["AcmeQuuxKit"]}, "sources": ["https://example.invalid/x"]}]), encoding="utf-8")
    r = run_cli(ipa, tmp_path / "o", home, [], name="userdir-lib")
    assert "acme_quux" in {i["id"] for i in r.report["libraries"]}


def test_malformed_user_files_only_warn(tmp_path, runs):
    ipa = native_app_with_unknown_sdk(tmp_path / "notes.ipa")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    r = run_cli(ipa, tmp_path / "o", runs.home, ["--libs-user", str(bad)], name="bad-user")
    assert r.returncode == 0 and r.stage("libs")["status"] in ("ok", "partial")
    assert any("libs" in w for w in r.report["warnings"])


def test_custom_engine_becomes_a_named_engine_after_writing_engines_user_d(tmp_path, runs):
    ipa = runs.ipas["custom_engine"]
    first = runs.cli("custom_engine")
    assert first.verdict("engine.custom") == "yes" and first.details["detect"]["primary"] is None

    d = tmp_path / "engines.user.d"
    d.mkdir()
    (d / "mystic_engine.json").write_text(json.dumps({
        "id": "mystic_engine", "name": "Mystic Engine (user rule)", "family": "in_house", "kind": "game_engine",
        "confirm_threshold": 0.8,
        "signals": [{"type": "file", "pattern": "res/data.pak", "weight": 0.5},
                    {"type": "symbol", "pattern": "luaL_newstate", "weight": 0.2},
                    {"type": "dylib", "pattern": "Metal.framework/Metal", "weight": 0.2}],
        "notes": "confirmed by the user on a test fixture", "sources": ["user:test"]}), encoding="utf-8")
    second = run_cli(ipa, tmp_path / "o2", runs.home, ["--engines-user", str(d)], name="user-engine")
    assert second.returncode == 0, second.proc.stderr[-800:]
    primary = second.details["detect"]["primary"]
    assert primary and primary["id"] == "mystic_engine" and primary["confirmed"], second.details["detect"]["candidates"][:3]
    assert second.verdict("engine.custom") == "no"                                       # now a known (user-defined) engine
    assert second.verdict("engine.primary") == "yes"
