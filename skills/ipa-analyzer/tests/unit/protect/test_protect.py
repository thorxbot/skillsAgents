from __future__ import annotations

import json
import plistlib

import pytest

from fixtures.macho_builder import build_macho
from ipa_analyzer.models import Status, Verdict
from ipa_analyzer.protect import load_rules, score_hits, summarize_fairplay, summarize_obfuscation

SIG = dict(identifier="com.example.t", team_id="ABCDE12345", entitlements={"get-task-allow": False})


def bins(*specs):
    out = []
    for path, role, enc in specs:
        out.append({"path": path, "role": role, "slices": [{"arch": "arm64", "encrypted": enc}]})
    return {"binaries": out}


# ---- FairPlay summary (pure) ----------------------------------------------------------------
def test_fairplay_all_encrypted_states_consequence():
    fp = summarize_fairplay(bins(("a/T", "main", True), ("a/F", "framework", True)), True)
    assert fp.verdict == Verdict.YES and fp.scope == "all" and fp.main_encrypted is True and fp.total_binaries == 2
    assert "il2cpp dump is blocked" in fp.text_en and "il2cpp dump" in fp.text_zh and "decrypted IPA" in fp.remediation
    assert fp.encrypted_binaries == ["a/F", "a/T"]


def test_fairplay_mixed_main_plain_framework_encrypted():
    fp = summarize_fairplay(bins(("a/T", "main", False), ("a/F", "framework", True)), True)
    assert fp.verdict == Verdict.YES and fp.scope == "partial" and fp.main_encrypted is False
    assert "readable" in fp.text_en and fp.case == "partial_other"


def test_fairplay_partial_main_encrypted():
    fp = summarize_fairplay(bins(("a/T", "main", True), ("a/F", "framework", False)), None)
    assert fp.scope == "partial" and fp.main_encrypted is True and fp.case == "main_encrypted"


def test_fairplay_sc_info_with_cryptid_zero_means_decrypted_container():
    fp = summarize_fairplay(bins(("a/T", "main", False), ("a/F", "framework", False)), True)
    assert fp.verdict == Verdict.NO and fp.scope == "none" and fp.sc_info_present is True and fp.case == "decrypted_container"
    assert "SC_Info" in fp.text_en and fp.remediation == ""
    plain = summarize_fairplay(bins(("a/T", "main", False)), False)
    assert plain.verdict == Verdict.NO and plain.case == "plain"


def test_fairplay_no_data_is_unknown():
    for m in (None, {}, {"binaries": []}):
        fp = summarize_fairplay(m, None)
        assert fp.verdict == Verdict.UNKNOWN and fp.scope == "unknown"


# ---- stage on synthetic IPAs ----------------------------------------------------------------
STAGES = ("ingest", "inventory", "meta", "macho", "protect")


def run_protect(run_stages, files, **kw):
    ctx = run_stages(files, stages=STAGES, **kw)
    return ctx, ctx.results["protect"], {f.id: f for f in ctx.stage_results["protect"].findings}


def test_stage_cryptid_1_main_and_framework(run_stages):
    files = {"T": build_macho(encrypted=True, code_signature=SIG), "Frameworks/A.framework/A": build_macho(filetype="dylib", encrypted=True)}
    ctx, data, f = run_protect(run_stages, files)
    assert data["fairplay"]["scope"] == "all" and data["fairplay"]["main_encrypted"] is True
    assert f["protect.fairplay"].verdict == Verdict.YES and "decrypted IPA" in f["protect.fairplay"].remediation
    assert set(f) == {"protect.fairplay", "protect.codesign", "protect.stripped", "protect.antidebug", "protect.jailbreak_detect",
                      "protect.obfuscation", "protect.packer"}
    assert f["protect.antidebug"].verdict in (Verdict.UNKNOWN, Verdict.SUSPECTED)       # encrypted: never "no"


def test_stage_cryptid_0_with_sc_info(run_stages):
    files = {"T": build_macho(code_signature=SIG, encryption_info=True), "SC_Info/T.sinf": b"x"}
    ctx, data, f = run_protect(run_stages, files)
    assert data["fairplay"]["scope"] == "none" and data["fairplay"]["sc_info_present"] is True
    assert f["protect.fairplay"].verdict == Verdict.NO and "SC_Info" in f["protect.fairplay"].summary


def test_stage_mixed_main_plain_framework_encrypted(run_stages):
    files = {"T": build_macho(), "Frameworks/E.framework/E": build_macho(filetype="dylib", encrypted=True)}
    ctx, data, f = run_protect(run_stages, files)
    assert data["fairplay"]["scope"] == "partial" and data["fairplay"]["main_encrypted"] is False
    assert data["fairplay"]["encrypted_binaries"] == [p for p in data["fairplay"]["encrypted_binaries"] if p.endswith("/E")]


def test_codesign_and_hardening(run_stages):
    ctx, data, f = run_protect(run_stages, {"T": build_macho(code_signature=SIG, canary=True, arc=True, stripped=True)})
    cs = data["codesign"]
    assert cs["signed"] is True and cs["team_id"] == "ABCDE12345" and cs["get_task_allow"] is False
    assert cs["signature_type"] in ("cms", "adhoc", "unknown")
    assert data["hardening"]["main"]["stripped"] is True and data["hardening"]["main"]["pie"] is True
    assert data["hardening"]["main"]["stack_canary"] is True and data["hardening"]["main"]["arc"] is True
    assert f["protect.codesign"].verdict == Verdict.YES and f["protect.stripped"].verdict == Verdict.YES
    ctx2, data2, f2 = run_protect(run_stages, {"T": build_macho()})
    assert data2["codesign"]["signed"] is False and f2["protect.codesign"].verdict == Verdict.NO
    assert data2["hardening"]["main"]["stripped"] is False and f2["protect.stripped"].verdict == Verdict.NO


def test_get_task_allow_true_reported(run_stages):
    sig = dict(identifier="x", team_id="T1", entitlements={"get-task-allow": True})
    ctx, data, f = run_protect(run_stages, {"T": build_macho(code_signature=sig)})
    assert data["codesign"]["get_task_allow"] is True


# ---- anti-debug / jailbreak ---------------------------------------------------------------
def test_no_features_means_no_hits_and_no_verdict_of_yes(run_stages):
    ctx, data, f = run_protect(run_stages, {"T": build_macho(strings=["hello world", "Welcome"], imports=["_printf", "_malloc"])})
    assert data["antidebug"]["hits"] == [] and data["jailbreak_detect"]["hits"] == []
    assert f["protect.antidebug"].verdict == Verdict.NO and f["protect.jailbreak_detect"].verdict == Verdict.NO
    assert f["protect.antidebug"].confidence <= 0.5


def test_antidebug_symbols_suspected_never_yes(run_stages):
    files = {"T": build_macho(imports=["_ptrace", "_dlsym", "_sysctl", "_task_get_exception_ports"], strings=["ptrace"])}
    ctx, data, f = run_protect(run_stages, files)
    assert f["protect.antidebug"].verdict == Verdict.SUSPECTED and f["protect.antidebug"].confidence <= 0.8
    pats = {h["pattern"] for h in data["antidebug"]["hits"]}
    assert {"_ptrace", "_sysctl", "_task_get_exception_ports"} <= pats
    assert "not a conclusion" in f["protect.antidebug"].summary


def test_antidebug_weak_symbols_alone_do_not_trigger(run_stages):
    ctx, data, f = run_protect(run_stages, {"T": build_macho(imports=["_sysctl", "_dlsym", "_getppid"])})
    assert f["protect.antidebug"].verdict == Verdict.UNKNOWN and "weak" in f["protect.antidebug"].summary


def test_encrypted_binary_symbols_still_readable_but_absence_is_unknown(run_stages):
    ctx, data, f = run_protect(run_stages, {"T": build_macho(encrypted=True, imports=["_ptrace"])})
    assert f["protect.antidebug"].verdict == Verdict.SUSPECTED
    ctx2, data2, f2 = run_protect(run_stages, {"T": build_macho(encrypted=True, imports=["_printf"])})
    assert f2["protect.antidebug"].verdict == Verdict.UNKNOWN and "encrypted" in f2["protect.antidebug"].summary
    assert f2["protect.jailbreak_detect"].verdict == Verdict.UNKNOWN


def test_jailbreak_strings_and_query_scheme(run_stages):
    strings = ["/Applications/Cydia.app", "/Library/MobileSubstrate/MobileSubstrate.dylib", "/usr/sbin/sshd"]
    ctx, data, f = run_protect(run_stages, {"T": build_macho(strings=strings)})
    assert f["protect.jailbreak_detect"].verdict == Verdict.SUSPECTED
    assert len(data["jailbreak_detect"]["hits"]) == 3 and f["protect.jailbreak_detect"].confidence <= 0.8
    info = plistlib.dumps({"CFBundleIdentifier": "a.b", "CFBundleName": "T", "CFBundleExecutable": "T",
                           "LSApplicationQueriesSchemes": ["cydia", "weixin"]})
    ctx2, data2, f2 = run_protect(run_stages, {"T": build_macho(encrypted=True, imports=["_printf"])}, info=info)
    assert f2["protect.jailbreak_detect"].verdict == Verdict.SUSPECTED
    assert [h["pattern"] for h in data2["jailbreak_detect"]["hits"]] == ["cydia"]


def test_single_weak_jailbreak_string_is_not_enough(run_stages):
    ctx, data, f = run_protect(run_stages, {"T": build_macho(strings=["/bin/bash"])})
    assert f["protect.jailbreak_detect"].verdict == Verdict.UNKNOWN


def test_score_hits_never_exceeds_suspected():
    rules = load_rules()
    hits = [{"kind": "string", "pattern": p, "weight": 1.0, "ref": "x"} for p in ("a", "b", "c", "d")]
    verdict, conf, score, case = score_hits(hits, rules, readable=True, scanned=True)
    assert verdict == Verdict.SUSPECTED and conf <= 0.8 and score == 1.0 and case == "hit"
    assert score_hits([], rules, readable=True, scanned=False)[0] == Verdict.UNKNOWN


def test_rules_file_is_sourced_and_loadable():
    rules = load_rules()
    assert rules.warnings == [] and "_ptrace" in rules.ad_symbols and "/Applications/Cydia.app" in rules.jb_strings
    doc = json.loads((__import__("ipa_analyzer.util.paths", fromlist=["x"]).resource_dir("data") / "protectors.json").read_text("utf-8"))
    for section in (doc["antidebug"]["symbols"], doc["antidebug"]["strings"], doc["jailbreak_detect"]["strings"],
                    doc["jailbreak_detect"]["symbols"], doc["jailbreak_detect"]["query_schemes"]):
        assert all(r["sources"] and r["weight"] > 0 for r in section)


def test_obfuscation_summary_uses_unity_dump_only():
    rules = load_rules().obfuscation
    assert summarize_obfuscation(None, rules)[0] == Verdict.UNKNOWN
    hi = {"dump": {"ok": True, "summary": {"obfuscation": {"score": 0.7, "level": "high"}}}}
    lo = {"dump": {"ok": True, "summary": {"obfuscation": {"score": 0.05, "level": "none"}}}}
    assert summarize_obfuscation(hi, rules)[0] == Verdict.SUSPECTED and summarize_obfuscation(lo, rules)[0] == Verdict.NO


def test_missing_macho_is_partial_not_crash(run_stages):
    ctx = run_stages({"T": build_macho()}, stages=("ingest", "inventory", "protect"))
    st = ctx.stage_results["protect"]
    assert st.status == Status.PARTIAL and ctx.results["protect"]["fairplay"]["scope"] == "unknown"
