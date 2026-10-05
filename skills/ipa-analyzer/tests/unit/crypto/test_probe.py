"""Decryptability probe assessment (crypto/probe.py)."""
from __future__ import annotations

from ipa_analyzer.crypto import probe


def F(fid, verdict, engine="", params=None):
    tags = ["engine:%s" % engine] if engine else []
    return {"id": fid, "verdict": verdict, "tags": tags, "params": params or {}}


def by_id(rows, fid):
    return [a for a in rows if a.finding_id == fid]


def test_cocos_scripts_supported_when_binary_readable():
    rows = probe.assess([F("engine.script.encrypted", "yes", "cocos")], fairplay=False)
    assert len(rows) == 1 and rows[0].feasibility == probe.SUPPORTED
    assert "--cocos-decrypt" in rows[0].next_step


def test_cocos_scripts_blocked_under_fairplay():
    rows = probe.assess([F("engine.script.encrypted", "yes", "cocos")], fairplay=True)
    assert rows[0].feasibility == probe.BLOCKED_FAIRPLAY
    assert "decrypted IPA" in rows[0].next_step


def test_cocos_resources_need_key():
    rows = probe.assess([F("engine.resource.encrypted", "yes", "cocos")], fairplay=False)
    assert rows[0].feasibility == probe.NEEDS_KEY and "--pvr-key" in rows[0].next_step


def test_unreal_pak_unsupported():
    rows = probe.assess([F("engine.pak.encrypted", "yes", "unreal")], fairplay=False)
    assert rows[0].feasibility == probe.UNSUPPORTED and "AES" in rows[0].scheme


def test_unity_metadata_unsupported_with_next_step():
    rows = probe.assess([F("unity.metadata.encrypted", "suspected")], fairplay=False)
    assert rows[0].feasibility == probe.UNSUPPORTED and "global-metadata" in rows[0].artifact


def test_unity_hotfix_needs_key():
    rows = probe.assess([F("unity.hotfix.script_protection", "yes", "unity")], fairplay=False)
    assert rows[0].feasibility == probe.NEEDS_KEY


def test_non_cocos_scripts_unknown():
    rows = probe.assess([F("engine.script.encrypted", "suspected", "lua")], fairplay=False)
    assert rows[0].feasibility == probe.UNKNOWN


def test_plain_verdicts_and_noise_are_ignored():
    rows = probe.assess([F("engine.script.encrypted", "no", "cocos"),
                         F("engine.cocos.variant", "yes", "cocos"),
                         F("meta.identity", "n/a")], fairplay=False)
    assert rows == []


def test_sorted_most_actionable_first():
    rows = probe.assess([F("engine.pak.encrypted", "yes", "unreal"),           # unsupported
                         F("engine.script.encrypted", "yes", "cocos"),         # supported
                         F("engine.resource.encrypted", "yes", "cocos")], fairplay=False)  # needs_key
    assert [a.feasibility for a in rows] == [probe.SUPPORTED, probe.NEEDS_KEY, probe.UNSUPPORTED]


def test_fairplay_detection_helper():
    assert probe.fairplay_encrypted([F("protect.fairplay", "yes")]) is True
    assert probe.fairplay_encrypted([F("unity.binary.fairplay", "yes")]) is True
    assert probe.fairplay_encrypted([F("protect.fairplay", "no")]) is False


def test_evidence_extracted_from_params():
    rows = probe.assess([F("engine.resource.encrypted", "yes", "cocos",
                           {"samples": ["res/a.ccz", "res/b.ccz"]})], fairplay=False)
    assert rows[0].evidence == ["res/a.ccz", "res/b.ccz"]
