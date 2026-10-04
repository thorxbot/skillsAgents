"""il2cpp pre-check aggregation (pure function)."""
from __future__ import annotations

from ipa_analyzer.unity import metadata as um
from ipa_analyzer.unity import precheck as up

PLAIN = {"present": True, "verdict": "no", "version": 24, "reasons": ["magic_ok"]}
SUPPORT = um.backend_support(24)


def pre(**kw):
    args = dict(backend="il2cpp", binary={"path": "b", "slice": "arm64", "encrypted": False}, metadata=dict(PLAIN),
                il2cpp_markers=12, support=SUPPORT, force_dump=False, unity_version="2021.3.16f1")
    args.update(kw)
    return up.run_precheck(**args)


def test_ready():
    r = pre()
    assert r["ready"] and r["error_code"] is None and r["reasons"] == ["ok"] and "il2cppdumper" in r["backends"]


def test_fairplay_blocks_even_with_force():
    r = pre(binary={"path": "b", "slice": "arm64", "encrypted": True}, force_dump=True)
    assert not r["ready"] and r["error_code"] == "E_BINARY_FAIRPLAY"


def test_unknown_encryption_is_a_warning_not_a_block():
    r = pre(binary={"path": "b", "slice": None, "encrypted": None})
    assert r["ready"] and "binary_encryption_unknown" in r["warnings"]


def test_encrypted_metadata_blocks_unless_forced():
    meta = {"present": True, "verdict": "suspected", "version": 24, "reasons": ["magic_ok", "string_region_unreadable"]}
    r = pre(metadata=meta)
    assert not r["ready"] and r["error_code"] == "E_METADATA_ENCRYPTED"
    r = pre(metadata=meta, force_dump=True)
    assert r["ready"] and r["forced"] and r["forced_error_code"] == "E_METADATA_ENCRYPTED"
    assert any(w.startswith("forced_past") for w in r["warnings"])


def test_yes_verdict_blocks():
    r = pre(metadata={"present": True, "verdict": "yes", "version": None, "reasons": ["magic_mismatch"]})
    assert r["error_code"] == "E_METADATA_ENCRYPTED"


def test_version_out_of_every_range_is_reported_as_unsupported_not_encrypted():
    meta = {"present": True, "verdict": "suspected", "version": 200, "reasons": ["magic_ok", "version_out_of_range"]}
    r = pre(metadata=meta, support=um.backend_support(200))
    assert not r["ready"] and r["error_code"] == "E_METADATA_VERSION_UNSUPPORTED"


def test_no_backend_supports_version_even_when_plain():
    r = pre(metadata={"present": True, "verdict": "no", "version": 36, "reasons": ["magic_ok"]},
            support={"supported_by": [], "needs_unity_version": []})
    assert r["error_code"] == "E_METADATA_VERSION_UNSUPPORTED" and not r["ready"]


def test_backend_needing_unity_version_without_it():
    sup = um.backend_support(39)           # cpp2il + redux; only cpp2il needs the Unity version
    meta = {"present": True, "verdict": "no", "version": 39, "reasons": ["magic_ok"]}
    assert pre(metadata=meta, support=sup, unity_version=None)["ready"]
    only_cpp2il = {"supported_by": ["cpp2il"], "needs_unity_version": ["cpp2il"]}
    r = pre(metadata=meta, support=only_cpp2il, unity_version=None)
    assert not r["ready"] and "backend_needs_unity_version" in r["reasons"]


def test_missing_markers_only_warn():
    r = pre(il2cpp_markers=0)
    assert r["ready"] and "no_il2cpp_markers_in_binary" in r["warnings"]
    assert "no_il2cpp_markers_in_binary" not in pre(il2cpp_markers=None)["warnings"]


def test_not_applicable_cases():
    assert pre(backend="mono")["reasons"] == ["backend_not_il2cpp"]
    assert pre(metadata={"present": False})["reasons"] == ["metadata_missing"]
    assert pre(binary={"path": None, "encrypted": None})["reasons"] == ["binary_missing"]
