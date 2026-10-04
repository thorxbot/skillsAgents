from __future__ import annotations

import json

import pytest

from ipa_analyzer.meta import provision as pv


def _summary(builders, kind, **over):
    raw = pv.parse_provision(builders.fake_cms(builders.provision_plist(kind, **over)))
    assert raw is not None
    return pv.summarize_provision(raw)


def test_cms_slice_and_parse(builders):
    raw = pv.parse_provision(builders.fake_cms(builders.provision_plist("appstore")))
    assert raw["Name"] == "Foo Profile"
    blob = pv.extract_plist_bytes(builders.fake_cms({"a": 1}))
    assert blob.startswith(b"<?xml") and blob.endswith(b"</plist>")


@pytest.mark.parametrize("data", [b"", b"\x30\x82\x00\x00no xml here", b"<?xml version='1.0'?><plist><dict>",
                                  b"<?xml?>garbage</plist>", b"\xff" * 100])
def test_garbage_profile_is_none(data):
    assert pv.parse_provision(data) is None


def test_bare_plist_is_accepted(builders):
    import plistlib
    assert pv.parse_provision(plistlib.dumps({"Name": "x"}))["Name"] == "x"


def test_summary_fields_and_no_udid_leak(builders):
    s = _summary(builders, "development")
    assert s["present"] and s["name"] == "Foo Profile" and s["team_name"] == "Example Team"
    assert s["team_id"] == "TEAM123456" and s["app_id_prefix"] == "TEAM123456"
    assert s["creation_date"] == "2024-01-02T03:04:05Z" and s["expiration_date"] == "2025-01-02T03:04:05Z"
    assert s["device_count"] == 2 and len(s["device_hash_prefixes"]) == 2 and s["provisions_all_devices"] is False
    assert s["entitlements"]["get-task-allow"] is True
    assert s["entitlements"]["com.apple.developer.associated-domains"] == ["applinks:example.com"]
    text = json.dumps(s)
    assert builders.UDID_A not in text and builders.UDID_B not in text
    assert builders.UDID_A.lower() not in text.lower()
    assert pv.device_hash_prefix(builders.UDID_A) in s["device_hash_prefixes"]
    assert pv.device_hash_prefix(" " + builders.UDID_A.upper() + " ") == pv.device_hash_prefix(builders.UDID_A)
    assert s["extra"]["certificate_count"] == 1


def test_many_devices_are_capped():
    raw = {"ProvisionedDevices": ["%040x" % i for i in range(120)], "Entitlements": {"get-task-allow": False}}
    s = pv.summarize_provision(raw)
    assert s["device_count"] == 120 and len(s["device_hash_prefixes"]) == pv.MAX_DEVICE_PREFIXES
    assert s["extra"]["device_hash_prefixes_truncated"] is True


def test_summary_tolerates_odd_types():
    s = pv.summarize_provision({"Name": 5, "TeamIdentifier": "T1", "ProvisionedDevices": "nope", "Entitlements": [1],
                                "ExpirationDate": "2030-01-01"})
    assert s["team_id"] == "T1" and s["device_count"] == 0 and s["entitlements"] == {} and s["expiration_date"] == "2030-01-01"


@pytest.mark.parametrize("kind,expected,conf_min", [("development", "development", 0.85), ("adhoc", "adhoc", 0.85),
                                                    ("enterprise", "enterprise", 0.85), ("appstore", "appstore", 0.7)])
def test_provision_kind(builders, kind, expected, conf_min):
    k = pv.provision_kind(_summary(builders, kind))
    assert k["kind"] == expected and k["confidence"] >= conf_min


def test_devices_without_get_task_allow_is_ambiguous(builders):
    s = _summary(builders, "adhoc")
    s["entitlements"].pop("get-task-allow")
    k = pv.provision_kind(s)
    assert k["kind"] == "unknown" and set(k["alternatives"]) == {"development", "adhoc"}


def test_distribution_matrix(builders):
    d = lambda kind: pv.summarize_provision(builders.provision_plist(kind))  # noqa: E731
    r = pv.classify_distribution(d("development"), has_code_signature=True)
    assert (r["type"], r["verdict"].value) == ("development", "yes")
    r = pv.classify_distribution(d("adhoc"), has_code_signature=True)
    assert r["type"] == "adhoc"
    r = pv.classify_distribution(d("enterprise"), has_code_signature=True)
    assert r["type"] == "enterprise"
    r = pv.classify_distribution(d("appstore"), has_code_signature=True)
    assert (r["type"], r["verdict"].value) == ("appstore", "suspected") and r["confidence"] == 0.75
    r = pv.classify_distribution(d("appstore"), store_markers=["SC_Info"], has_code_signature=True)
    assert r["type"] == "appstore" and r["verdict"].value == "yes" and r["confidence"] >= 0.9
    # store artefacts + ad hoc profile -> re-signed hint, downgraded
    r = pv.classify_distribution(d("adhoc"), store_markers=["iTunesMetadata.plist"], has_code_signature=True)
    assert r["type"] == "adhoc" and r["verdict"].value == "suspected" and r["repackaged_hint"] and "appstore" in r["alternatives"]
    # no profile
    # container-layer evidence cannot prove the origin: never better than suspected / 0.6-0.7
    r = pv.classify_distribution(None, store_markers=["iTunesMetadata.plist", "SC_Info"], has_code_signature=True)
    assert (r["type"], r["verdict"].value, r["confidence"]) == ("appstore", "suspected", 0.65)
    r = pv.classify_distribution(None, store_markers=["iTunesMetadata.plist", "SC_Info"], has_code_signature=True,
                                 store_names_consistent=True)
    assert (r["type"], r["verdict"].value, r["confidence"]) == ("appstore", "suspected", 0.7)
    assert "unsigned_or_repackaged" in r["alternatives"]
    assert any(e.ref == "container_evidence_only" and "cannot prove" in e.detail for e in r["evidence"])
    r = pv.classify_distribution(None, store_markers=["SC_Info"], has_code_signature=True, store_names_consistent=True)
    assert (r["verdict"].value, r["confidence"]) == ("suspected", 0.6)
    r = pv.classify_distribution(None, store_markers=["iTunesMetadata.plist"], has_code_signature=True)
    assert (r["verdict"].value, r["confidence"]) == ("suspected", 0.6)
    r = pv.classify_distribution(None, store_markers=["SC_Info"], has_code_signature=False)
    assert r["verdict"].value == "suspected" and "unsigned_or_repackaged" in r["alternatives"]
    r = pv.classify_distribution(None, has_code_signature=False)
    assert (r["type"], r["verdict"].value) == ("unsigned_or_repackaged", "suspected")
    r = pv.classify_distribution(None, has_code_signature=True)
    assert r["type"] == "unsigned_or_repackaged" and r["verdict"].value == "suspected" and "appstore" in r["alternatives"]
    r = pv.classify_distribution(None, prov_unreadable=True, store_markers=["SC_Info"])
    assert r["type"] == "unknown" and r["verdict"].value == "unknown"
