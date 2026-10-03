from __future__ import annotations

import hashlib
import struct

import pytest

from fixtures.macho_builder import build_code_signature, build_macho
from ipa_analyzer.macho import parse, parse_code_signature

ENT = {"application-identifier": "ABCDE12345.com.example.app", "get-task-allow": False,
       "com.apple.developer.team-identifier": "ABCDE12345", "keychain-access-groups": ["ABCDE12345.*"]}


def test_adhoc_signature():
    sig = parse_code_signature(build_code_signature(identifier="com.example.adhoc"))
    assert sig.parse_error is None and sig.warnings == []
    assert sig.identifier == "com.example.adhoc" and sig.team_id is None and sig.is_adhoc
    assert sig.hash_types == ["sha256"] and sig.flags == 0x2 and sig.signature_kind == "adhoc"
    assert sig.entitlements is None and sig.entitlement_keys == [] and sig.requirements_present
    assert not sig.cms_present and not sig.has_der_entitlements


def test_full_signature_fields():
    blob = build_code_signature("com.example.app", "ABCDE12345", ENT, der_entitlements=True, flags=0, cms=True)
    sig = parse_code_signature(blob)
    assert sig.identifier == "com.example.app" and sig.team_id == "ABCDE12345"
    assert sig.entitlements == ENT and sig.entitlement_keys == sorted(ENT)
    assert sig.entitlements_raw_xml.lstrip().startswith("<?xml") and sig.has_der_entitlements
    assert sig.cms_present and sig.signature_kind == "cms" and not sig.is_adhoc and sig.size == len(blob)
    d = sig.to_dict()
    assert d["team_id"] == "ABCDE12345" and d["entitlement_keys"] == sorted(ENT) and "entitlements" not in d


def test_empty_cms_wrapper_is_not_a_certificate_signature():
    sig = parse_code_signature(build_code_signature(cms="empty"))
    assert not sig.cms_present and sig.signature_kind == "adhoc"


def test_linker_signed():
    sig = parse_code_signature(build_code_signature(flags=0x20002))
    assert sig.is_linker_signed and sig.signature_kind == "linker"


@pytest.mark.parametrize("htype,algo", [(1, "sha1"), (2, "sha256"), (4, "sha384")])
def test_cdhash_is_truncated_digest_of_codedirectory(htype, algo):
    blob = build_code_signature(hash_type=htype)
    cd_off = struct.unpack(">I", blob[16:20])[0]                  # index[0].offset
    cd_len = struct.unpack(">I", blob[cd_off + 4:cd_off + 8])[0]
    expect = getattr(hashlib, algo)(blob[cd_off:cd_off + cd_len]).digest()[:20].hex()
    sig = parse_code_signature(blob)
    assert sig.cdhash == expect and sig.cdhashes == {sig.hash_types[0]: expect} and len(sig.cdhash) == 40


def test_multiple_code_directories_prefers_strongest():
    sig = parse_code_signature(build_code_signature(alt_sha1=True))
    assert sig.hash_types == ["sha256", "sha1"] and set(sig.cdhashes) == {"sha256", "sha1"}
    assert sig.cdhash == sig.cdhashes["sha256"] != sig.cdhashes["sha1"]
    assert [d.slot for d in sig.code_directories] == [0, 0x1000]


@pytest.mark.parametrize("version", [0x20100, 0x20200, 0x20300, 0x20400])
def test_old_directory_versions(version):
    sig = parse_code_signature(build_code_signature("v.test", "TEAMID1234", version=version))
    assert sig.identifier == "v.test" and sig.parse_error is None
    assert sig.team_id == ("TEAMID1234" if version >= 0x20200 else None)


def test_team_id_falls_back_to_entitlement():
    sig = parse_code_signature(build_code_signature(entitlements=ENT, version=0x20100))
    assert sig.team_id == "ABCDE12345"


def test_signature_inside_macho_slice():
    data = build_macho(code_signature=dict(identifier="in.macho", team_id="TEAM123456", entitlements=ENT))
    with parse(data) as mf:
        sl = mf.slices[0]
        assert sl.has_code_signature
        sig = sl.code_signature
        assert sig is sl.code_signature                                   # cached
        assert (sig.identifier, sig.team_id) == ("in.macho", "TEAM123456") and sig.entitlements["get-task-allow"] is False
    with parse(build_macho()) as mf:
        assert mf.slices[0].code_signature is None and not mf.slices[0].has_code_signature


@pytest.mark.parametrize("mutate", [
    lambda b: b[:5],                                                        # too short
    lambda b: b"\x00" * 64,                                                 # wrong magic
    lambda b: b[:20],                                                       # truncated index
    lambda b: b[:12] + struct.pack(">II", 0, 99999) + b[20:],              # slot offset outside the blob
    lambda b: struct.pack(">III", 0xFADE0CC0, len(b), 0xFFFFFFFF) + b[12:],  # absurd entry count
    lambda b: b[:len(b) // 2],                                              # truncated mid-directory
])
def test_malformed_signature_never_raises(mutate):
    sig = parse_code_signature(mutate(build_code_signature("x", "T", ENT, cms=True)))
    assert sig.parse_error or sig.warnings or sig.identifier is not None   # degraded but returned
    sig.to_dict()


def test_bad_entitlements_plist_is_recorded():
    blob = bytearray(build_code_signature(entitlements=ENT))
    pos = bytes(blob).index(b"<?xml")
    blob[pos:pos + 5] = b"<?xmX"
    sig = parse_code_signature(bytes(blob))
    assert sig.entitlements is None and any("entitlements" in w for w in sig.warnings) and sig.identifier


def test_signature_outside_file_degrades():
    data = bytearray(build_macho(code_signature=True))
    from fixtures.macho_builder import LC_CODE_SIGNATURE, find_load_commands
    off = find_load_commands(bytes(data), LC_CODE_SIGNATURE)[0][0]
    struct.pack_into("<II", data, off + 8, len(data) + 1000, 500)
    with parse(bytes(data)) as mf:
        sig = mf.slices[0].code_signature
        assert mf.slices[0].has_code_signature and sig.parse_error and sig.signature_kind == "unknown"
    struct.pack_into("<II", data, off + 8, len(data) - 40, 4000)           # extends past EOF
    with parse(bytes(data)) as mf:
        sig = mf.slices[0].code_signature
        assert sig.parse_error or any("truncated" in w for w in sig.warnings)


def test_bare_code_directory_blob():
    blob = build_code_signature("bare.cd")
    cd_off = struct.unpack(">I", blob[16:20])[0]
    sig = parse_code_signature(blob[cd_off:])
    assert sig.identifier == "bare.cd" and sig.cdhash
