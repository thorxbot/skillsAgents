"""Builders for WP2 tests: fake IPAs, plists, provisioning profiles, CodeResources seals."""
from __future__ import annotations

import hashlib
import plistlib
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import pytest

from ipa_analyzer.config import Config
from ipa_analyzer.context import AnalysisContext
from ipa_analyzer.ingest.minimal_zip import ZipSource

APP = "Payload/Foo.app/"
EMAIL = "secret.buyer@example.com"
BUYER = "Zhang Secret Buyer"
UDID_A = "00008030-001A2B3C4D5E6F78"
UDID_B = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"


def info_plist(binary: bool = False, **over: Any) -> bytes:
    d: Dict[str, Any] = {
        "CFBundleIdentifier": "com.example.foo", "CFBundleShortVersionString": "1.2.3",
        "CFBundleVersion": "45", "CFBundleExecutable": "Foo", "CFBundleName": "FooName",
        "CFBundleDisplayName": "Foo Display", "MinimumOSVersion": "12.0", "UIDeviceFamily": [1, 2],
    }
    d.update(over)
    d = {k: v for k, v in d.items() if v is not None}
    return plistlib.dumps(d, fmt=plistlib.FMT_BINARY if binary else plistlib.FMT_XML)


def fake_cms(plist: Dict[str, Any]) -> bytes:
    """DER-ish junk + XML plist + trailing junk, like a signed .mobileprovision."""
    body = plistlib.dumps(plist, fmt=plistlib.FMT_XML)
    return b"\x30\x82\x0f\xa0\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02" + b"\xa0\x82" + body + b"\x31\x82\x00\x10\xde\xad\xbe\xef"


def provision_plist(kind: str, **over: Any) -> Dict[str, Any]:
    import datetime as dt
    base: Dict[str, Any] = {
        "Name": "Foo Profile", "TeamName": "Example Team", "TeamIdentifier": ["TEAM123456"],
        "ApplicationIdentifierPrefix": ["TEAM123456"], "UUID": "11111111-2222-3333-4444-555555555555",
        "CreationDate": dt.datetime(2024, 1, 2, 3, 4, 5), "ExpirationDate": dt.datetime(2025, 1, 2, 3, 4, 5),
        "Platform": ["iOS"], "DeveloperCertificates": [b"cert1"],
        "Entitlements": {"application-identifier": "TEAM123456.com.example.foo", "get-task-allow": False,
                         "aps-environment": "production",
                         "com.apple.developer.associated-domains": ["applinks:example.com"]},
    }
    if kind == "development":
        base["ProvisionedDevices"] = [UDID_A, UDID_B]
        base["Entitlements"]["get-task-allow"] = True
        base["Entitlements"]["aps-environment"] = "development"
    elif kind == "adhoc":
        base["ProvisionedDevices"] = [UDID_A, UDID_B]
    elif kind == "enterprise":
        base["ProvisionsAllDevices"] = True
    elif kind != "appstore":
        raise ValueError(kind)
    base.update(over)
    return base


def itunes_plist(**over: Any) -> bytes:
    import datetime as dt
    d: Dict[str, Any] = {
        "itemId": 123456789, "itemName": "Foo Store Name", "artistName": "Foo Studio", "artistId": 42,
        "genre": "Games", "genreId": 6014, "bundleDisplayName": "Foo Store Display",
        "softwareVersionBundleId": "com.example.foo", "releaseDate": "2020-05-06T07:08:09Z",
        "softwareVersionExternalIdentifier": 999, "bundleShortVersionString": "1.2.3", "bundleVersion": "45",
        "appleId": EMAIL, "userName": BUYER, "purchaseDate": dt.datetime(2021, 1, 1, 12, 0, 0),
        "com.apple.iTunesStore.downloadInfo": {
            "accountInfo": {"AppleID": EMAIL, "DSPersonID": 777000111, "FamilyID": 5, "PurchaserID": 6},
            "purchaseDate": "2021-01-01T12:00:00Z"},
        "unknownKey": "keep-out-of-output",
    }
    d.update(over)
    return plistlib.dumps(d, fmt=plistlib.FMT_BINARY)


def seal(files: Dict[str, bytes], *, sha1_only: bool = False, optional: Optional[set] = None,
         extra_rules: Optional[Dict[str, Any]] = None, nested: Optional[list] = None) -> bytes:
    """CodeResources plist for ``files`` (paths relative to the .app root)."""
    optional = optional or set()
    f1: Dict[str, Any] = {}
    f2: Dict[str, Any] = {}
    for p, data in files.items():
        sha1 = hashlib.sha1(data).digest()
        f1[p] = {"hash": sha1, "optional": True} if p in optional else sha1
        if sha1_only:
            continue
        ent: Dict[str, Any] = {"hash2": hashlib.sha256(data).digest()}
        if p in optional:
            ent["optional"] = True
        f2[p] = ent
    for n in nested or []:
        f2[n] = {"cdhash": b"\x00" * 20, "requirement": "anchor apple"}
    rules2: Dict[str, Any] = {
        "^.*": True, "^.*\\.lproj/": {"optional": True, "weight": 1000.0},
        "^Base\\.lproj/": {"weight": 1010.0}, "^PkgInfo$": {"omit": True, "weight": 20.0},
        "^(Frameworks|PlugIns)/": {"nested": True, "weight": 10.0},
    }
    rules2.update(extra_rules or {})
    out: Dict[str, Any] = {"files": f1, "rules": {"^.*": True}, "rules2": rules2}
    if not sha1_only:
        out["files2"] = f2
    return plistlib.dumps(out, fmt=plistlib.FMT_XML)


@pytest.fixture()
def run_meta(tmp_path, make_zip):
    """``run_meta(files, redact=True, app_root=APP, **cfg)`` -> (StageResult, ctx). ``files`` keys are
    archive names; use ``app(...)`` to prefix app-relative names."""
    from ipa_analyzer.analyzers.meta import MetaStage

    created = []

    def _run(files: Dict[str, Any], *, app_root: str = APP, input_name: str = "sample.ipa", **cfg: Any):
        zp = make_zip(files, input_name)
        ctx = AnalysisContext(Config(output_dir=tmp_path / "out", **cfg), zp, source=ZipSource(zp), app_root=app_root)
        created.append(ctx)
        return MetaStage().run(ctx), ctx

    yield _run
    for c in created:
        c.close()


def app(files: Dict[str, Any], root: str = APP) -> Dict[str, Any]:
    return {root + k: v for k, v in files.items()}


@pytest.fixture()
def builders():
    class B:
        pass
    b = B()
    b.info_plist, b.fake_cms, b.provision_plist, b.itunes_plist, b.seal, b.app = (
        info_plist, fake_cms, provision_plist, itunes_plist, seal, app)
    b.APP, b.EMAIL, b.BUYER, b.UDID_A, b.UDID_B = APP, EMAIL, BUYER, UDID_A, UDID_B
    return b
