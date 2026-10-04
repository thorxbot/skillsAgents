from __future__ import annotations

import io
import json

import pytest

from ipa_analyzer.unity.hotfix import resource_update as ru


class FakeSource:
    def __init__(self, files):
        self.files = files

    def read_head(self, name, n):
        if name not in self.files:
            raise KeyError(name)
        return self.files[name][:n]


def run(files, rows=None, **kw):
    src = FakeSource(files)
    rows = rows or [{"path": p, "size": len(d)} for p, d in files.items()]
    return ru.analyze(src, rows, lambda p: p, frameworks=kw.pop("frameworks", []), **kw)


def test_hosts_are_domain_only_no_path_port_userinfo_or_token():
    text = ("https://user:pw@cdn.example-game.com:8443/path/a.bin?token=SECRET123 and http://res.foo.cn/x "
            "https://www.w3.org/2001/XMLSchema https://127.0.0.1/a http://localhost:8080 https://schemas.microsoft.com/x "
            "https://dl.Game-Host.io/#frag")
    hosts = ru.extract_hosts(text)
    assert hosts == ["cdn.example-game.com", "res.foo.cn", "dl.game-host.io"]
    blob = json.dumps(hosts)
    for bad in ("SECRET", "token", "pw", "8443", "path", "/"):
        assert bad not in blob


def test_glued_literals_are_cut_at_the_next_url():
    assert ru.extract_hosts("https://janacdn.cisgames.cnhttps://janacdn.coconut.ishttps://x.y") == [
        "janacdn.cisgames.cn", "janacdn.coconut.is"]


def test_cdn_label_is_token_based_not_substring():
    assert ru.looks_like_cdn("janacdn.cisgames.cn") and ru.looks_like_cdn("res.foo.cn") and ru.looks_like_cdn("a.s3.amazonaws.com")
    assert not ru.looks_like_cdn("gcgcsupport.castlespan.com") and not ru.looks_like_cdn("api.game.com")


def test_metadata_host_scan_over_chunks():
    data = b"\0" * 10 + b"https://assets.game.io/p" + b"\0" * 40 + b"x" * 5000 + b"http://dl.other.cn" + b"\0"
    hosts = ru.scan_metadata_hosts(io.BytesIO(data), len(data), chunk=64)
    assert hosts == ["assets.game.io", "dl.other.cn"]


def test_addressables_settings_catalog_and_hosts():
    files = {
        "Data/Raw/aa/settings.json": json.dumps({"m_buildTarget": "iOS", "m_AddressablesVersion": "2.9.0",
                                                  "m_DisableCatalogUpdateOnStart": False,
                                                  "m_CatalogLocations": [{"m_InternalId": "https://cdn.mygame.com/aa/catalog.json?x=1"}]}).encode(),
        "Data/Raw/aa/catalog.bin": b"\0\0binary",
        "Data/Raw/aa_remote/Release/iOS/v1.2/catalog_1.2.json": json.dumps({"m_InternalIds": ["https://res.mygame.com/b/x.bundle"]}).encode(),
        "Data/Raw/aa_remote/Release/iOS/v1.2/catalog_1.2.hash": b"abc",
        "Data/Raw/aa/iOS/a.bundle": b"UnityFS",
        "Data/Raw/aa_remote/Release/iOS/v1.2/b.bundle": b"UnityFS",
        "Data/Raw/aa/iOS/a.bundle.manifest": b"ManifestFileVersion: 0",
    }
    out = run(files, frameworks=[{"id": "addressables", "name": "Unity Addressables", "kind": "resource", "confidence": 0.9, "version_hint": "2.9.0"}])
    assert out["addressables_version"] == "2.9.0"
    assert out["hosts"] == ["cdn.mygame.com", "res.mygame.com"]
    kinds = {c["path"].rsplit("/", 1)[-1]: c["kind"] for c in out["catalogs"]}
    assert kinds["catalog.bin"] == "local" and kinds["catalog_1.2.json"] == "remote_copy"
    assert next(c for c in out["catalogs"] if c["path"].endswith("catalog_1.2.json"))["version"] == "1.2"
    assert out["manifests"][0]["kind"] == "addressables_settings" and out["manifests"][0]["catalog_update_on_start_disabled"] is False
    assert any("remote" in h for h in out["layout_hints"]) and any("BuildPipeline" in h for h in out["layout_hints"])
    assert out["frameworks"][0]["id"] == "addressables"


def test_generic_manifests_version_files_and_noise_filter():
    files = {
        "Data/Raw/version.txt": json.dumps({"version": "1.0.7", "files": [{"filename": "a.b", "hash": "x", "size": 1}] * 3,
                                             "cdn": "https://janacdn.example.cn/game/"}).encode(),
        "Data/Raw/filelist.txt": b"a.bundle\nb.bundle\nc.bundle\n",
        "Data/Raw/google-services.json": b'{"url": "https://my-proj.firebaseio.com", "x": "https://www.google.com"}',
        "Data/Raw/Network.config.json": b'{"api": "https://api.game.com/v1"}',
        "Data/Raw/yoo/DefaultPackage/PackageManifest_DefaultPackage_v1.bytes": b"OOY\x00" + b"\x01" * 40,
    }
    out = run(files)
    by = {m["path"].rsplit("/", 1)[-1]: m for m in out["manifests"]}
    assert by["version.txt"]["kind"] == "filelist_json" and by["version.txt"]["version"] == "1.0.7" and by["version.txt"]["entries"] == 3
    assert by["filelist.txt"]["kind"] == "text_list" and by["filelist.txt"]["entries"] == 3
    assert by["PackageManifest_DefaultPackage_v1.bytes"]["kind"] == "yoo_manifest"
    assert "janacdn.example.cn" in out["hosts"] and "api.game.com" in out["hosts"]
    assert not any("google" in h or "firebase" in h for h in out["hosts"])
    assert "Network.config.json" not in by                       # unknown json configs are read for hosts but not listed


def test_metadata_hosts_need_cdn_shape_or_manifest_corroboration():
    out = run({"Data/Raw/version.txt": b'{"version":"1","files":[]}'}, metadata_hosts=["res.game.cn", "ads.tracker.com", "gcgcsupport.castlespan.com"])
    assert out["hosts"] == ["res.game.cn"] and out["other_literal_hosts_count"] == 2
    assert out["hosts_sources"]["res.game.cn"] == ["metadata"]


def test_at_most_20_hosts_and_deduplicated():
    urls = " ".join("https://cdn%d.game.cn/x" % i for i in range(30)) + " https://cdn1.game.cn/y"
    out = run({"Data/Raw/version.txt": json.dumps({"version": "1", "files": [], "u": urls}).encode()})
    assert len(out["hosts"]) == 20 and len(set(out["hosts"])) == 20


@pytest.mark.parametrize("host,noise", [("w3.org", True), ("www.apple.com", True), ("10.0.0.1", True), ("localhost", True),
                                       ("nodot", True), ("cdn.game.cn", False)])
def test_noise_hosts(host, noise):
    assert ru.is_noise_host(host) is noise
