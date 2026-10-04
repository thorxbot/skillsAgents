"""Scenarios distilled from real-world observations (rebuilt synthetically; no real app content)."""
from __future__ import annotations

import struct

from fixtures.engine_builder import SynthApp, detect, random_blob, run_stages
from ipa_analyzer.engines import scoring
from ipa_analyzer.analyzers.engine_fingerprint import EngineFingerprintStage
from ipa_analyzer.models import Status


def nhp_app(n_json=2000, n_astc=700, n_png=300) -> SynthApp:
    """Thousands of small files whose extensions say json / astc / png but whose first 4 bytes are NHPK / NHPT / NHPO."""
    app = SynthApp()

    def add(path, tag, i):
        body = random_blob(60 + (i % 40), seed=i)
        app.files[path] = tag + struct.pack("<I", 8 + len(body)) + body

    for i in range(n_json):
        add("assets/b%d/native/%04d.json" % (i % 20, i), b"NHPK", i)
    for i in range(n_astc):
        add("assets/b%d/native/%04d.astc" % (i % 20, i), b"NHPT", 10_000 + i)
    for i in range(n_png):
        add("assets/b%d/native/%04d.png" % (i % 20, i), b"NHPO", 20_000 + i)
    app.files["assets/ok.png"] = b"\x89PNG\r\n\x1a\n" + bytes(40)
    return app


# --- a) CCZp textures + Cocos layout features => Cocos family ---------------------------------------------------------------------
def ccz_files(n=80):
    return {"HD/Sprites/%d#0.ccz" % i: b"CCZp\x00\x01\x00\x00" + bytes(60) for i in range(n)}


def test_ccz_textures_alone_mean_cocos_family(tmp_path):
    app = SynthApp(files=dict(ccz_files(), **{"Audio/a.caf": b"caff" + bytes(20), "HD/a.atlas": b"page\nsize: 4,4"}))
    ctx = run_stages(tmp_path, app)
    d = detect(ctx)
    assert d["primary"]["family"] == "cocos" and d["primary"]["id"] == "cocos_family"
    assert d["primary"]["confidence"] >= 0.7
    fp = ctx.results["engine.fingerprint"]
    assert [h["id"] for h in fp["asset_formats"]][:1] == ["ccz"]
    variants = [c for c in d["candidates"] if c["family"] == "cocos" and c["id"] != "cocos_family"]
    assert variants and all(not c["confirmed"] for c in variants)       # variant stays undetermined


def test_ccz_plus_js_binding_layout_selects_the_js_variant(tmp_path):
    files = dict(ccz_files(), **{"script/jsb_boot.js": b"// cocos2d boot", "main.js": b"cc.game.run()",
                                 "project.json": b"{}", "src/app.jsc": b"\x00\x01\x02" * 20})
    d = detect(run_stages(tmp_path, SynthApp(files=files)))
    assert d["primary"]["id"] == "cocos2dx_js" and d["primary"]["family"] == "cocos"
    assert all(not c["confirmed"] for c in d["candidates"] if c["id"] in ("cocos_family", "cocos2dx_cpp"))


def test_ccz_with_lua_template_layout_selects_the_lua_variant(tmp_path):
    files = dict(ccz_files(), **{"src/cocos/cocos2d/Cocos2d.lua": b"x" * 10, "src/main.lua": b"x" * 10, "res/a.png": b"\x89PNG\r\n\x1a\n" + bytes(8)})
    app = SynthApp(files=files, strings=["cocos2d-x 3.17.2"])
    d = detect(run_stages(tmp_path, app))
    assert d["primary"]["id"] == "cocos2dx_lua"


def test_encrypted_binary_with_ccz_still_gives_the_family_and_explains_the_limit(tmp_path):
    app = SynthApp(files=ccz_files(), strings=["cocos2d-x 3.17.2", "luaL_newstate"], objc_classes=["AppDelegate"],
                   dylibs=["/System/Library/Frameworks/OpenGLES.framework/OpenGLES", "/usr/lib/libc++.1.dylib"],
                   imports=["_OBJC_CLASS_$_EAGLContext"])
    ctx = run_stages(tmp_path, app, encrypted=True)
    d = detect(ctx)
    assert d["primary"]["id"] == "cocos_family"
    assert ctx.stage_status("engine.detect") == Status.PARTIAL and "encrypted" in ctx.stage_results["engine.detect"].reason
    assert d["extra"]["visibility"]["limited"] and d["extra"]["visibility"]["strings_available"] is False
    fp = ctx.results["engine.fingerprint"]
    assert "gles" in fp["render"] and fp["script_vms"] == [] and fp["extra"]["binary_limited"] is True
    assert "FairPlay-encrypted" in fp["summary_text"]
    f = {x.id: x for x in ctx.findings}
    assert "decrypted IPA" in f["engine.primary"].remediation
    assert any("encrypted" in w for w in ctx.warnings)


# --- b) thousands of NHPK / NHPT / NHPO files => container profile, no vendor claim ---------------------------------------------------
def test_custom_header_families_are_profiled_from_the_inventory_clusters(tmp_path):
    ctx = run_stages(tmp_path, nhp_app())
    inv = ctx.results["inventory"]
    assert {c["head_ascii"] for c in inv["header_clusters"]} >= {"NHPK", "NHPT", "NHPO"}
    fp = ctx.results["engine.fingerprint"]
    clusters = {h["id"]: h for h in fp["containers"] if h["id"].startswith("header-cluster:")}
    assert set(clusters) == {"header-cluster:NHPK", "header-cluster:NHPT", "header-cluster:NHPO"}
    k = clusters["header-cluster:NHPK"]
    assert k["extra"]["count"] == 2000 and k["extra"]["exts"] == {".json": 2000} and k["extra"]["ext_mismatch"] == {".json": 2000}
    assert k["extra"]["verdict"] == "custom_format" and k["confidence"] >= 0.65
    assert k["extra"]["payload"]["size_field"] == {"offset": 4, "fraction": 1.0, "probed": 5}
    assert any("none of these files has one" in e["detail"] for e in k["evidence"])
    assert fp["extra"]["containers"]["cluster_source"] == "inventory" and fp["extra"]["containers"]["header_clusters"] == 3
    assert fp["extra"]["containers"]["ext_magic_mismatch"] == {".astc": 700, ".json": 2000, ".png": 300}
    f = {x.id: x for x in ctx.findings}
    assert f["engine.container.unknown"].verdict.value == "suspected" and f["engine.container.unknown"].confidence <= 0.8
    assert "custom container" in fp["summary_text"]


def test_no_vendor_or_engine_name_is_asserted_from_the_header_tags(tmp_path):
    ctx = run_stages(tmp_path, nhp_app(n_json=300, n_astc=100, n_png=60))
    d = detect(ctx)
    assert d["primary"] is None and not [c for c in d["candidates"] if c["confirmed"]]
    blob = " ".join([x.title + " " + x.summary + " " + x.remediation for x in ctx.findings]).lower()
    for vendor in ("netease", "neox", "supercell", "tencent", "unity", "unreal"):
        assert vendor not in blob, vendor
    assert d["custom"]["verdict"] in ("no", "unknown")


def test_own_clustering_is_used_when_the_inventory_has_no_cluster_field(tmp_path):
    ctx = run_stages(tmp_path, nhp_app(n_json=120, n_astc=60, n_png=40), stages=("macho", "engine.fingerprint"), keep_open=True)
    ctx.results["inventory"].pop("header_clusters")
    scoring._BUNDLE_CACHE.pop(ctx, None)
    res = EngineFingerprintStage().run(ctx)
    clusters = [h["id"] for h in res.data["containers"] if h["id"].startswith("header-cluster:")]
    assert sorted(clusters) == ["header-cluster:NHPK", "header-cluster:NHPO", "header-cluster:NHPT"]
    assert res.data["extra"]["containers"]["cluster_source"] == "own"
    ctx.close()


def test_cluster_members_are_not_listed_again_as_individual_containers(tmp_path):
    app = nhp_app(n_json=200, n_astc=0, n_png=0)
    app.files["assets/big.json"] = b"NHPK" + struct.pack("<I", 4 + 1_200_000) + random_blob(1_200_000, seed=5)
    ctx = run_stages(tmp_path, app)
    ids = [h["id"] for h in ctx.results["engine.fingerprint"]["containers"]]
    assert ids == ["header-cluster:NHPK"] or all("big.json" not in i for i in ids)


def test_plain_data_files_with_known_magic_create_no_cluster(tmp_path):
    app = SynthApp(files={"a/%d.json" % i: b'{"k": %d}' % i for i in range(120)})
    ctx = run_stages(tmp_path, app)
    fp = ctx.results["engine.fingerprint"]
    assert fp["containers"] == [] and ctx.results["engine.fingerprint"]["extra"]["containers"]["header_clusters"] == 0
    assert {x.id: x for x in ctx.findings}["engine.container.unknown"].verdict.value == "n/a"
