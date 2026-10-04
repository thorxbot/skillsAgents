"""Cocos decrypt helpers, key recovery and the opt-in ``cocos.decrypt`` stage."""
from __future__ import annotations

import gzip
import json

from fixtures import engine_checker_builder as B
from fixtures.macho_builder import build_macho
from ipa_analyzer.analyzers.cocos_decrypt import CocosDecryptStage
from ipa_analyzer.crypto import cocos, xxtea
from ipa_analyzer.models import Status, Verdict

KEY = b"mygamekey123"
SIGN = b"XXTEA"

LUA_SRC = b"local M = {}\nfunction M.run(x) return x + 1 end\nreturn M\n" * 8
JS_SRC = b'{"__type__":"cc.SceneAsset","_name":"menu","nodes":[1,2,3]}'


def enc_lua(plain=LUA_SRC, key=KEY, sign=SIGN):
    return sign + xxtea.encrypt(plain, key)


def enc_jsc(plain=JS_SRC, key=KEY, gzip_it=False):
    body = gzip.compress(plain) if gzip_it else plain
    return xxtea.encrypt(body, key)


# --------------------------------------------------------------------------------- helper-level tests
def test_decrypt_lua_roundtrip():
    r = cocos.decrypt_lua(enc_lua(), KEY, SIGN)
    assert r.ok and r.scheme == "lua" and r.plaintext == LUA_SRC


def test_decrypt_lua_requires_sign():
    assert not cocos.decrypt_lua(xxtea.encrypt(LUA_SRC, KEY), KEY, SIGN).ok  # no sign prefix


def test_decrypt_lua_bytecode_accepted():
    bc = b"\x1bLua" + b"\x53\x00\x19\x93\r\n\x1a\n" + b"compiled-ish body " * 4
    r = cocos.decrypt_lua(enc_lua(bc), KEY, SIGN)
    assert r.ok and r.plaintext == bc


def test_decrypt_jsc_plain_and_gzip():
    r = cocos.decrypt_jsc(enc_jsc(), KEY)
    assert r.ok and not r.gunzipped and r.plaintext == JS_SRC
    rg = cocos.decrypt_jsc(enc_jsc(gzip_it=True), KEY)
    assert rg.ok and rg.gunzipped and rg.plaintext == JS_SRC


def test_wrong_key_fails_cleanly():
    assert not cocos.decrypt_lua(enc_lua(), b"nope", SIGN).ok
    assert not cocos.decrypt_jsc(enc_jsc(), b"nope").ok


def test_recover_key_from_binary():
    samples = [cocos.Sample("lua", enc_lua()), cocos.Sample("jsc", enc_jsc(gzip_it=True))]
    binary = b"\x00libfoo\x00dlopen\x00" + KEY + b"\x00__cstring\x00AVFoundation\x00"
    rec = cocos.recover_key(samples, binary=binary, sign=SIGN)
    assert rec.key == KEY and rec.source == "binary_string" and rec.validated_samples == 2


def test_recover_key_provided_beats_scan():
    samples = [cocos.Sample("lua", enc_lua())]
    rec = cocos.recover_key(samples, provided_keys=[b"mygamekey123"], binary=None, sign=SIGN)
    assert rec.key == KEY and rec.source == "provided"


def test_recover_key_absent():
    samples = [cocos.Sample("lua", enc_lua())]
    rec = cocos.recover_key(samples, binary=b"only noise here\x00no key\x00", sign=SIGN)
    assert rec.key is None


# ------------------------------------------------------------------------------------- stage tests
def _run(tmp_path, files, **cocos_cfg):
    binary = build_macho(strings=["AVFoundation", KEY.decode(), "UIKit"])
    ctx = B.make_ctx(tmp_path, files, main_binary=binary)
    ctx.cfg.cocos.enabled = True
    for k, v in cocos_cfg.items():
        setattr(ctx.cfg.cocos, k, v)
    res = CocosDecryptStage().run(ctx)
    return ctx, res


def test_stage_disabled_by_default(tmp_path):
    ctx = B.make_ctx(tmp_path, {"src/main.lua": enc_lua()})
    res = CocosDecryptStage().run(ctx)
    assert res.status == Status.SKIPPED and "cocos-decrypt" in (res.reason or "")
    ctx.close()


def test_stage_decrypts_and_writes_output(tmp_path):
    files = {"src/main.lua": enc_lua(), "src/app/game.luac": enc_lua(LUA_SRC + b"-- more\n"),
             "assets/main/index.jsc": enc_jsc(gzip_it=True)}
    ctx, res = _run(tmp_path, files)
    assert res.status == Status.OK
    f = [x for x in res.findings if x.id == "engine.cocos.decrypt"][0]
    assert f.verdict == Verdict.YES
    assert res.data["key_recovery"]["key_ascii"] == KEY.decode()
    assert res.data["output"]["decrypted"] == 3
    # files are written under decrypted/ mirroring their in-app path
    out = ctx.out_dir / "decrypted" / "src" / "main.lua"
    assert out.is_file() and out.read_bytes() == LUA_SRC
    jsc_out = ctx.out_dir / "decrypted" / "assets" / "main" / "index.jsc"
    assert jsc_out.read_bytes() == JS_SRC
    manifest = json.loads((ctx.out_dir / "decrypted" / "manifest.json").read_text())
    assert manifest["summary"]["decrypted"] == 3 and manifest["key_recovery"]["found"] is True
    ctx.close()


def test_stage_key_not_recovered_is_partial(tmp_path):
    # key is NOT in the binary and not provided -> encrypted scripts present but unrecovered
    files = {"src/main.lua": enc_lua(key=b"secretAbsentKey")}
    binary = build_macho(strings=["AVFoundation", "UIKit"])
    ctx = B.make_ctx(tmp_path, files, main_binary=binary)
    ctx.cfg.cocos.enabled = True
    res = CocosDecryptStage().run(ctx)
    assert res.status == Status.PARTIAL
    f = [x for x in res.findings if x.id == "engine.cocos.decrypt"][0]
    assert f.verdict == Verdict.UNKNOWN
    assert res.data["key_recovery"]["found"] is False
    ctx.close()


def test_stage_skips_when_no_scripts(tmp_path):
    ctx, res = _run(tmp_path, {"assets/foo.png": B.rand(200)})
    assert res.status == Status.SKIPPED
    ctx.close()


def test_stage_provided_key(tmp_path):
    files = {"src/main.lua": enc_lua(key=b"customK")}
    binary = build_macho(strings=["UIKit"])
    ctx = B.make_ctx(tmp_path, files, main_binary=binary)
    ctx.cfg.cocos.enabled = True
    ctx.cfg.cocos.keys = ("customK",)
    ctx.cfg.cocos.scan_binary_for_key = False
    res = CocosDecryptStage().run(ctx)
    assert res.status == Status.OK
    assert res.data["key_recovery"]["source"] == "provided"
    ctx.close()
