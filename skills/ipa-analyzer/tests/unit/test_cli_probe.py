"""The ``probe`` CLI subcommand: analyze then assess decryptability."""
from __future__ import annotations

import json
import plistlib

from fixtures.ipa_builder import build_ipa
from fixtures.macho_builder import build_macho
from ipa_analyzer import cli
from ipa_analyzer.crypto import ccz, xxtea


def _cocos_ipa(tmp_path):
    files = {
        "Info.plist": plistlib.dumps({"CFBundleExecutable": "Game", "CFBundleIdentifier": "com.ex.g",
                                      "CFBundleName": "Game"}),
        "Game": build_macho(arch="arm64", strings=["cocos2d-x-3.17", "xxtea_decrypt"]),
        "application.js": b"var x=1;" * 20, "src/settings.json": b'{"CocosEngine":"3.8.2"}',
        "src/import-map.json": b"{}", "src/system.bundle.js": b"var y=2;" * 20,
        "jsb-adapter/engine-adapter.js": b"var z=3;" * 20,
        "assets/main/index.jsc": xxtea.encrypt(b'{"scene":1}', b"thekey"),
        "res/hero.ccz": ccz.encrypt_ccz(b"TEX" * 300, (1, 2, 3, 4)),
    }
    return build_ipa(tmp_path / "g.ipa", files, app_name="Game")


def test_probe_writes_assessment_and_prints(tmp_path, capsys):
    ipa = _cocos_ipa(tmp_path)
    out = tmp_path / "out"
    code = cli.main(["probe", str(ipa), "-o", str(out), "--offline", "--lang", "en"])
    assert code == 0
    report = json.loads(next(out.glob("*/decryptability.json")).read_text(encoding="utf-8"))
    kinds = {a["artifact"]: a["feasibility"] for a in report["assessments"]}
    assert any("scripts" in k.lower() and v == "supported" for k, v in kinds.items())
    assert any("resources" in k.lower() and v == "needs_key" for k, v in kinds.items())
    assert report["fairplay_encrypted"] is False
    text = capsys.readouterr().out
    assert "DECRYPTABLE NOW" in text and "NEEDS KEY" in text and "next:" in text


def test_probe_json_mode(tmp_path, capsys):
    ipa = _cocos_ipa(tmp_path)
    code = cli.main(["probe", str(ipa), "-o", str(tmp_path / "o"), "--offline", "--json"])
    assert code == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["tool"] and "assessments" in doc and doc["assessments"]


def test_probe_missing_input(tmp_path):
    assert cli.main(["probe", str(tmp_path / "nope"), "-o", str(tmp_path / "o")]) == 2
