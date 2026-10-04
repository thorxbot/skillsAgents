"""libs + protect + classify through the full CLI on a synthetic IPA: report.json stays schema-valid."""
from __future__ import annotations

import json
import plistlib

from fixtures.ipa_builder import build_ipa
from fixtures.macho_builder import build_macho
from ipa_analyzer import cli


def test_full_pipeline_report_contains_wp4_sections(tmp_path, check_report):
    info = plistlib.dumps({"CFBundleIdentifier": "com.example.t", "CFBundleName": "T", "CFBundleExecutable": "T",
                           "CFBundleShortVersionString": "1.0", "CFBundleVersion": "1", "GADApplicationIdentifier": "ca-app-pub-x"})
    files = {"Info.plist": info,
             "T": build_macho(encrypted=True, dylibs=["@rpath/GoogleMobileAds.framework/GoogleMobileAds",
                                                      "@rpath/OddKit.framework/OddKit",
                                                      "/System/Library/Frameworks/CoreLocation.framework/CoreLocation"],
                              imports=["_ptrace", "_OBJC_CLASS_$_GADMobileAds"]),
             "Frameworks/GoogleMobileAds.framework/GoogleMobileAds": build_macho(filetype="dylib", encrypted=True),
             "Frameworks/OddKit.framework/OddKit": build_macho(filetype="dylib", encrypted=True),
             "SC_Info/T.sinf": b"x"}
    ipa = build_ipa(tmp_path / "T.ipa", files, app_name="T")
    out = tmp_path / "out"
    assert cli.main(["analyze", str(ipa), "-o", str(out), "--offline", "--no-il2cpp"]) in (0, 3)
    report = json.loads(next(out.glob("*/report.json")).read_text(encoding="utf-8"))
    assert check_report(report) == []
    stages = {s["name"]: s["status"] for s in report["stages"]}
    assert stages["libs"] in ("ok", "partial") and stages["protect"] in ("ok", "partial") and stages["classify"] in ("ok", "partial")
    assert any(l["id"] == "admob" for l in report["libraries"])
    ids = {f["id"] for f in report["findings"]}
    assert {"libs.summary", "libs.unknown", "protect.fairplay", "protect.antidebug", "classify.category"} <= ids
    fp = next(f for f in report["protection"]["findings"] if f["id"] == "protect.fairplay")
    assert fp["verdict"] == "yes"
    md = next(out.glob("*/report.md")).read_text(encoding="utf-8") if list(out.glob("*/report.md")) else ""
    assert "OddKit" in md or md == ""
