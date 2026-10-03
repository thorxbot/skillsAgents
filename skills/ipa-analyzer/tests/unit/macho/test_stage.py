from __future__ import annotations

import json
import plistlib
import shutil
import zipfile
from pathlib import Path
from typing import BinaryIO, Dict, List

import pytest

from fixtures.macho_builder import build_fat, build_macho
from ipa_analyzer import pipeline
from ipa_analyzer.analyzers import macho_stage
from ipa_analyzer.analyzers.macho_stage import MachoStage, classify_role, is_macho_magic_id, pick_main
from ipa_analyzer.config import Config
from ipa_analyzer.context import AnalysisContext
from ipa_analyzer.ingest import EntryInfo, open_source
from ipa_analyzer.models import Status, StageResult, Verdict, dumps_json, to_jsonable
from ipa_analyzer.registry import Registry, get_registry, register

APP = "Payload/Foo.app/"
SIG = dict(identifier="com.example.foo", team_id="ABCDE12345", entitlements={"get-task-allow": False, "aps-environment": "production"})


class DirSource:
    """Test double of WP1's DirSource: a directory exposed through the ArchiveSource protocol."""

    kind = "dir"

    def __init__(self, root: Path) -> None:
        self.path = Path(root)
        self._root = Path(root)

    def namelist(self) -> List[EntryInfo]:
        out = []
        for p in sorted(self._root.rglob("*")):
            rel = p.relative_to(self._root).as_posix()
            if p.is_dir():
                out.append(EntryInfo(rel + "/", 0, is_dir=True))
            else:
                out.append(EntryInfo(rel, p.stat().st_size))
        return out

    def stat(self, name: str) -> EntryInfo:
        p = self._root / name
        if not p.is_file():
            raise KeyError(name)
        return EntryInfo(name, p.stat().st_size)

    def open(self, name: str) -> BinaryIO:
        p = self._root / name
        if not p.is_file():
            raise KeyError(name)
        return open(p, "rb")

    def read_head(self, name: str, n: int) -> bytes:
        with self.open(name) as fh:
            return fh.read(n)

    def extract_to(self, name: str, dest: Path) -> Path:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self._root / name, dest)
        return dest

    def close(self) -> None:
        return None


def app_files(**over) -> Dict[str, bytes]:
    """A small but complete app bundle (names relative to the archive root)."""
    files = {
        APP + "Info.plist": plistlib.dumps({"CFBundleExecutable": "FooBin", "CFBundleIdentifier": "com.example.foo"}),
        APP + "FooBin": build_fat([
            build_macho(arch="armv7", encrypted=True, strings=["main-armv7"]),
            build_macho(arch="arm64", encrypted=True, strings=["main-arm64"], objc_classes=["AppDelegate"],
                        dylibs=["/usr/lib/libSystem.B.dylib", ("@rpath/UnityFramework.framework/UnityFramework", "load"),
                                ("/usr/lib/libz.dylib", "weak")], rpaths=["@executable_path/Frameworks"],
                        code_signature=SIG, canary=True, arc=True, cpp=True, swift=True)]),
        APP + "Frameworks/UnityFramework.framework/UnityFramework": build_macho(
            filetype="dylib", cryptid=0, encryption_info=True, strings=["il2cpp_init"], flags=0),
        APP + "Frameworks/libhelper.dylib": build_fat([build_macho(arch="arm64", filetype="dylib", cryptid=1),
                                                       build_macho(arch="x86_64", filetype="dylib", platform="iossimulator")]),
        APP + "PlugIns/Share.appex/Share": build_macho(encrypted=True, stripped=True),
        APP + "Watch/Wrist.app/Wrist": build_macho(arch="arm64_32", platform="watchos", min_os="6.0"),
        APP + "Tools/helper-tool": build_macho(),
        APP + "Assets.car": b"BOMStore" + b"\0" * 100,
        APP + "readme.txt": b"hello",
    }
    files.update(over)
    return {k: v for k, v in files.items() if v is not None}


def inventory_for(files: Dict[str, bytes], truncated: bool = False) -> dict:
    rows = []
    for name in sorted(files):
        head = files[name][:4]
        magic = "macho" if head in macho_stage._MAGIC_HEADS else "unknown"
        rows.append({"path": name, "size": len(files[name]), "csize": len(files[name]), "ext": "", "magic": magic,
                     "category": "other"})
    return {"files": rows[:3] if truncated else rows, "files_total": len(rows), "files_truncated": truncated,
            "inventory_file": "inventory.json"}


def make_ctx(tmp_path, files, *, kind="zip", app_root=APP, truncated=False, write_inventory_json=False):
    tmp_path.mkdir(parents=True, exist_ok=True)
    if kind == "zip":
        ipa = tmp_path / "Foo.ipa"
        with zipfile.ZipFile(ipa, "w", zipfile.ZIP_DEFLATED) as zf:
            for n, d in files.items():
                zf.writestr(n, d)
        src = open_source(ipa)
    else:
        root = tmp_path / "tree"
        for n, d in files.items():
            (root / n).parent.mkdir(parents=True, exist_ok=True)
            (root / n).write_bytes(d)
        src, ipa = DirSource(root), root
    ctx = AnalysisContext(Config(output_dir=tmp_path / "out"), ipa, source=src, app_root=app_root)
    ctx.bind_input("ab" * 32, "Foo")
    inv = inventory_for(files, truncated)
    ctx.results["inventory"] = inv
    if write_inventory_json:
        full = inventory_for(files)
        (ctx.out_dir / "inventory.json").write_text(json.dumps({"files": full["files"]}), encoding="utf-8")
    return ctx


def by_path(data):
    return {b["path"]: b for b in data["binaries"]}


# --- tests -------------------------------------------------------------------------------------
def test_stage_registered_with_frozen_arguments():
    spec = get_registry().get("macho") if "macho" in get_registry() else pipeline.ensure_analyzers_loaded().get("macho")
    assert spec.requires == ("inventory",) and spec.after == () and not spec.always_run


def test_roles_kinds_and_binary_records(tmp_path):
    ctx = make_ctx(tmp_path, app_files())
    res = MachoStage().run(ctx)
    assert res.status == Status.OK and res.warnings == []
    b = by_path(res.data)
    roles = {p.replace(APP, ""): x["role"] for p, x in b.items()}
    assert roles == {
        "FooBin": "main", "Frameworks/UnityFramework.framework/UnityFramework": "framework",
        "Frameworks/libhelper.dylib": "dylib", "PlugIns/Share.appex/Share": "appex",
        "Watch/Wrist.app/Wrist": "watch", "Tools/helper-tool": "other"}
    assert list(b) == sorted(b)                                            # deterministic order
    main = b[APP + "FooBin"]
    assert main["rel"] == "FooBin" and main["kind"] == "execute" and main["is_fat"] and main["size"] > 0
    assert [s["arch"] for s in main["slices"]] == ["armv7", "arm64"]
    arm = main["slices"][1]
    assert arm["encrypted"] is True and arm["cryptid"] == 1 and arm["cryptsize"] > 0
    assert arm["team_id"] == "ABCDE12345" and arm["entitlements_keys"] == ["aps-environment", "get-task-allow"]
    assert arm["entitlements"] == {"get-task-allow": False, "aps-environment": "production"}
    assert arm["signed"] and arm["signature"]["identifier"] == "com.example.foo" and arm["signature"]["adhoc"]
    assert arm["has_objc"] and arm["has_swift"] and arm["has_cpp"] and arm["is_pie"] and not arm["stripped"]
    assert arm["has_stack_canary"] and arm["uses_arc"] and arm["platform"] == "ios" and arm["min_os"] == "12.0"
    assert arm["uuid"] and arm["sdk"] == "17.0" and arm["symbol_level"] == "full" and not arm["simulator"]
    assert main["slices"][0]["signed"] is False and main["slices"][0]["team_id"] is None
    # dependency list is taken from the preferred (arm64) slice, de-duplicated
    assert [(d["path"], d["kind"], d["load_kind"], d["weak"]) for d in main["dylibs"]] == [
        ("/usr/lib/libSystem.B.dylib", "system", "load", False),
        ("@rpath/UnityFramework.framework/UnityFramework", "bundled", "load", False),
        ("/usr/lib/libz.dylib", "system", "weak", True), ("/usr/lib/libc++.1.dylib", "system", "load", False)]
    assert main["rpaths"] == ["@executable_path/Frameworks"] and main["parse_warnings"] == []
    unity = b[APP + "Frameworks/UnityFramework.framework/UnityFramework"]["slices"][0]
    assert unity["encrypted"] is False and unity["cryptid"] == 0 and unity["cryptsize"] > 0   # LC kept, cryptid 0
    helper = b[APP + "Frameworks/libhelper.dylib"]
    assert helper["kind"] == "dylib" and [s["encrypted"] for s in helper["slices"]] == [True, False]
    assert helper["slices"][1]["simulator"] is True
    assert b[APP + "Tools/helper-tool"]["slices"][0]["cryptid"] is None
    assert b[APP + "PlugIns/Share.appex/Share"]["slices"][0]["stripped"] is True


def test_summary_block(tmp_path):
    res = MachoStage().run(make_ctx(tmp_path, app_files()))
    s = res.data["summary"]
    assert s["main_binary"] == APP + "FooBin" and s["any_encrypted"] is True and s["all_encrypted"] is False
    assert s["archs"] == ["armv7", "arm64"] and s["min_os"] == "12.0" and s["languages_hint"] == ["objc", "swift", "cpp"]
    assert s["encrypted_binaries"] == [APP + "FooBin", APP + "Frameworks/libhelper.dylib", APP + "PlugIns/Share.appex/Share"]
    assert s["main_encrypted"] is True and s["binaries_total"] == 6


def test_all_encrypted_true_only_when_every_slice_is(tmp_path):
    files = {APP + "Info.plist": plistlib.dumps({"CFBundleExecutable": "Foo"}),
             APP + "Foo": build_macho(encrypted=True), APP + "Frameworks/a.dylib": build_macho(filetype="dylib", encrypted=True)}
    s = MachoStage().run(make_ctx(tmp_path, files)).data["summary"]
    assert s["all_encrypted"] is True and s["any_encrypted"] is True
    files = {APP + "Info.plist": plistlib.dumps({"CFBundleExecutable": "Foo"}), APP + "Foo": build_macho()}
    s = MachoStage().run(make_ctx(tmp_path / "b", files)).data["summary"]
    assert s["all_encrypted"] is False and s["any_encrypted"] is False and s["main_encrypted"] is False


def test_finding(tmp_path):
    res = MachoStage().run(make_ctx(tmp_path, app_files()))
    assert [f.id for f in res.findings] == ["macho.summary"]
    f = res.findings[0]
    assert f.verdict == Verdict.YES and f.confidence >= 0.9
    assert f.params["parsed"] == 6 and f.params["total"] == 6 and f.params["encrypted_binaries"] == 3
    assert f.evidence and f.evidence[0].kind == "macho" and f.evidence[0].ref == APP + "FooBin"
    assert all(e.kind == "macho" for e in f.evidence) and len(f.evidence) <= 11
    assert "FairPlay" in f.remediation and "decrypt" in f.remediation


def test_i18n_files_cover_the_finding_and_format_cleanly(tmp_path):
    res = MachoStage().run(make_ctx(tmp_path, app_files()))
    params = res.findings[0].params
    root = Path(macho_stage.__file__).resolve().parents[3] / "data" / "i18n"
    for lang in ("zh", "en"):
        d = json.loads((root / lang / "macho.json").read_text(encoding="utf-8"))
        assert {"title", "summary", "remediation"} <= set(d["macho.summary"])
        assert d["macho.summary"]["summary"].format_map(params)
        assert all(k.startswith("macho.") for k in d)
        for role in ("main", "framework", "dylib", "appex", "watch", "other"):
            assert "macho.role." + role in d
    zh = json.loads((root / "zh" / "macho.json").read_text(encoding="utf-8"))
    assert zh["macho.summary"]["title"] != json.loads((root / "en" / "macho.json").read_text(encoding="utf-8"))["macho.summary"]["title"]


def test_data_is_json_serialisable_and_stable(tmp_path):
    res = MachoStage().run(make_ctx(tmp_path, app_files()))
    assert to_jsonable(res.data) == res.data
    text = dumps_json(res.data, sort_keys=True)
    assert json.loads(text) == res.data


def test_zip_and_dir_inputs_give_identical_results(tmp_path):
    files = app_files()
    a = MachoStage().run(make_ctx(tmp_path / "z", files, kind="zip"))
    b = MachoStage().run(make_ctx(tmp_path / "d", files, kind="dir"))
    assert a.status == b.status == Status.OK
    assert a.data == b.data
    assert [f.to_dict() for f in a.findings] == [f.to_dict() for f in b.findings]


def test_app_directory_as_root(tmp_path):
    files = {k[len(APP):]: v for k, v in app_files().items()}
    res = MachoStage().run(make_ctx(tmp_path, files, kind="dir", app_root=""))
    roles = {p: b["role"] for p, b in by_path(res.data).items()}
    assert roles["FooBin"] == "main" and roles["Watch/Wrist.app/Wrist"] == "watch"
    assert by_path(res.data)["FooBin"]["rel"] == "FooBin"


def test_garbage_file_labelled_macho_makes_stage_partial(tmp_path):
    files = app_files(**{APP + "Frameworks/Broken.framework/Broken": b"not a mach-o at all" * 10,
                         APP + "Frameworks/Java.dylib": bytes.fromhex("cafebabe00000034") + b"\0" * 100,
                         APP + "Frameworks/Cut.dylib": build_macho()[:20]})
    ctx = make_ctx(tmp_path, files)
    for row in ctx.results["inventory"]["files"]:
        if row["path"].endswith(("Broken", "Java.dylib", "Cut.dylib")):
            row["magic"] = "macho"
    res = MachoStage().run(ctx)
    assert res.status == Status.PARTIAL and res.reason and "3 of 9" in res.reason
    assert len(res.warnings) >= 3 and any("Java" in w for w in res.warnings)
    assert sorted(res.data["failed"]) == [APP + "Frameworks/Broken.framework/Broken", APP + "Frameworks/Cut.dylib",
                                          APP + "Frameworks/Java.dylib"]
    assert len(res.data["binaries"]) == 6 and res.data["summary"]["main_binary"] == APP + "FooBin"
    assert res.findings[0].params["parsed"] == 6 and res.findings[0].params["total"] == 9


def test_extraction_failure_is_a_warning_not_a_crash(tmp_path):
    ctx = make_ctx(tmp_path, app_files())
    real = ctx.extract
    ctx.extract = lambda names: {} if "Watch/Wrist.app/Wrist" in list(names)[0] else real(names)
    res = MachoStage().run(ctx)
    assert res.status == Status.PARTIAL and any("cannot extract" in w and "Wrist" in w for w in res.warnings)
    assert len(res.data["binaries"]) == 5


def test_no_macho_files(tmp_path):
    files = {APP + "Info.plist": plistlib.dumps({"CFBundleExecutable": "Foo"}), APP + "a.txt": b"hello world"}
    res = MachoStage().run(make_ctx(tmp_path, files))
    assert res.status == Status.OK and res.data["binaries"] == [] and res.data["summary"]["main_binary"] is None
    assert res.data["summary"]["any_encrypted"] is False and res.data["summary"]["all_encrypted"] is False
    assert any("no Mach-O" in w for w in res.warnings)
    assert res.findings[0].verdict == Verdict.UNKNOWN and res.findings[0].verdict != Verdict.NO


def test_main_detection_fallbacks(tmp_path):
    plain = {APP + "Foo": build_macho(), APP + "Other": build_macho(filetype="dylib")}
    # no Info.plist: the app directory's stem wins
    assert by_path(MachoStage().run(make_ctx(tmp_path / "a", plain)).data)[APP + "Foo"]["role"] == "main"
    # neither Info.plist nor matching stem: the single top-level executable
    files = {APP + "weird": build_macho(), APP + "lib.dylib": build_macho(filetype="dylib")}
    res = MachoStage().run(make_ctx(tmp_path / "b", files))
    assert by_path(res.data)[APP + "weird"]["role"] == "main"
    # ambiguous: no main, warning, still ok data
    files = {APP + "x1": build_macho(), APP + "x2": build_macho()}
    res = MachoStage().run(make_ctx(tmp_path / "c", files))
    assert res.data["summary"]["main_binary"] is None and any("main executable" in w for w in res.warnings)
    assert {b["role"] for b in res.data["binaries"]} == {"other"}
    # CFBundleExecutable pointing at a missing file falls back to the stem
    files = {APP + "Info.plist": plistlib.dumps({"CFBundleExecutable": "Gone"}), APP + "Foo": build_macho()}
    assert MachoStage().run(make_ctx(tmp_path / "d", files)).data["summary"]["main_binary"] == APP + "Foo"


def test_truncated_inventory_uses_inventory_json(tmp_path):
    files = app_files()
    res = MachoStage().run(make_ctx(tmp_path, files, truncated=True, write_inventory_json=True))
    assert res.status == Status.OK and len(res.data["binaries"]) == 6


def test_truncated_inventory_without_json_falls_back_to_header_sniffing(tmp_path):
    files = app_files()
    ctx = make_ctx(tmp_path, files, truncated=True, write_inventory_json=False)
    res = MachoStage().run(ctx)
    assert len(res.data["binaries"]) == 6 and res.data["summary"]["main_binary"] == APP + "FooBin"


def test_truncated_inventory_json_in_list_form_and_corrupt(tmp_path):
    files = app_files()
    ctx = make_ctx(tmp_path / "list", files, truncated=True)
    (ctx.out_dir / "inventory.json").write_text(json.dumps(inventory_for(files)["files"]), encoding="utf-8")
    assert len(MachoStage().run(ctx).data["binaries"]) == 6
    ctx = make_ctx(tmp_path / "bad", files, truncated=True)
    (ctx.out_dir / "inventory.json").write_text("{not json", encoding="utf-8")
    res = MachoStage().run(ctx)
    assert len(res.data["binaries"]) == 6 and any("inventory.json" in w for w in ctx.warnings)


def test_inventory_without_files_key_is_tolerated(tmp_path):
    ctx = make_ctx(tmp_path, app_files())
    ctx.results["inventory"] = {}
    res = MachoStage().run(ctx)               # empty table -> sniffing finds the binaries
    assert res.status == Status.OK and len(res.data["binaries"]) == 6


def test_works_inside_the_pipeline(tmp_path):
    reg = Registry()

    @register("inventory", registry=reg)
    def inv(ctx):
        return StageResult.ok("inventory", ctx.results.get("inventory_seed"))

    register("macho", requires=("inventory",), registry=reg)(MachoStage)
    ctx = make_ctx(tmp_path, app_files())
    ctx.results["inventory_seed"] = ctx.results.pop("inventory")
    run = pipeline.run(ctx, reg)
    st = {r.name: r for r in run.stage_results}
    assert st["macho"].status == Status.OK, st["macho"].error
    assert ctx.results["macho"]["summary"]["main_binary"] == APP + "FooBin"
    assert [f.id for f in ctx.findings if f.id.startswith("macho.")] == ["macho.summary"]


def test_stage_skipped_when_inventory_missing(tmp_path):
    reg = Registry()
    register("inventory", registry=reg)(lambda ctx: StageResult.skipped("inventory", "n/a"))
    register("macho", requires=("inventory",), registry=reg)(MachoStage)
    run = pipeline.run(make_ctx(tmp_path, app_files()), reg)
    assert {r.name: r.status for r in run.stage_results}["macho"] == Status.SKIPPED


# --- pure helpers ------------------------------------------------------------------------------
@pytest.mark.parametrize("rel,main,role", [
    ("Foo", "Foo", "main"), ("Foo", None, "other"), ("Frameworks/A.framework/A", "Foo", "framework"),
    ("Frameworks/libx.dylib", "Foo", "dylib"), ("Frameworks/LIBX.DYLIB", "Foo", "dylib"),
    ("PlugIns/S.appex/S", "Foo", "appex"), ("Extensions/E.appex/E", "Foo", "appex"),
    ("PlugIns/S.appex/Frameworks/B.framework/B", "Foo", "framework"), ("Watch/W.app/W", "Foo", "watch"),
    ("Watch/W.app/Frameworks/C.framework/C", "Foo", "watch"), ("AppClips/Clip.app/Clip", "Foo", "other"),
    ("Tools/t", "Foo", "other"),
])
def test_classify_role(rel, main, role):
    assert classify_role(rel, main) == role


def test_pick_main_and_magic_ids():
    top = [("a", "dylib"), ("Foo", "execute"), ("b", "execute")]
    assert pick_main(top, "a", "Foo") == "a" and pick_main(top, "zz", "Foo") == "Foo"
    assert pick_main(top, None, None) is None and pick_main([("x", "execute")], None, None) == "x"
    assert pick_main([], "Foo", "Foo") is None
    assert is_macho_magic_id("macho") and is_macho_magic_id("MACHO_FAT") and is_macho_magic_id("macho_arm64")
    assert not is_macho_magic_id("png") and not is_macho_magic_id(None) and not is_macho_magic_id("")
