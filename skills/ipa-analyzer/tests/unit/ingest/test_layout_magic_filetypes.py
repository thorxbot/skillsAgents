from __future__ import annotations

import json
import struct

import pytest

from fixtures.ipa_builder import build_ipa, build_zip_bytes
from ipa_analyzer.errors import InvalidInput
from ipa_analyzer.ingest.layout import detect_kind, find_app_root
from ipa_analyzer.ingest.source import DirSource, ZipSource
from ipa_analyzer.util import filetypes, magic
from ipa_analyzer.util.paths import resource_dir


# --- layout ------------------------------------------------------------------------------------
def _zip(tmp_path, entries, name="x.ipa"):
    p = tmp_path / name
    p.write_bytes(build_zip_bytes(entries))
    return ZipSource(p)


def test_single_app(tmp_path):
    src = ZipSource(build_ipa(tmp_path / "a.ipa", {"Info.plist": b"x"}, app_name="Foo"))
    loc = find_app_root(src)
    assert (loc.app_root, loc.app_name_dir, loc.warnings) == ("Payload/Foo.app/", "Foo.app", [])
    assert detect_kind(src, loc) == "ipa"
    src.close()


def test_multiple_apps_pick_largest_with_info_plist(tmp_path):
    src = _zip(tmp_path, {
        "Payload/Small.app/Info.plist": b"x", "Payload/Big.app/Info.plist": b"x", "Payload/Big.app/data": b"y" * 5000,
        "Payload/Huge.app/data": b"z" * 99999,                      # largest but no Info.plist
        "Payload/Big.app/Watch/W.app/Info.plist": b"w" * 10,        # nested .app is not a candidate
    })
    loc = find_app_root(src)
    assert loc.app_root == "Payload/Big.app/"
    assert any("multiple" in w for w in loc.warnings)
    src.close()


def test_no_info_plist_still_accepted_with_warning(tmp_path):
    src = _zip(tmp_path, {"Payload/A.app/bin": b"x"})
    loc = find_app_root(src)
    assert loc.app_root == "Payload/A.app/" and any("Info.plist" in w for w in loc.warnings)
    src.close()


def test_wrapper_folder_and_bare_app(tmp_path):
    src = _zip(tmp_path, {"Folder/Payload/A.app/Info.plist": b"x"})
    assert find_app_root(src).app_root == "Folder/Payload/A.app/"
    src.close()
    src = _zip(tmp_path, {"B.app/Info.plist": b"x"}, "b.zip")
    loc = find_app_root(src)
    assert loc.app_root == "B.app/" and any("no Payload" in w for w in loc.warnings) and detect_kind(src, loc) == "zip"
    src.close()


@pytest.mark.parametrize("entries", [{}, {"readme.txt": b"x"}, {"Payload/": b"", "Payload/notes.txt": b"x"},
                                     {"__MACOSX/Payload/._A.app": b"x"}])
def test_not_an_app_raises(tmp_path, entries):
    src = _zip(tmp_path, entries)
    with pytest.raises(InvalidInput):
        find_app_root(src)
    src.close()


def test_directory_layouts(tmp_path):
    app = tmp_path / "Foo.app"
    app.mkdir()
    (app / "Info.plist").write_bytes(b"x")
    src = DirSource(app)
    loc = find_app_root(src)
    assert (loc.app_root, loc.app_name_dir, detect_kind(src, loc)) == ("", "Foo.app", "app_dir")
    pay = tmp_path / "ex"
    (pay / "Payload" / "Bar.app").mkdir(parents=True)
    (pay / "Payload" / "Bar.app" / "Info.plist").write_bytes(b"x")
    src = DirSource(pay)
    loc = find_app_root(src)
    assert (loc.app_root, detect_kind(src, loc)) == ("Payload/Bar.app/", "payload_dir")
    plain = tmp_path / "Whatever"
    plain.mkdir()
    (plain / "Info.plist").write_bytes(b"x")
    assert find_app_root(DirSource(plain)).app_root == ""
    empty = tmp_path / "Empty.app"
    empty.mkdir()
    (empty / "x.bin").write_bytes(b"x")
    assert any("Info.plist" in w for w in find_app_root(DirSource(empty)).warnings)


# --- magic -------------------------------------------------------------------------------------
def _macho(magic_bytes, filetype_fmt, ftype=2):
    return magic_bytes + struct.pack(filetype_fmt, 0x0100000C) + struct.pack(filetype_fmt, 0) + \
        struct.pack(filetype_fmt, ftype) + b"\0" * 40


FAT = b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + struct.pack(">IIIII", 0x0100000C, 0, 4096, 100, 14) + b"\0" * 20
JAVA = b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\0" * 40
MAGIC_CASES = [
    (_macho(b"\xcf\xfa\xed\xfe", "<I"), "macho"), (_macho(b"\xce\xfa\xed\xfe", "<I"), "macho"),
    (_macho(b"\xfe\xed\xfa\xcf", ">I"), "macho"), (FAT, "macho"), (JAVA, "java_class"),
    (b"\x89PNG\r\n\x1a\n" + b"\0" * 20, "png"), (b"\xff\xd8\xff\xe0" + b"\0" * 20, "jpeg"), (b"GIF89a" + b"\0" * 10, "gif"),
    (b"RIFF\x10\0\0\0WEBPVP8 ", "webp"), (b"RIFF\x10\0\0\0WAVEfmt ", "wav"), (b"RIFF\x10\0\0\0AVI LIST", "avi"),
    (b"\0\0\0\x18ftypheic\0\0\0\0", "heic"), (b"\0\0\0\x18ftypmp42\0\0\0\0", "mp4"), (b"\0\0\0\x14ftypqt  \0\0\0\0", "mov"),
    (b"\0\0\0\x1cftypM4A \0\0\0\0", "m4a"), (b"\0\0\0\x1cftypavif\0\0\0\0", "avif"),
    (b"ID3\x03\0\0\0\0\0\0", "mp3"), (b"OggS\0\x02", "ogg"), (b"fLaC\0\0", "flac"), (b"caff\0\x01\0\0desc", "caf"),
    (b"FORM\0\x02nvAIFFCOMM", "aiff"),
    (b"\x00\x01\x00\x00\x00\x11\x01\x00", "ttf"), (b"OTTO\0\x10\x01\0", "otf"), (b"wOFF\0\1\0\0", "woff"), (b"wOF2\0\1", "woff2"),
    (b"SQLite format 3\0\x10\0\x01\x01", "sqlite"), (b"bplist00\xd4\0", "bplist"),
    (b"<?xml version=\"1.0\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\">\n<plist version=\"1.0\">", "plist_xml"),
    (b"<?xml version=\"1.0\"?><resources/>", "xml"),
    (b"UnityFS\0\0\0\0\x08" + b"5.x.x\0", "unityfs"), (b"UnityWeb\0", "unityweb"), (b"UnityRaw\0", "unityraw"),
    (b"UnityArchive\0", "unityarchive"), (b"GDPC\x02\0\0\0", "gdpc"), (b"\xaf\x1b\xb1\xfa\x18\0\0\0", "il2cpp_metadata"),
    (b"\x1bLuaQ\0\x01\x04", "lua_bytecode"), (b"\x1bLJ\x02\x00", "lua_bytecode"),
    (b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f" + b"\0" * 8, "hermes_bytecode"),
    (b"CCZp\0\0\0\1", "ccz"), (b"PK\x03\x04\x14\0", "zip"), (b"PK\x05\x06" + b"\0" * 18, "zip"), (b"\x1f\x8b\x08\0", "gzip"),
    (b"BOMStore\0\0\0\x01", "bomstore"), (b"NIBArchive\x01\0\0\0", "nib_archive"), (b"MTLB\x01\x80\x02\0", "metallib"),
    (b"\x7fELF\x02\x01\x01", "elf"), (b"%PDF-1.5\r", "pdf"), (b"KTX " .replace(b"KTX ", b"\xabKTX 11\xbb\r\n\x1a\n") + b"\0" * 8, "ktx"),
    (b"#!/bin/sh\necho hi\n", "shebang"), (b"{\"a\": 1}", "json"), (b"hello world\n", "text"),
    (b"<!DOCTYPE html><html>", "html"), (b"", "empty"), (b"\x00\x01\x02\xfe\xfd\xfc\x80\x81", "unknown"),
]


@pytest.mark.parametrize("head,expected", MAGIC_CASES, ids=[c[1] + str(i) for i, c in enumerate(MAGIC_CASES)])
def test_sniff(head, expected):
    t, conf = magic.sniff(head)
    assert t == expected and 0.0 <= conf <= 1.0
    assert (conf >= magic.STRONG_CONFIDENCE) or expected in ("unknown", "text", "json", "xml")


def test_pe_verified_by_pe_signature():
    pe = bytearray(b"MZ" + b"\0" * 62 + b"\0" * 64)
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\0\0"
    assert magic.sniff(bytes(pe)) == ("pe", 0.95)
    assert magic.sniff(b"MZ" + b"\0" * 100)[1] < magic.STRONG_CONFIDENCE      # DOS stub only: weak


def test_mpeg_audio_frame_and_weak_bmp_ico():
    assert magic.sniff(b"\xff\xfb\x90\x00" + b"\0" * 8) == ("mp3", 0.5)
    assert magic.sniff(b"BM" + b"\xaa" * 20)[1] < magic.STRONG_CONFIDENCE
    assert magic.sniff(b"\0\0\1\0\x02\0" + b"\0" * 20) == ("ico", 0.5)


def test_macho_header_info_and_fat_vs_java():
    assert magic.macho_header_info(FAT) == {"fat": True, "bits": 32, "endian": ">", "nfat": 2}
    assert magic.macho_header_info(JAVA) is None
    assert magic.macho_header_info(b"\xcf\xfa\xed\xfe" + b"\0" * 4)["bits"] == 64


def test_sniff_tail_ue_pak():
    assert magic.sniff_tail(b"\0" * 100 + struct.pack("<I", 0x5A6F12E1) + b"\0" * 40)[0] == "ue_pak"
    assert magic.sniff_tail(b"\0" * 200)[0] == "unknown"


def test_sniff_never_raises_on_random_prefixes():
    import os
    for _ in range(300):
        magic.sniff(os.urandom(64))
    for n in range(0, 12):
        magic.sniff(b"\xca\xfe\xba\xbe"[:n])
        magic.sniff(b"RIFF\0\0\0\0WEBP"[:n])


# --- filetypes ---------------------------------------------------------------------------------
def test_rules_file_is_consistent():
    doc = json.loads((resource_dir("data") / "filetypes.json").read_text(encoding="utf-8"))
    assert tuple(doc["categories"]) == filetypes.CATEGORIES
    seen = {}
    for cat, exts in doc["ext_categories"].items():
        for e in exts:
            assert e == e.lower() and e.startswith("."), e
            assert e not in seen, "%s in %s and %s" % (e, cat, seen[e])
            seen[e] = cat
    seen = {}
    for cat, ids in doc["magic_categories"].items():
        for m in ids:
            assert m not in seen and m in magic.MAGIC_IDS, m
            seen[m] = cat
    filetypes.parse_rules(doc)
    bad = dict(doc, ext_categories={"nonsense": [".x"]})
    with pytest.raises(ValueError):
        filetypes.parse_rules(bad)


C = filetypes.classify
CLASS_CASES = [
    # (rel path, magic, confidence, expected)
    ("Foo", "macho", 0.98, "executable"), ("Frameworks/X.framework/X", "macho", 0.98, "framework"),
    ("Frameworks/libz.dylib", "macho", 0.98, "dylib"), ("PlugIns/E.appex/E", "macho", 0.98, "plugin"),
    ("Watch/W.app/W", "macho", 0.98, "plugin"), ("PlugIns/E.appex/Frameworks/F.framework/F", "macho", 0.98, "framework"),
    ("Assets.car", "bomstore", 0.99, "assets_car"), ("Base.lproj/Main.storyboardc/Info.plist", "bplist", 0.97, "ui_layout"),
    ("Base.lproj/Main.storyboardc/UIViewController-abc.nib", "nib_archive", 0.95, "ui_layout"),
    ("en.lproj/Localizable.strings", "bplist", 0.97, "localization"), ("en.lproj/InfoPlist.strings", "text", 0.5, "localization"),
    ("Info.plist", "bplist", 0.97, "plist"), ("Info.plist", "plist_xml", 0.95, "plist"),
    ("icon.png", "png", 0.99, "image"), ("a.dat", "png", 0.99, "image"), ("photo.png", "unknown", 0.0, "image"),
    ("bg.mp3", "mp3", 0.85, "audio"), ("clip.mov", "mov", 0.97, "video"), ("f.ttf", "ttf", 0.85, "font"),
    ("db.sqlite", "sqlite", 0.99, "database"), ("x.lua", "text", 0.5, "script"), ("x.luac", "lua_bytecode", 0.97, "script"),
    ("main.jsbundle", "hermes_bytecode", 0.9, "script"), ("default.metallib", "metallib", 0.9, "shader"),
    ("x.metal", "text", 0.5, "shader"), ("m.fbx", "unknown", 0.0, "model_3d"), ("heart.scn", "bplist", 0.97, "model_3d"),
    ("Data/Managed/Metadata/global-metadata.dat", "il2cpp_metadata", 0.97, "engine_data"),
    ("Data/Managed/Metadata/global-metadata.dat", "unknown", 0.0, "engine_data"),
    ("Data/Raw/aa/bundle1.dat", "unityfs", 0.99, "assetbundle"), ("Data/level0", "unknown", 0.0, "engine_data"),
    ("Data/globalgamemanagers", "unknown", 0.0, "engine_data"), ("Data/sharedassets0.assets.resS", "unknown", 0.0, "engine_data"),
    ("Data/Managed/Assembly-CSharp.dll", "pe", 0.95, "executable"), ("Data/Managed/Assembly-CSharp.dll", "unknown", 0.0, "executable"),
    ("res/game.pak", "unknown", 0.0, "packed_archive"), ("data.pck", "gdpc", 0.9, "packed_archive"), ("x.bin", "zip", 0.95, "packed_archive"),
    ("_CodeSignature/CodeResources", "plist_xml", 0.95, "signing"), ("SC_Info/Foo.sinf", "unknown", 0.0, "signing"),
    ("embedded.mobileprovision", "unknown", 0.0, "signing"), ("settings.json", "json", 0.6, "config"),
    ("README", "text", 0.5, "text"), ("notes.txt", "text", 0.5, "text"), ("blob.bin", "unknown", 0.0, "other"),
    ("noext", "unknown", 0.0, "other"), ("weird.png", "unreadable", 0.0, "image"), ("note", "text", 0.5, "text"),
    ("data.json", "png", 0.99, "image"),                                  # magic beats the extension
    ("fake.png", "macho", 0.98, "executable"),
    ("maybe.bmp", "bmp", 0.3, "image"), ("x.dll", "pe", 0.5, "executable"),
    ("clip.xyz", "matroska", 0.9, "video"),
]


@pytest.mark.parametrize("rel,mg,conf,expected", CLASS_CASES)
def test_classify(rel, mg, conf, expected):
    assert C(rel, mg, conf) == expected


def test_classify_outside_app_and_scope():
    assert C("iTunesMetadata.plist", "bplist", 0.97, in_app=False) == "signing"
    assert C("iTunesMetadata.plist", "bplist", 0.97, in_app=True) == "plist"
    assert C("iTunesArtwork@2x", "png", 0.99, in_app=False) == "signing"
    assert C("Symbols/x.bin", "unknown", 0.0, in_app=False) == "other"


def test_weak_magic_does_not_override_extension():
    assert C("sound.wav", "mp3", 0.5) == "audio"
    assert C("blob.png", "bmp", 0.3) == "image"
    assert C("blob", "bmp", 0.3) == "image"            # nothing else known: weak magic is used
    assert C("a.txt", "ico", 0.5) == "text"


def test_file_ext():
    assert filetypes.file_ext("a/b/Foo.PNG") == ".png" and filetypes.file_ext("a.tar.gz") == ".gz"
    assert filetypes.file_ext("a.b/noext") == "" and filetypes.file_ext(".DS_Store") == ""


def test_load_inventory_files_falls_back_to_full_file(tmp_path):
    (tmp_path / "inventory.json").write_text(json.dumps({"files": [{"path": "a"}, {"path": "b"}]}), encoding="utf-8")
    inv = {"files": [{"path": "a"}], "files_truncated": True, "inventory_file": "inventory.json"}
    assert [f["path"] for f in filetypes.load_inventory_files(inv, tmp_path)] == ["a", "b"]
    assert len(filetypes.load_inventory_files(dict(inv, files_truncated=False), tmp_path)) == 1
    assert len(filetypes.load_inventory_files(inv, tmp_path / "missing")) == 1
