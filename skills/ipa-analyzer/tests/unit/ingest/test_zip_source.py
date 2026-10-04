from __future__ import annotations

import io
import os
import zipfile
import zlib

import pytest

from fixtures.ipa_builder import ZipBuilder, build_ipa, build_zip_bytes
from ipa_analyzer.errors import InvalidInput, LimitExceeded
from ipa_analyzer.ingest import ArchiveSource
from ipa_analyzer.ingest.source import DirSource, ZipSource, open_source


def _write(tmp_path, data: bytes, name="x.ipa"):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_roundtrip_matches_zipfile(tmp_path):
    files = {"Info.plist": b"plist" * 100, "bin/a": bytes(range(256)) * 50, "empty": b"", "dir/sub/z.txt": "héllo"}
    p = build_ipa(tmp_path / "a.ipa", files)
    with zipfile.ZipFile(p) as zf:                       # the builder output is a valid zip
        assert zf.testzip() is None
        expected = {n: zf.read(n) for n in zf.namelist() if not n.endswith("/")}
    src = open_source(p)
    assert isinstance(src, ArchiveSource) and src.kind == "zip"
    got = {e.name: e for e in src.namelist()}
    assert set(got) == set(zipfile.ZipFile(p).namelist())
    for n, data in expected.items():
        assert src.stat(n).size == len(data)
        with src.open(n) as fh:
            assert fh.read() == data
        assert src.read_head(n, 7) == data[:7]
    assert got["Payload/"].is_dir and got["Payload/Test.app/"].is_dir
    with pytest.raises(KeyError):
        src.stat("missing")
    with pytest.raises(KeyError):
        src.open("missing")
    src.close()


def test_read_head_beyond_size_and_zero(tmp_path):
    p = build_ipa(tmp_path / "a.ipa", {"f": b"abc"})
    src = ZipSource(p)
    assert src.read_head("Payload/Test.app/f", 100) == b"abc"
    assert src.read_head("Payload/Test.app/f", 0) == b""
    src.close()


@pytest.mark.parametrize("compress", [True, False])
def test_seek_and_backward_seek(tmp_path, compress):
    data = os.urandom(300_000) + b"tail-marker"
    p = build_ipa(tmp_path / "a.ipa", {"big": data}, compress=compress)
    for mem_limit in (10_000_000, 1000):                  # materialise in memory / restart the stream
        src = ZipSource(p, memory_limit=mem_limit)
        with src.open("Payload/Test.app/big") as fh:
            assert fh.read(10) == data[:10]
            fh.seek(250_000)
            assert fh.read(5) == data[250_000:250_005]
            fh.seek(100)                                  # backward
            assert fh.read(5) == data[100:105]
            fh.seek(-11, os.SEEK_END)
            assert fh.read() == b"tail-marker"
            assert fh.tell() == len(data)
        src.close()


def test_spill_dir_used_for_large_backward_seek(tmp_path):
    data = os.urandom(200_000)
    p = build_ipa(tmp_path / "a.ipa", {"big": data})
    spill = tmp_path / "spill"
    src = ZipSource(p, memory_limit=100, spill_dir=spill, spill_limit=10_000_000)
    with src.open("Payload/Test.app/big") as fh:
        fh.read(150_000)
        fh.seek(10)
        assert fh.read(20) == data[10:30]
        assert spill.is_dir()
        fh.seek(199_990)
        assert fh.read() == data[199_990:]
    src.close()


def test_zip64_records(tmp_path):
    p = build_ipa(tmp_path / "z64.ipa", {"Info.plist": b"x" * 1000, "b/c": b"hello"}, zip64=True)
    src = open_source(p)
    assert {e.name: e.size for e in src.namelist() if not e.is_dir}["Payload/Test.app/Info.plist"] == 1000
    assert src.read_head("Payload/Test.app/b/c", 10) == b"hello"
    src.close()


def test_prepended_data_is_tolerated(tmp_path):
    p = build_ipa(tmp_path / "sfx.ipa", {"f": b"data"}, prefix_junk=b"MZ" + b"\0" * 1000)
    src = open_source(p)
    assert src.read_head("Payload/Test.app/f", 10) == b"data"
    assert any("precede" in w for w in src.warnings)
    src.close()


def test_non_utf8_names_fall_back_to_cp437_and_warn(tmp_path):
    gbk = "中文.txt".encode("gbk")
    zb = ZipBuilder()
    zb.add(gbk, b"a")                                           # bit 11 clear, not UTF-8
    zb.add(b"bad\xff\xfe.txt", b"b", utf8_flag=True)            # bit 11 set but invalid UTF-8
    zb.add("é.txt".encode("utf-8"), b"c", utf8_flag=False)      # bit 11 clear but valid UTF-8 (common in the wild)
    zb.add("ünï/ok.txt", b"d")                                  # properly flagged
    p = _write(tmp_path, zb.finish())
    src = ZipSource(p)
    names = [e.name for e in src.namelist()]
    assert gbk.decode("cp437") in names and "bad\xff\xfe.txt".encode("latin-1").decode("cp437") in names
    assert "é.txt" in names and "ünï/ok.txt" in names
    assert any("CP437" in w for w in src.warnings)
    assert src.read_head(gbk.decode("cp437"), 5) == b"a"
    src.close()


def test_unicode_path_extra_field_preferred(tmp_path):
    import struct
    raw = b"\xd6\xd0.txt"
    up = struct.pack("<BL", 1, zlib.crc32(raw) & 0xFFFFFFFF) + "中.txt".encode("utf-8")
    extra = struct.pack("<HH", 0x7075, len(up)) + up
    data = b"hello"
    crc = zlib.crc32(data) & 0xFFFFFFFF
    lh = struct.pack("<4sHHHHHLLLHH", b"PK\x03\x04", 20, 0, 0, 0, 0x21, crc, 5, 5, len(raw), 0) + raw + data
    cd = struct.pack("<4sBBHHHHHLLLHHHHHLL", b"PK\x01\x02", 20, 3, 20, 0, 0, 0, 0x21, crc, 5, 5, len(raw), len(extra),
                     0, 0, 0, 0o100644 << 16, 0) + raw + extra
    eocd = struct.pack("<4sHHHHLLH", b"PK\x05\x06", 0, 0, 1, 1, len(cd), len(lh), 0)
    src = ZipSource(_write(tmp_path, lh + cd + eocd))
    assert [e.name for e in src.namelist()] == ["中.txt"]
    src.close()


def test_duplicate_names_last_wins_with_warning(tmp_path):
    zb = ZipBuilder()
    zb.add("a.txt", b"first")
    zb.add("a.txt", b"second!")
    src = ZipSource(_write(tmp_path, zb.finish()))
    assert len(src.namelist()) == 1 and src.read_head("a.txt", 20) == b"second!"
    assert any("duplicate" in w for w in src.warnings)
    src.close()


def test_backslash_names_normalised_for_dos_hosts(tmp_path):
    zb = ZipBuilder()
    zb.add("Payload\\A.app\\Info.plist", b"x", system=0)
    zb.add("./Payload/A.app/f", b"y")
    src = ZipSource(_write(tmp_path, zb.finish()))
    assert {e.name for e in src.namelist()} == {"Payload/A.app/Info.plist", "Payload/A.app/f"}
    src.close()


def test_symlink_entries_flagged(tmp_path):
    p = build_ipa(tmp_path / "s.ipa", {"real": b"x"}, symlinks={"Frameworks/Current": "A"})
    src = ZipSource(p)
    e = src.stat("Payload/Test.app/Frameworks/Current")
    assert e.is_symlink and not e.is_dir and src.symlink_target("Payload/Test.app/Frameworks/Current") == "A"
    assert not src.stat("Payload/Test.app/real").is_symlink
    src.close()


def test_empty_zip_lists_nothing(tmp_path):
    src = ZipSource(_write(tmp_path, build_zip_bytes({})))
    assert src.namelist() == []
    src.close()


def test_zero_byte_and_garbage_inputs(tmp_path):
    with pytest.raises(InvalidInput, match="empty"):
        open_source(_write(tmp_path, b"", "e.ipa"))
    with pytest.raises(InvalidInput, match="unsupported"):
        open_source(_write(tmp_path, b"just some text, not an archive" * 5, "t.ipa"))
    with pytest.raises(InvalidInput, match="does not exist"):
        open_source(tmp_path / "nope.ipa")
    gz = _write(tmp_path, b"\x1f\x8b\x08" + b"\0" * 100, "x.ipa")
    with pytest.raises(InvalidInput, match="gzip"):
        open_source(gz)


def test_extension_is_not_trusted(tmp_path):
    p = build_ipa(tmp_path / "renamed.bin", {"f": b"x"})
    src = open_source(p)
    assert src.kind == "zip"
    src.close()


@pytest.mark.parametrize("cut", [1, 10, 22, 100, 500, "half"])
def test_truncated_zip_raises_invalid_input(tmp_path, cut):
    full = build_ipa(tmp_path / "f.ipa", {"Info.plist": b"x" * 5000, "a": os.urandom(4000)}).read_bytes()
    data = full[: len(full) // 2] if cut == "half" else full[:-cut]
    with pytest.raises(InvalidInput):
        open_source(_write(tmp_path, data, "t.ipa"))


def test_corrupt_central_directory(tmp_path):
    full = bytearray(build_ipa(tmp_path / "f.ipa", {"a": b"x" * 100}).read_bytes())
    cd = full.rfind(b"PK\x01\x02")
    full[cd:cd + 4] = b"XXXX"
    with pytest.raises(InvalidInput, match="corrupt central directory"):
        ZipSource(_write(tmp_path, bytes(full), "c.ipa"))


def test_corrupt_deflate_stream_raises_on_read(tmp_path):
    zb = ZipBuilder()
    zb.add("bad", b"x" * 1000, comp_data=b"\xff\x00garbage-not-deflate", method=8)
    src = ZipSource(_write(tmp_path, zb.finish()))
    with pytest.raises(InvalidInput):
        src.read_head("bad", 10)
    with pytest.raises(InvalidInput):
        src.extract_to("bad", tmp_path / "out.bin")
    assert not (tmp_path / "out.bin").exists()
    src.close()


def test_lying_size_header_cannot_expand_beyond_declared(tmp_path):
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    bomb = co.compress(b"\0" * 5_000_000) + co.flush()
    zb = ZipBuilder()
    zb.add("liar", b"y" * 10, comp_data=bomb, method=8)           # declares 10 bytes, inflates to 5 MB
    src = ZipSource(_write(tmp_path, zb.finish()))
    with pytest.raises(InvalidInput, match="beyond its declared size"):
        with src.open("liar") as fh:
            fh.read()
    src.close()


def test_extract_verifies_crc(tmp_path):
    zb = ZipBuilder()
    zb.add("c", b"abc", comp_data=b"abd", method=0)               # crc of "abc", payload "abd"
    src = ZipSource(_write(tmp_path, zb.finish()))
    with pytest.raises(InvalidInput, match="verification"):
        src.extract_to("c", tmp_path / "o" / "c")
    assert not (tmp_path / "o" / "c").exists()
    src.close()


def test_extract_to_ok_and_directories(tmp_path):
    p = build_ipa(tmp_path / "a.ipa", {"d/f.bin": b"payload" * 1000})
    src = ZipSource(p)
    out = src.extract_to("Payload/Test.app/d/f.bin", tmp_path / "deep" / "dir" / "f.bin")
    assert out.read_bytes() == b"payload" * 1000
    d = src.extract_to("Payload/", tmp_path / "dd")
    assert d.is_dir()
    src.close()


def test_unsupported_method_and_encrypted_entry(tmp_path):
    zb = ZipBuilder()
    zb.add("m", b"data", comp_data=b"zzzz", method=99)
    src = ZipSource(_write(tmp_path, zb.finish()))
    with pytest.raises(InvalidInput, match="unsupported compression"):
        src.read_head("m", 4)
    src.close()


def test_max_entries_limit(tmp_path):
    p = build_ipa(tmp_path / "a.ipa", {"f%d" % i: b"x" for i in range(30)})
    with pytest.raises(LimitExceeded):
        ZipSource(p, max_entries=10)


def test_close_releases_streams(tmp_path):
    p = build_ipa(tmp_path / "a.ipa", {"f": b"x" * 100})
    src = ZipSource(p)
    fh = src.open("Payload/Test.app/f")
    src.close()
    assert fh.closed or fh.raw.closed
    with pytest.raises(ValueError):
        src.open("Payload/Test.app/f")
    p.unlink()                                                    # no handle left (matters on Windows)


# --- DirSource -----------------------------------------------------------------------------------
def _make_tree(root, files):
    for n, d in files.items():
        f = root / n
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(d if isinstance(d, bytes) else d.encode())


def test_dir_source_basic(tmp_path):
    _make_tree(tmp_path / "App.app", {"Info.plist": b"x", "a/b.bin": b"12345", "a/c/d": b""})
    (tmp_path / "App.app" / "emptydir").mkdir()
    src = open_source(tmp_path / "App.app")
    assert isinstance(src, DirSource) and src.kind == "dir"
    names = {e.name: e for e in src.namelist()}
    assert names["a/"].is_dir and names["emptydir/"].is_dir and names["a/b.bin"].size == 5
    assert src.read_head("a/b.bin", 3) == b"123"
    with src.open("a/b.bin") as fh:
        fh.seek(2)
        assert fh.read() == b"345"
    assert src.extract_to("a/b.bin", tmp_path / "o" / "b").read_bytes() == b"12345"
    with pytest.raises(KeyError):
        src.stat("zzz")


def test_dir_source_symlink_not_followed(tmp_path):
    root = tmp_path / "App.app"
    _make_tree(root, {"real": b"data"})
    try:
        os.symlink("real", root / "link")
        os.symlink(str(tmp_path), root / "outside")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported")
    src = DirSource(root)
    names = {e.name: e for e in src.namelist()}
    assert names["link"].is_symlink and names["outside"].is_symlink and not names["outside"].is_dir
    assert src.symlink_target("link") == "real"
    assert not any(n.startswith("outside/") for n in names)


def test_dir_source_limit_and_not_a_dir(tmp_path):
    _make_tree(tmp_path / "d", {"f%d" % i: b"x" for i in range(20)})
    with pytest.raises(LimitExceeded):
        DirSource(tmp_path / "d", max_entries=5)
    with pytest.raises(InvalidInput):
        DirSource(tmp_path / "d" / "f1")


# --- R1 regressions: malformed directory records ------------------------------------------------------
def _eocd(data: bytes) -> int:
    return data.rfind(b"PK\x05\x06")


def _with_zip64_hoff(data: bytes, hoff: int) -> bytes:
    """Rewrite the single central-directory record so its local header offset lives in a zip64 extra field."""
    import struct
    eocd = _eocd(data)
    cd_size, cd_off = struct.unpack_from("<LL", data, eocd + 12)
    rec = bytearray(data[cd_off:cd_off + cd_size])
    nlen, elen, clen = struct.unpack_from("<HHH", rec, 28)
    assert (elen, clen) == (0, 0) and len(rec) == 46 + nlen
    extra = struct.pack("<HHQ", 1, 8, hoff)
    struct.pack_into("<H", rec, 30, len(extra))
    struct.pack_into("<L", rec, 42, 0xFFFFFFFF)
    new_cd = bytes(rec[:46 + nlen]) + extra
    tail = bytearray(data[eocd:])
    struct.pack_into("<L", tail, 12, len(new_cd))
    return data[:cd_off] + new_cd + bytes(tail)


@pytest.mark.parametrize("hoff", [2 ** 63 + 5, 2 ** 64 - 1, 10 ** 12])
def test_huge_zip64_local_header_offset_is_invalid_input(tmp_path, hoff):
    single = build_zip_bytes({"Payload/A.app/x.bin": b"y" * 64}, compress=False)
    p = _write(tmp_path, _with_zip64_hoff(single, hoff), "z.ipa")
    src = ZipSource(p)                                  # opening works; only the bad entry is unreadable
    assert any("out-of-range" in w for w in src.warnings)
    name = [e.name for e in src.namelist() if not e.is_dir][0]
    with pytest.raises(InvalidInput):
        src.read_head(name, 8)
    with pytest.raises(InvalidInput):
        src.open(name).read()
    with pytest.raises(InvalidInput):
        src.extract_to(name, tmp_path / "out.bin")


def test_central_directory_beyond_end_of_file_is_rejected(tmp_path):
    """EOCD cd_size / cd_off pointing outside the file must be refused before anything is read (mutation M12)."""
    import struct
    data = bytearray(build_ipa(tmp_path / "f.ipa", {"a": b"x" * 100}).read_bytes())
    eocd = _eocd(bytes(data))
    cd_size, cd_off = struct.unpack_from("<LL", data, eocd + 12)
    bad_size = bytearray(data)
    struct.pack_into("<L", bad_size, eocd + 12, cd_size + 10_000)       # directory "ends" after the file
    with pytest.raises(InvalidInput, match="central directory lies outside the file"):
        ZipSource(_write(tmp_path, bytes(bad_size), "s.ipa"))
    bad_off = bytearray(data)
    struct.pack_into("<L", bad_off, eocd + 16, cd_off + 10_000)         # offset past the directory
    with pytest.raises(InvalidInput, match="central directory lies outside the file"):
        ZipSource(_write(tmp_path, bytes(bad_off), "o.ipa"))


def test_implausible_directory_size_rejected_before_reading_it(tmp_path, monkeypatch):
    import struct
    size = 20_000_000
    eocd = b"PK\x05\x06" + struct.pack("<HHHHLLH", 0, 0, 2, 2, size, 0, 0)
    p = _write(tmp_path, b"\0" * size + eocd, "big.ipa")
    reads = []
    real_open = open

    def spy(*a, **k):
        fh = real_open(*a, **k)
        orig = fh.read
        fh.read = lambda n=-1: (reads.append(n), orig(n))[1]
        return fh

    monkeypatch.setattr("ipa_analyzer.ingest.source.open", spy, raising=False)
    with pytest.raises(InvalidInput, match="implausibly large"):
        ZipSource(p)
    assert all(n < 1_000_000 for n in reads)             # the 20 MB "directory" was never read


def test_entry_count_limit_is_decided_from_the_end_record(tmp_path):
    p = build_ipa(tmp_path / "many.ipa", {"f%d" % i: b"x" for i in range(30)})
    with pytest.raises(LimitExceeded):
        ZipSource(p, max_entries=10)
