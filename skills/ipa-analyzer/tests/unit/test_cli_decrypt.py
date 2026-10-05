"""The ``decrypt`` CLI subcommand (operator-key decryption of a file or directory)."""
from __future__ import annotations

from ipa_analyzer import cli
from ipa_analyzer.crypto import ccz, xxtea

PVR = (0xAABBCCDD, 0x11223344, 0x55667788, 0x99AABBCC)


def test_decrypt_file_xxtea_with_sign(tmp_path, capsys):
    src = tmp_path / "main.lua"
    src.write_bytes(b"XXTEA" + xxtea.encrypt(b"local a=42 return a\n", "gamekey"))
    out = tmp_path / "main.dec.lua"
    code = cli.main(["decrypt", str(src), "--scheme", "xxtea", "--key", "gamekey", "--sign", "XXTEA", "-o", str(out)])
    assert code == 0 and out.read_bytes() == b"local a=42 return a\n"


def test_decrypt_file_ccz(tmp_path):
    src = tmp_path / "tex.ccz"
    src.write_bytes(ccz.encrypt_ccz(b"PVRTEXTURE" * 50, PVR))
    out = tmp_path / "tex.raw"
    code = cli.main(["decrypt", str(src), "--scheme", "ccz",
                     "--key", "aabbccdd 11223344 55667788 99aabbcc", "-o", str(out)])
    assert code == 0 and out.read_bytes() == b"PVRTEXTURE" * 50


def test_decrypt_file_xor_hex_key(tmp_path):
    src = tmp_path / "cfg.bin"
    src.write_bytes(bytes(b ^ 0x5A for b in b'{"k":1}'))
    out = tmp_path / "cfg.json"
    code = cli.main(["decrypt", str(src), "--scheme", "xor", "--key", "hex:5a", "-o", str(out)])
    assert code == 0 and out.read_bytes() == b'{"k":1}'


def test_decrypt_directory_mode(tmp_path):
    d = tmp_path / "in"
    (d / "sub").mkdir(parents=True)
    (d / "a.bin").write_bytes(bytes(b ^ 0x5A for b in b"alpha"))
    (d / "sub" / "b.bin").write_bytes(bytes(b ^ 0x5A for b in b"beta"))
    (d / "skip.txt").write_bytes(b"leave me")
    out = tmp_path / "out"
    code = cli.main(["decrypt", str(d), "--scheme", "xor", "--key", "hex:5a", "--glob", "*.bin", "-o", str(out)])
    assert code == 0
    assert (out / "a.bin").read_bytes() == b"alpha" and (out / "sub" / "b.bin").read_bytes() == b"beta"
    assert not (out / "skip.txt").exists()


def test_decrypt_wrong_key_is_partial(tmp_path):
    src = tmp_path / "x.dat"
    src.write_bytes(xxtea.encrypt(b"original payload here", "right"))
    code = cli.main(["decrypt", str(src), "--scheme", "xxtea", "--key", "wrong", "-o", str(tmp_path / "o")])
    assert code == 3                      # EXIT_PARTIAL: nothing decrypted


def test_decrypt_missing_input(tmp_path):
    assert cli.main(["decrypt", str(tmp_path / "nope"), "--scheme", "xor", "--key", "k"]) == 2
