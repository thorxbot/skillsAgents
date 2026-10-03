from __future__ import annotations

import plistlib

import pytest

from ipa_analyzer.meta.strings_file import (decode_strings_bytes, lang_from_lproj, lang_rank, normalize_lang,
                                            parse_strings_file, parse_strings_text)

SAMPLE = '/* comment */\n"CFBundleDisplayName" = "你好 App";\n// line comment\n"NSCameraUsageDescription" = "Need \\"camera\\"\\nline2";\n'


def test_utf8_text():
    r = parse_strings_file(SAMPLE.encode("utf-8"))
    assert r == {"CFBundleDisplayName": "你好 App", "NSCameraUsageDescription": 'Need "camera"\nline2'}


@pytest.mark.parametrize("enc,bom", [("utf-16-le", b"\xff\xfe"), ("utf-16-be", b"\xfe\xff"),
                                      ("utf-8", b"\xef\xbb\xbf")])
def test_bom_variants(enc, bom):
    body = SAMPLE.encode(enc)
    r = parse_strings_file(bom + body)
    assert r["CFBundleDisplayName"] == "你好 App"


@pytest.mark.parametrize("enc", ["utf-16-le", "utf-16-be"])
def test_utf16_without_bom_is_sniffed(enc):
    r = parse_strings_file(SAMPLE.encode(enc))
    assert r["CFBundleDisplayName"] == "你好 App"


def test_binary_and_xml_plist():
    d = {"CFBundleDisplayName": "二进制", "n": 3}
    for fmt in (plistlib.FMT_BINARY, plistlib.FMT_XML):
        assert parse_strings_file(plistlib.dumps(d, fmt=fmt)) == {"CFBundleDisplayName": "二进制"}


def test_escapes_unicode_and_octal():
    t = r'"a" = "\U4F60\u597D"; "b" = "\101\102"; "c" = "tab\there"; "d" = "\UD83D\UDE00"; "e" = "back\\slash"; "f"="\q";'
    r = parse_strings_text(t)
    assert r["a"] == "你好" and r["b"] == "AB" and r["c"] == "tab\there"
    assert r["d"] == "\U0001F600" and r["e"] == "back\\slash" and r["f"] == "q"


def test_lone_surrogate_does_not_crash():
    assert parse_strings_text(r'"a" = "\UD83Dx";')["a"] == "\ufffdx"


def test_unquoted_and_shorthand_and_multiline_and_duplicates():
    t = 'key1 = value1;\nshort;\n"m" = "line1\nline2";\n"k" = "first";\n"k" = "second";\n'
    r = parse_strings_text(t)
    assert r["key1"] == "value1" and r["short"] == "short" and r["m"] == "line1\nline2" and r["k"] == "second"


def test_wrapped_in_braces():
    assert parse_strings_text('{ "a" = "b"; }') == {"a": "b"}


def test_nested_values_skipped_and_parsing_continues():
    t = '"x" = { a = (1,2,"3;"); b = "}"; };\n"y" = "ok";\n"z" = (1, 2);\n"w" = "fine";'
    assert parse_strings_text(t) == {"y": "ok", "w": "fine"}


def test_malformed_recovers():
    t = '"a" = "ok";\n"bad" "oops";\n= = ;\n"c" = "also ok";\n"unterminated" = "abc'
    r = parse_strings_text(t)
    assert r["a"] == "ok" and r["c"] == "also ok"
    assert r.get("unterminated") == "abc"      # best effort for a truncated tail


@pytest.mark.parametrize("data", [b"", b"\x00\x01\x02\xff\xfe\xfd", b"/* never closed", b"\"", b";;;;", b"bplist00garbage"])
def test_garbage_never_raises(data):
    assert isinstance(parse_strings_file(data), dict)


def test_non_bytes_input():
    assert parse_strings_file(None) == {}      # type: ignore[arg-type]


def test_decode_prefers_utf8_for_plain_ascii():
    assert decode_strings_bytes(b'"a"="b";') == '"a"="b";'


@pytest.mark.parametrize("raw,expected", [
    ("zh-Hans", "zh-Hans"), ("zh_CN", "zh-Hans"), ("zh-Hans-CN", "zh-Hans"), ("zh-SG", "zh-Hans"),
    ("zh-Hant", "zh-Hant"), ("zh_TW", "zh-Hant"), ("zh-HK", "zh-Hant"), ("zh-Hant-TW", "zh-Hant"), ("zh", "zh"),
    ("en", "en"), ("en_GB", "en-GB"), ("EN-us", "en-US"), ("English", "en"), ("Japanese", "ja"),
    ("Base", "Base"), ("base", "Base"), ("pt_BR", "pt-BR"), ("sr-latn", "sr-Latn"), ("es-419", "es-419"), ("", ""),
])
def test_normalize_lang(raw, expected):
    assert normalize_lang(raw) == expected


def test_lang_from_lproj():
    assert lang_from_lproj("zh-Hans.lproj") == "zh-Hans"
    assert lang_from_lproj("Payload/x/en_GB.lproj/") == "en-GB"
    assert lang_from_lproj("English.lproj") == "en"


def test_lang_rank_order():
    langs = ["ja", "Base", "en-US", "en", "zh-Hant", "zh", "zh-Hans", "fr"]
    assert sorted(langs, key=lang_rank) == ["zh-Hans", "zh", "zh-Hant", "en", "en-US", "Base", "fr", "ja"]
