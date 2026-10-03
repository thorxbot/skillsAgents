"""Error classification and log redaction."""
from __future__ import annotations

from pathlib import Path

import pytest

from ipa_analyzer.il2cpp import Il2CppErrorCode as E
from ipa_analyzer.il2cpp import errors as X
from ipa_analyzer.il2cpp.tools import load_catalog

PATTERNS = load_catalog()["backends"]["il2cppdumper"]["error_patterns"]
DOTNET = load_catalog()["dotnet"]


def cls(lines, **kw):
    return X.classify_output(lines, PATTERNS, missing_framework_markers=DOTNET["missing_framework_markers"],
                             missing_framework_rc=DOTNET["missing_framework_exit_code"], **kw)


@pytest.mark.parametrize("lines,code", [
    (["ERROR: Metadata file not found or encrypted."], E.E_METADATA_ENCRYPTED),
    (["System.InvalidDataException: ERROR: Metadata file supplied is not valid metadata file."], E.E_METADATA_ENCRYPTED),
    (["System.NotSupportedException: ERROR: Metadata file supplied is not a supported version[35]."],
     E.E_METADATA_VERSION_UNSUPPORTED),
    (["ERROR: Can't use auto mode to process file, try manual mode."], E.E_REGISTRATION_NOT_FOUND),
    (["Input CodeRegistration: "], E.E_REGISTRATION_NOT_FOUND),
    (["ERROR: This file may be protected."], E.E_REGISTRATION_NOT_FOUND),
    (["Searching...", "ERROR: An error occurred while processing."], E.E_REGISTRATION_NOT_FOUND),
    (["You must install or update .NET to run this application."], E.E_DOTNET_MISSING),
    (["System.NotSupportedException: ERROR: il2cpp file not supported."], E.E_UNKNOWN),
])
def test_classification(lines, code):
    assert cls(lines).code == code


def test_specific_pattern_beats_generic_one():
    # both lines present: the metadata message is listed first and must win over the generic failure line
    got = cls(["ERROR: An error occurred while processing.", "ERROR: Metadata file not found or encrypted."])
    assert got.code == E.E_METADATA_ENCRYPTED


def test_version_group_is_extracted():
    got = cls(["x not a supported version[31.1]"])
    assert got.groups == {"ver": "31.1"} and "31.1" in got.message


def test_missing_framework_exit_code_alone_is_enough():
    assert cls(["no text"], returncode=150).code == E.E_DOTNET_MISSING
    assert cls(["no text"], returncode=1) is None


def test_prompt_is_the_last_resort():
    got = cls(["Dumping..."], prompt="Press any key to exit...")
    assert got.code == E.E_UNKNOWN and "waiting for interactive input" in got.message
    assert cls(["Done!"]) is None


def test_bad_pattern_entries_are_skipped():
    got = X.classify_output(["boom"], [{"pattern": "(", "code": "E_UNKNOWN"}, {"pattern": "boom", "code": "NOPE"},
                                       {"pattern": "boom", "code": "E_TIMEOUT"}])
    assert got.code == E.E_TIMEOUT


def test_every_code_has_title_remediation_and_i18n_keys():
    import json
    from ipa_analyzer.util.paths import resource_dir
    for lang in ("zh", "en"):
        data = json.loads((resource_dir("data") / "i18n" / lang / "il2cpp.json").read_text(encoding="utf-8"))
        for code in E:
            assert X.title_for(code) and X.remediation_for(code)
            assert data[X.i18n_error_key(code)] and data[X.i18n_remediation_key(code)], (lang, code)


def test_redaction():
    home = Path("/Users/alice")
    assert X.redact_text("loading /Users/alice/Library/x.dll", home=home) == "loading ~/Library/x.dll"
    assert "bob" not in X.redact_text("at /Users/bob/proj/Program.cs:line 3")
    assert "<user>" in X.redact_text(r"C:\Users\Carol\AppData\Local\x")
    assert "dave" not in X.redact_text("/home/dave/.cache/ipa-analyzer")
    assert X.redact_text("") == ""
    assert X.redact_lines(["a /Users/zed/x"], home=Path("/nonexistent/h")) == ["a /Users/<user>/x"]
    assert X.tail_lines(list("abcdef"), 3) == ["d", "e", "f"] and X.tail_lines(["a"], 0) == []
