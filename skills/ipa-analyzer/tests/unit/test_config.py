from __future__ import annotations

import json
from pathlib import Path

import pytest

from ipa_analyzer.config import Config, parse_size
from ipa_analyzer.errors import UsageError


def test_defaults():
    c = Config()
    assert c.il2cpp.timeout_s == 900 and c.il2cpp.enabled and not c.il2cpp.force_dump
    assert c.unity.bundle_deep_sample == 200
    assert c.limits.max_ratio == 200 and c.limits.max_files == 200_000
    assert c.redact and c.signature_integrity and not c.offline and not c.assume_yes


def test_dict_roundtrip_is_json_serialisable():
    c = Config(output_dir=Path("o"), stages=("meta",), skip=("libs",), libs_user_path=Path("l.json"))
    c.il2cpp.backend_order = ["a", "b"]
    d = c.to_dict()
    json.dumps(d)
    c2 = Config.from_dict(d)
    assert c2.to_dict() == d
    assert c2.stages == ("meta",) and c2.libs_user_path == Path("l.json")


@pytest.mark.parametrize("kw", [{"lang": "fr"}, {"formats": ("pdf",)}, {"extract": ("nope",)}])
def test_validate_rejects(kw):
    with pytest.raises(UsageError):
        Config(**kw).validate()


@pytest.mark.parametrize("text,expected", [("1024", 1024), ("1k", 1024), ("64M", 64 * 1024 ** 2),
                                            ("2GiB", 2 * 1024 ** 3), ("1.5g", int(1.5 * 1024 ** 3))])
def test_parse_size(text, expected):
    assert parse_size(text) == expected


@pytest.mark.parametrize("bad", ["", "abc", "-1", "12x"])
def test_parse_size_bad(bad):
    with pytest.raises(UsageError):
        parse_size(bad)
