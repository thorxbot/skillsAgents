"""The formats package must stay a standalone library: standard library imports only."""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import ipa_analyzer.formats as formats

PKG = Path(formats.__file__).parent
STDLIB = set(getattr(sys, "stdlib_module_names", ())) or {
    "__future__", "re", "struct", "lzma", "time", "dataclasses", "typing", "io", "zlib", "bz2",
}


def _imports(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield 0, a.name
        elif isinstance(node, ast.ImportFrom):
            yield node.level, node.module or ""


def test_formats_modules_import_only_stdlib_and_siblings():
    modules = sorted(PKG.glob("*.py"))
    assert {m.stem for m in modules} >= {
        "unityfs", "lz4", "lua_bytecode", "lua_source", "pe_cli", "magic_scan", "compress_sniff",
    }
    for path in modules:
        for level, name in _imports(path):
            if level == 1:  # sibling inside formats/
                continue
            assert level == 0, f"{path.name}: relative import beyond the package ({'.' * level}{name})"
            root = name.split(".")[0]
            assert root in STDLIB, f"{path.name} imports non-stdlib module {name}"
            assert root != "ipa_analyzer"
