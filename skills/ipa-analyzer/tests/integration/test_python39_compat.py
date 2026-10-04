"""Static guard for Python 3.9 (the lowest supported version), because the developer machine may run a newer one.

Found by running the whole suite on a real 3.9 interpreter: ``Path.write_text(..., newline=...)`` only exists since 3.10 and
silently broke the whole il2cpp success path.  This test catches that class of mistake on any interpreter.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parents[2]
FILES = sorted(p for d in ("src", "tests", "scripts") for p in (ROOT / d).rglob("*.py"))
NEW_CALLS = {"bit_count": "int.bit_count (3.10)", "pairwise": "itertools.pairwise (3.10)", "aiter": "aiter (3.10)",
             "anext": "anext (3.10)"}


def problems(text: str, name: str = "<src>") -> List[str]:
    try:
        tree = ast.parse(text, feature_version=(3, 9))
    except SyntaxError as exc:
        return ["%s:%s syntax newer than 3.9: %s" % (name, exc.lineno, exc.msg)]
    out: List[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        callee = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
        kws = {k.arg for k in node.keywords}
        if callee in ("write_text", "read_text") and "newline" in kws:
            out.append("%s:%d Path.%s(newline=) needs Python 3.10: use open(..., newline=)" % (name, node.lineno, callee))
        if callee == "zip" and "strict" in kws:
            out.append("%s:%d zip(strict=) needs Python 3.10" % (name, node.lineno))
        if callee == "dataclass" and kws & {"slots", "kw_only", "match_args"}:
            out.append("%s:%d dataclass(%s) needs Python 3.10" % (name, node.lineno, ", ".join(sorted(kws))))
        if callee in NEW_CALLS:
            out.append("%s:%d %s" % (name, node.lineno, NEW_CALLS[callee]))
    return out


def test_the_checker_flags_what_it_should():
    bad = ("from pathlib import Path\nPath('x').write_text('a', encoding='utf-8', newline='\\n')\n"
           "list(zip([1], [2], strict=True))\nmatch 1:\n    case 1: pass\n")
    assert problems("x = Path('a').write_text('a', newline='\\n')\n")
    assert problems("list(zip([1], [2], strict=True))\n")
    assert problems("match 1:\n    case 1:\n        pass\n")
    assert problems(bad)
    assert not problems("with open('x', 'w', encoding='utf-8', newline='\\n') as fh:\n    fh.write('a')\n")


def test_no_python_310_only_apis_in_src_tests_or_scripts():
    found: List[str] = []
    for f in FILES:
        found += problems(f.read_text(encoding="utf-8"), str(f.relative_to(ROOT)))
    assert not found, "\n" + "\n".join(found)


def test_every_source_module_has_future_annotations():
    """Runtime annotations such as ``X | None`` are only legal on 3.9 when annotations are not evaluated."""
    missing = []
    for f in (ROOT / "src").rglob("*.py"):
        text = f.read_text(encoding="utf-8")
        if f.name != "__init__.py" and text.strip() and "from __future__ import annotations" not in text:
            missing.append(str(f.relative_to(ROOT)))
    assert not missing, missing
