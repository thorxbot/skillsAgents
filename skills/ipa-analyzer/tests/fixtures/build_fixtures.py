#!/usr/bin/env python3
"""Aggregate entry point of the synthetic fixtures: writes every whole-package IPA of ``full_ipa_builders``.

    python tests/fixtures/build_fixtures.py OUT_DIR [name ...]     # all fixtures, or only the named ones
    python tests/fixtures/build_fixtures.py --list

The per-work-package builders (``ipa_builder``, ``macho_builder``, ``formats_builder``, ``unity_builder``,
``unity_hotfix_builder``, ``engine_builder``, ``engine_checker_builder``) are imported from here by the tests as
``fixtures.<module>``; the fake Il2CppDumper is ``fake_dumper.py``. Nothing is, or is derived from, a real app.
"""
from __future__ import annotations

import sys
from pathlib import Path

_TESTS = Path(__file__).resolve().parent.parent
for _p in (str(_TESTS), str(_TESTS.parent / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fixtures.full_ipa_builders import DUMPER_SCRIPT, FIXTURES, build_all, build_fixture  # noqa: E402


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if args else 1
    if args[0] == "--list":
        for name, spec in FIXTURES.items():
            print("%-32s %s" % (name, spec.description))
        return 0
    out, names = Path(args[0]), args[1:]
    unknown = [n for n in names if n not in FIXTURES]
    if unknown:
        print("unknown fixture(s): %s (see --list)" % ", ".join(unknown), file=sys.stderr)
        return 1
    paths = {n: build_fixture(n, out) for n in names} if names else build_all(out)
    for name, p in paths.items():
        print("%-32s %8d bytes  %s" % (name, p.stat().st_size, p))
    print("fake Il2CppDumper for --il2cpp-tool: %s" % DUMPER_SCRIPT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
