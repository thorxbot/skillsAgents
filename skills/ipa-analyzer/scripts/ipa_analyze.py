#!/usr/bin/env python3
"""Run ipa-analyzer without installing it: ``python scripts/ipa_analyze.py analyze app.ipa``."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ipa_analyzer.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
