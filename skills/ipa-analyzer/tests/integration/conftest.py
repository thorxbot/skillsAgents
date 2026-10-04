"""Fixtures for the end-to-end tests (helpers live in ``fixtures/e2e_support.py``)."""
from __future__ import annotations

from pathlib import Path

import pytest

from fixtures.e2e_support import Runs
from fixtures.full_ipa_builders import build_all


@pytest.fixture(scope="session")
def runs(tmp_path_factory) -> Runs:
    base = tmp_path_factory.mktemp("e2e")
    ipas = build_all(base / "ipas")
    home = base / "home"
    home.mkdir()
    return Runs(ipas, base, home)


@pytest.fixture(scope="session")
def home_dir(runs: Runs) -> Path:
    return runs.home
