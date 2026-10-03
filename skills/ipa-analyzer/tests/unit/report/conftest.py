"""Fixtures for the report tests (helpers live in ``fixtures.sample_report``)."""
from __future__ import annotations

import pytest

from fixtures.sample_report import FIXTURE_NAMES, make_catalog, report_dict


@pytest.fixture(params=["zh", "en"])
def lang(request):
    return request.param


@pytest.fixture()
def catalog(lang):
    return make_catalog(lang)


@pytest.fixture(params=FIXTURE_NAMES)
def fixture_name(request):
    return request.param


@pytest.fixture()
def rdict(fixture_name):
    return report_dict(fixture_name)
