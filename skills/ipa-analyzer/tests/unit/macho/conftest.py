"""Helpers shared by the Mach-O tests."""
from __future__ import annotations

import threading

import pytest


@pytest.fixture()
def within():
    """``within(seconds, fn, *args)``: run ``fn`` in a thread; fail the test if it does not finish in time."""

    def _run(seconds, fn, *args, **kwargs):
        box = {}

        def target():
            try:
                box["value"] = fn(*args, **kwargs)
            except BaseException as exc:  # noqa: BLE001 - re-raised in the test thread
                box["error"] = exc

        t = threading.Thread(target=target, daemon=True)
        t.start()
        t.join(seconds)
        assert not t.is_alive(), "operation did not finish within %ss (hang?)" % seconds
        if "error" in box:
            raise box["error"]
        return box.get("value")

    return _run
