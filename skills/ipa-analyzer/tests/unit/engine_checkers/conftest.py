from __future__ import annotations

from pathlib import Path

import pytest

from fixtures import engine_checker_builder as B
from ipa_analyzer.analyzers.engines_other import EngineOtherStage
from ipa_analyzer.models import Status, Verdict


class Runner:
    """Build a synthetic app, run the ``engine.other`` stage and give convenient access to the result."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.n = 0
        self.ctxs = []

    def run(self, files, detect=(), **kw):
        self.n += 1
        d = self.tmp / ("c%d" % self.n)
        d.mkdir()
        ctx = B.make_ctx(d, files, detect=detect, **kw)
        self.ctxs.append(ctx)
        res = EngineOtherStage().run(ctx)
        return Result(ctx, res)

    def close(self) -> None:
        for c in self.ctxs:
            c.close()


class Result:
    def __init__(self, ctx, res) -> None:
        self.ctx, self.res = ctx, res
        self.status = res.status
        self.data = res.data or {}

    def finding(self, fid: str, engine: str):
        hits = [f for f in self.res.findings if f.id == fid and "engine:%s" % engine in f.tags]
        assert len(hits) == 1, "%s/%s: %d findings (%s)" % (fid, engine, len(hits), [f.id for f in self.res.findings])
        return hits[0]

    def verdict(self, fid: str, engine: str) -> Verdict:
        return self.finding(fid, engine).verdict


@pytest.fixture()
def runner(tmp_path):
    r = Runner(tmp_path)
    yield r
    r.close()


@pytest.fixture()
def ok():
    return Status.OK
