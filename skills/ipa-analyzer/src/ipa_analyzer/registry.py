"""Stage registry: ``@register`` decorator, dependency validation and deterministic ordering.

A stage is a class with ``run(self, ctx) -> StageResult`` (instantiated without arguments) or a
plain function ``run(ctx) -> StageResult``. Hard dependencies (``requires``) gate execution and
order; soft dependencies (``after``) only affect order. ``always_run`` stages (the report stage)
run even when dependencies failed and are scheduled after every other stage.
"""
from __future__ import annotations

import heapq
import inspect
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .errors import CycleError, RegistryError

StageFunc = Callable[[Any], Any]   # (AnalysisContext) -> StageResult


@dataclass(frozen=True)
class StageSpec:
    name: str
    run: StageFunc
    requires: Tuple[str, ...] = ()
    after: Tuple[str, ...] = ()
    always_run: bool = False
    module: str = ""
    description: str = ""


def _as_tuple(v: Optional[Iterable[str]]) -> Tuple[str, ...]:
    if v is None:
        return ()
    if isinstance(v, str):
        return (v,)
    return tuple(v)


class Registry:
    def __init__(self) -> None:
        self._specs: Dict[str, StageSpec] = {}
        self.import_failures: Dict[str, str] = {}   # module name -> error text (analyzer discovery)

    # --- registration -----------------------------------------------------------------------
    def add(self, spec: StageSpec) -> StageSpec:
        if not spec.name or not isinstance(spec.name, str):
            raise RegistryError("stage name must be a non-empty string")
        if spec.name in spec.requires or spec.name in spec.after:
            raise RegistryError("stage %r depends on itself" % spec.name)
        prev = self._specs.get(spec.name)
        if prev is not None:
            raise RegistryError("duplicate stage name %r (already registered by %s; again in %s)"
                                % (spec.name, prev.module or "?", spec.module or "?"))
        self._specs[spec.name] = spec
        return spec

    def get(self, name: str) -> Optional[StageSpec]:
        return self._specs.get(name)

    def names(self) -> List[str]:
        return sorted(self._specs)

    def specs(self) -> List[StageSpec]:
        return [self._specs[n] for n in self.names()]

    def __contains__(self, name: object) -> bool:
        return name in self._specs

    def __len__(self) -> int:
        return len(self._specs)

    def record_import_failure(self, module: str, error: str) -> None:
        self.import_failures[module] = error

    # --- validation / ordering --------------------------------------------------------------
    def validate(self) -> None:
        """Raise ``RegistryError`` / ``CycleError`` if the graph is invalid.

        Unknown hard dependencies are an error unless some analyzer module failed to import (then
        the dependent is skipped at run time with "dependency X not available").
        """
        if not self.import_failures:
            for s in self._specs.values():
                for dep in s.requires:
                    if dep not in self._specs:
                        raise RegistryError("stage %r requires unknown stage %r" % (s.name, dep))
        self.order()

    def _edges(self, names: Set[str]) -> Dict[str, Set[str]]:
        """name -> set of names that must run before it (restricted to ``names``)."""
        pred: Dict[str, Set[str]] = {n: set() for n in names}
        normal = [n for n in names if not self._specs[n].always_run]
        for n in names:
            s = self._specs[n]
            for d in s.requires + s.after:
                if d in names:
                    pred[n].add(d)
            if s.always_run:
                pred[n].update(x for x in normal)
        return pred

    def order(self, selected: Optional[Iterable[str]] = None) -> List[str]:
        """Deterministic topological order (ties broken alphabetically). Raises ``CycleError``."""
        names = set(self._specs) if selected is None else {n for n in selected if n in self._specs}
        pred = self._edges(names)
        indeg = {n: len(p) for n, p in pred.items()}
        succ: Dict[str, List[str]] = {n: [] for n in names}
        for n, ps in pred.items():
            for p in ps:
                succ[p].append(n)
        heap = [n for n, d in indeg.items() if d == 0]
        heapq.heapify(heap)
        out: List[str] = []
        while heap:
            n = heapq.heappop(heap)
            out.append(n)
            for m in succ[n]:
                indeg[m] -= 1
                if indeg[m] == 0:
                    heapq.heappush(heap, m)
        if len(out) != len(names):
            raise CycleError(self._find_cycle({n for n in names if n not in set(out)}, pred))
        return out

    @staticmethod
    def _find_cycle(remaining: Set[str], pred: Dict[str, Set[str]]) -> List[str]:
        start = sorted(remaining)[0]
        path: List[str] = []
        seen: Dict[str, int] = {}
        cur = start
        while cur not in seen:
            seen[cur] = len(path)
            path.append(cur)
            nxt = sorted(p for p in pred[cur] if p in remaining)
            cur = nxt[0]
        cyc = path[seen[cur]:] + [cur]
        cyc.reverse()   # edges point dependency -> dependent; show "a -> b" meaning b depends on a
        return cyc

    def closure(self, names: Iterable[str]) -> Set[str]:
        """``names`` plus all transitive hard dependencies that are registered."""
        out: Set[str] = set()
        stack = list(names)
        while stack:
            n = stack.pop()
            if n in out or n not in self._specs:
                continue
            out.add(n)
            stack.extend(self._specs[n].requires)
        return out


_default = Registry()


def get_registry() -> Registry:
    """The process-wide registry used by ``@register`` and the pipeline."""
    return _default


def register(name: str, requires: Optional[Sequence[str]] = (), after: Optional[Sequence[str]] = (),
             *, always_run: bool = False, description: str = "", registry: Optional[Registry] = None):
    """Class/function decorator registering a stage. Returns the decorated object unchanged."""

    def deco(obj):
        if inspect.isclass(obj):
            instance = obj()
            run = instance.run
        elif callable(obj):
            run = obj
        else:
            raise RegistryError("@register target for %r must be a class or a function" % name)
        spec = StageSpec(name=name, run=run, requires=_as_tuple(requires), after=_as_tuple(after),
                         always_run=always_run, module=getattr(obj, "__module__", ""),
                         description=description or (inspect.getdoc(obj) or "").split("\n")[0])
        (registry if registry is not None else _default).add(spec)
        return obj

    return deco
