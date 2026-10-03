"""Pipeline: dependency-ordered, failure-isolated stage execution and basic ``Report`` assembly."""
from __future__ import annotations

import datetime as _dt
import logging
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import TOOL_NAME, __version__
from .context import AnalysisContext
from .errors import InvalidInput, RegistryError, UsageError
from .models import SCHEMA_VERSION, Finding, Report, Status, StageResult, to_jsonable
from .registry import Registry, StageSpec, get_registry

log = logging.getLogger(__name__)

IMPORT_STAGE_PREFIX = "import:"

# Finding ids copied into Report.protection.findings (in addition to every ``protect.*`` id).
PROTECTION_FINDING_IDS = frozenset({
    "meta.fairplay_container", "meta.signature_integrity", "unity.metadata.encrypted", "unity.binary.fairplay",
    "unity.assetbundle.encryption", "unity.mono.dll_encrypted", "unity.hotfix.script_protection",
    "engine.pak.encrypted", "engine.script.encrypted", "engine.resource.encrypted",
})


@dataclass
class PipelineRun:
    stage_results: List[StageResult] = field(default_factory=list)   # in execution order
    invalid_input: bool = False      # some stage raised InvalidInput
    fatal_error: Optional[str] = None

    @property
    def failed(self) -> List[str]:
        return [r.name for r in self.stage_results if r.status == Status.FAILED]


def ensure_analyzers_loaded() -> Registry:
    """Import ``ipa_analyzer.analyzers`` (auto-discovery) and return the default registry."""
    import importlib

    importlib.import_module("ipa_analyzer.analyzers")
    return get_registry()


def _import_failure_spec(module: str, error: str) -> StageSpec:
    def _run(ctx: AnalysisContext, _e: str = error, _m: str = module) -> StageResult:
        return StageResult.failed(IMPORT_STAGE_PREFIX + _m, "module %s failed to import: %s" % (_m, _e))

    return StageSpec(name=IMPORT_STAGE_PREFIX + module, run=_run, module=module,
                     description="analyzer module import failure")


def plan(reg: Registry, cfg: Any) -> List[StageSpec]:
    """Validate the registry and return all specs (incl. import-failure pseudo stages) in run order."""
    reg.validate()
    specs: Dict[str, StageSpec] = {s.name: s for s in reg.specs()}
    for mod, err in sorted(reg.import_failures.items()):
        pseudo = _import_failure_spec(mod, err)
        specs.setdefault(pseudo.name, pseudo)
    tmp = Registry()
    tmp.import_failures = dict(reg.import_failures)
    for s in specs.values():
        tmp.add(s)
    for opt, label in ((cfg.stages, "--stages"), (cfg.skip, "--skip")):
        for n in opt or ():
            if n not in specs:
                raise UsageError("unknown stage in %s: %r (known: %s)" % (label, n, ", ".join(sorted(specs))))
    return [specs[n] for n in tmp.order()]


def _normalize(result: Any, spec: StageSpec) -> StageResult:
    if not isinstance(result, StageResult):
        raise TypeError("stage %r returned %s instead of StageResult" % (spec.name, type(result).__name__))
    result.name = spec.name
    result.data = to_jsonable(result.data)           # raises TypeError for non-JSON data
    result.findings = [f if isinstance(f, Finding) else Finding.from_dict(f) for f in result.findings]
    return result


def run(ctx: AnalysisContext, registry: Optional[Registry] = None) -> PipelineRun:
    """Execute all stages. Never raises for stage errors; raises ``RegistryError``/``CycleError``/
    ``UsageError`` before any stage runs if the registry or the stage selection is invalid."""
    reg = registry if registry is not None else ensure_analyzers_loaded()
    cfg = ctx.cfg
    ordered = plan(reg, cfg)
    known = {s.name: s for s in ordered}
    selected = None
    if cfg.stages:
        selected = reg.closure(cfg.stages) | {s.name for s in ordered if s.always_run}
    skip = set(cfg.skip or ())
    outcome = PipelineRun()

    for spec in ordered:
        name = spec.name
        started = time.perf_counter()
        result: Optional[StageResult] = None
        if name in skip:
            result = StageResult.skipped(name, "disabled by --skip")
        elif selected is not None and name not in selected:
            result = StageResult.skipped(name, "not selected by --stages")
        elif not spec.always_run:
            for dep in spec.requires:
                if dep not in known:
                    result = StageResult.skipped(name, "dependency %s not available" % dep)
                    break
                st = ctx.stage_status(dep)
                if st == Status.FAILED:
                    result = StageResult.skipped(name, "dependency %s failed" % dep)
                    break
                if st != Status.OK and st != Status.PARTIAL:
                    result = StageResult.skipped(name, "dependency %s skipped" % dep)
                    break
        if result is None:
            try:
                result = _normalize(spec.run(ctx), spec)
            except InvalidInput as exc:
                outcome.invalid_input = True
                result = StageResult.failed(name, "InvalidInput: %s" % exc)
                log.debug("stage %s raised InvalidInput", name, exc_info=True)
            except Exception as exc:  # noqa: BLE001 - stage isolation is the point
                result = StageResult.failed(name, "%s: %s" % (type(exc).__name__, exc))
                log.debug("stage %s crashed:\n%s", name, traceback.format_exc())
        if not result.duration_s:
            result.duration_s = time.perf_counter() - started
        result.duration_s = round(result.duration_s, 3)

        ctx.stage_results[name] = result
        if result.status in (Status.OK, Status.PARTIAL):
            ctx.results[name] = result.data
        ctx.findings.extend(result.findings)
        for w in result.warnings:
            ctx.warnings.append("[%s] %s" % (name, w))
        log.info("stage %-22s %-8s %.2fs%s", name, result.status.value, result.duration_s,
                 (" (%s)" % (result.reason or result.error)) if (result.reason or result.error) else "")
        outcome.stage_results.append(result)
    return outcome


# --- basic report assembly ----------------------------------------------------------------------
def _d(x: Any) -> Dict[str, Any]:
    return x if isinstance(x, dict) else {}


def _l(x: Any) -> list:
    return x if isinstance(x, list) else []


def build_report(ctx: AnalysisContext, stage_results: Optional[List[StageResult]] = None) -> Report:
    """Assemble a ``Report`` from ``ctx`` using the mapping documented in CONTRACT-FREEZE.md.

    Defensive about missing stages (sections stay empty). WP8 may call this and then post-process
    (redaction, externalising large tables, executive summary).
    """
    res = ctx.results
    srs = stage_results if stage_results is not None else list(ctx.stage_results.values())
    ingest = _d(res.get("ingest"))
    meta = _d(res.get("meta"))
    inv = _d(res.get("inventory"))
    macho = _d(res.get("macho"))
    detect = _d(res.get("engine.detect"))
    classify = _d(res.get("classify"))
    libs = _d(res.get("libs"))

    app: Dict[str, Any] = dict(_d(meta.get("identity")))
    if meta.get("distribution") is not None:
        app["distribution"] = meta.get("distribution")
    for k in ("sdk", "extensions", "background_modes", "capabilities"):
        if k in meta:
            app[k] = meta[k]

    trackers = [{"id": i.get("id"), "name": i.get("name"), "tags": i.get("tags", [])}
                for i in _l(libs.get("items")) if isinstance(i, dict)
                and set(i.get("tags") or []) & {"ads", "analytics", "tracking", "attribution"}]

    engine_details: Dict[str, Any] = {}
    if "engine.fingerprint" in res:
        engine_details["fingerprint"] = res["engine.fingerprint"]
    if "engine.detect" in res:
        engine_details["detect"] = res["engine.detect"]
    if "engine.unity" in res:
        unity = dict(res["engine.unity"])
        if "engine.unity.hotfix" in res:
            unity["hotfix"] = res["engine.unity.hotfix"]
        engine_details["unity"] = unity
    other = _d(res.get("engine.other"))
    for k, v in other.items():
        if not k.startswith("_"):
            engine_details[k] = v

    prot = [f for f in ctx.findings if f.id.startswith("protect.") or f.id in PROTECTION_FINDING_IDS]
    local_warnings = list(ctx.warnings)

    return Report(
        schema_version=SCHEMA_VERSION,
        tool={"name": TOOL_NAME, "version": __version__},
        generated_at=_dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        input={
            "path": ingest.get("path", str(ctx.input_path)),
            "sha256": ingest.get("sha256", ctx.input_sha256),
            "size": ingest.get("size"),
            "kind": ingest.get("kind"),
        },
        app=app,
        classification={k: classify[k] for k in ("category", "subcategory", "confidence", "evidence") if k in classify},
        structure={
            "tree": inv.get("tree"),
            "nested_units": _l(inv.get("nested_units")),
            "binaries": _l(macho.get("binaries")),
            "languages": _l(detect.get("languages")),
            "engine": {"primary": detect.get("primary"), "candidates": _l(detect.get("candidates"))},
        },
        resources={k: inv.get(k, []) for k in ("by_category", "by_ext", "top_files", "archives", "localizations")},
        libraries=[i for i in _l(libs.get("items")) if isinstance(i, dict)],
        protection={"findings": prot},
        engine_details=engine_details,
        privacy={
            "permissions": _l(meta.get("permissions")),
            "url_schemes": _l(meta.get("url_schemes")),
            "query_schemes": _l(meta.get("query_schemes")),
            "ats": _d(meta.get("ats")),
            "trackers": trackers,
        },
        stages=[r.summary_dict() for r in srs],
        findings=list(ctx.findings),
        warnings=local_warnings,
        redaction={"applied": False, "fields": []},
        artifacts=dict(ctx.artifacts) or None,
        config=ctx.cfg.to_dict(),
    )


__all__ = ["PipelineRun", "run", "plan", "build_report", "ensure_analyzers_loaded", "PROTECTION_FINDING_IDS"]
