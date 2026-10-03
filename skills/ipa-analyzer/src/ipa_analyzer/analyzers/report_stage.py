"""Stage ``report`` (WP8): assemble, redact, validate and write ``report.json`` / ``report.md`` / ``report.html``.

Always runs, whatever happened upstream. The stage returns the exit-code decision in its data
(``exit_code``: 3 when a stage failed, else 0) and never calls ``sys.exit``.
"""
from __future__ import annotations

import json
import logging
import sys
from typing import Any, Dict, List, Optional, Tuple

from ..context import AnalysisContext
from ..models import Status, StageResult
from ..registry import register
from ..report import (load_catalog, redact_report, redact_text, render_html, render_json, render_markdown)
from ..report.i18n import Catalog, I18nError
from ..report.redact import RedactionStats
from ..report.render_json import canonicalize, externalize_large
from ..report.schema import validate
from ..report.summary import console_text, enrich_report, exit_code_for

log = logging.getLogger(__name__)

NAME = 'report'
INVENTORY_REL = "inventory.json"


@register(name='report', after=('ingest', 'inventory', 'meta', 'macho', 'engine.fingerprint', 'engine.detect', 'engine.other', 'engine.unity', 'engine.unity.hotfix', 'libs', 'protect', 'classify'), always_run=True)
class ReportStage:
    def run(self, ctx: AnalysisContext) -> StageResult:
        return _run(ctx)


def _ensure_bound(ctx: AnalysisContext) -> None:
    """Make sure the output directory exists even if ``ingest`` failed before binding it."""
    if ctx.is_bound:
        return
    from ..util.hashing import sha256_stream

    digest = "unhashed"
    if ctx.input_path.is_file():
        try:
            digest = sha256_stream(ctx.input_path)
        except OSError:
            pass
    ctx.bind_input(digest)


def _write_text(ctx: AnalysisContext, rel: str, text: str) -> None:
    path = ctx.artifact_path(rel)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _load_catalog(lang: str, warnings: List[str]) -> Catalog:
    try:
        return load_catalog(lang, on_conflict="warn")
    except I18nError as exc:
        warnings.append("i18n: %s" % exc)
        return Catalog(lang=lang, tables={})


def _ensure_inventory_file(ctx: AnalysisContext, warnings: List[str]) -> Optional[str]:
    """``inventory.json`` normally comes from the inventory stage; write a truncated copy if it did not."""
    if "inventory.json" in ctx.artifacts and (ctx.out_dir / ctx.artifacts["inventory.json"]).is_file():
        return ctx.artifacts["inventory.json"]
    if (ctx.out_dir / INVENTORY_REL).is_file():
        ctx.register_artifact("inventory.json", INVENTORY_REL)
        return INVENTORY_REL
    inv = ctx.results.get("inventory")
    if not isinstance(inv, dict) or not inv.get("files"):
        return None
    doc = {"files": inv.get("files"), "files_total": inv.get("files_total", len(inv.get("files") or [])),
           "files_truncated": True, "note": "file list as carried by ctx.results['inventory'] (the inventory "
                                            "stage did not write a full inventory.json)"}
    _write_text(ctx, INVENTORY_REL, json.dumps(doc, ensure_ascii=False, indent=2) + "\n")
    ctx.register_artifact("inventory.json", INVENTORY_REL)
    warnings.append("inventory.json was not provided by the inventory stage; wrote the (possibly truncated) file list")
    return INVENTORY_REL


def _print_console(text: str) -> None:
    try:
        sys.stdout.write(text + "\n")
        sys.stdout.flush()
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, "encoding", None) or "ascii"
        sys.stdout.write(text.encode(enc, errors="replace").decode(enc, errors="replace") + "\n")
        sys.stdout.flush()
    except (OSError, ValueError):
        log.debug("could not print the console summary", exc_info=True)


def _run(ctx: AnalysisContext) -> StageResult:
    from .. import pipeline     # deferred: core module, avoids any import-order coupling at registration time

    cfg = ctx.cfg
    warnings: List[str] = []
    _ensure_bound(ctx)

    # 1. assemble ------------------------------------------------------------------------------------
    stage_results = list(ctx.stage_results.values())
    stage_results.append(StageResult(NAME, Status.OK))       # this stage lists itself (duration is not knowable yet)
    report = pipeline.build_report(ctx, stage_results)
    try:
        enrich_report(report, ctx.results)
    except Exception as exc:  # noqa: BLE001 - a view-model problem must never cost us the report
        log.debug("enrich_report failed", exc_info=True)
        warnings.append("report enrichment failed (%s: %s); some sections may be thinner" % (type(exc).__name__, exc))
    inv_rel = _ensure_inventory_file(ctx, warnings)

    formats = [f for f in ("json", "md", "html") if f == "json" or f in cfg.formats]
    planned: Dict[str, str] = {"report.json": "report.json"}
    if "md" in formats:
        planned["report.md"] = "report.md"
    if "html" in formats:
        planned["report.html"] = "report.html"

    rd = canonicalize(report.to_dict())
    side = externalize_large(rd)
    for rel in side:
        planned[rel] = rel
    arts = dict(rd.get("artifacts") or {})
    arts.update(planned)
    if inv_rel:
        arts["inventory.json"] = inv_rel
    rd["artifacts"] = dict(sorted(arts.items()))

    # 2. redact ---------------------------------------------------------------------------------------
    meta_red = ctx.results.get("meta", {}).get("redaction") if isinstance(ctx.results.get("meta"), dict) else None
    producer = [str(k) for k in (meta_red or {}).get("keys", [])] if isinstance(meta_red, dict) else []
    rd, red_info = redact_report(rd, enabled=cfg.redact, producer_fields=producer, extras=side)
    rd["redaction"] = red_info
    if isinstance(meta_red, dict) and meta_red.get("applied") and not cfg.redact:
        rd["redaction"] = dict(red_info, applied=True)     # purchaser data was already blanked by the meta stage

    # 3. i18n + validation ------------------------------------------------------------------------------
    catalog = _load_catalog(cfg.lang, warnings)
    for f in list(rd.get("findings") or []) + list((rd.get("protection") or {}).get("findings") or []):
        if isinstance(f, dict):
            catalog.finding_text(f)
    warnings += catalog.collect_warnings()
    outcome = validate(rd)
    if outcome.skipped_reason:
        warnings.append("report schema validation skipped: %s" % outcome.skipped_reason)
    elif outcome.errors:
        shown = "; ".join(outcome.errors[:5]) + ("; ..." if len(outcome.errors) > 5 else "")
        warnings.append("report.json does not match the schema (%s, %d problem(s)): %s"
                        % (outcome.validator, len(outcome.errors), shown))
    if warnings:
        rd["warnings"] = list(rd.get("warnings") or []) + [w for w in warnings if w not in (rd.get("warnings") or [])]

    # 4. render -----------------------------------------------------------------------------------------
    texts: Dict[str, str] = {}
    failed_formats: List[str] = []
    md_text: Optional[str] = None
    if "md" in formats or "html" in formats:
        try:
            md_text = render_markdown(rd, catalog, summary=rd.get("summary"))
        except Exception as exc:  # noqa: BLE001
            log.debug("markdown rendering failed", exc_info=True)
            failed_formats += [f for f in ("md", "html") if f in formats]
            rd["warnings"].append("markdown rendering failed: %s: %s" % (type(exc).__name__, exc))
    stats2 = RedactionStats()
    if md_text is not None:
        if "md" in formats:
            texts["report.md"] = redact_text(md_text, stats2) if cfg.redact else md_text
        if "html" in formats:
            try:
                html_text = render_html(md_text, catalog)
                texts["report.html"] = redact_text(html_text, stats2) if cfg.redact else html_text
            except Exception as exc:  # noqa: BLE001
                log.debug("html rendering failed", exc_info=True)
                failed_formats.append("html")
                rd["warnings"].append("html rendering failed: %s: %s" % (type(exc).__name__, exc))
    if cfg.redact and stats2.total:
        merged = RedactionStats(dict(rd["redaction"].get("counts") or {}))
        merged.merge(stats2)
        rd["redaction"] = dict(rd["redaction"], counts=dict(sorted(merged.counts.items())),
                               fields=sorted(set(rd["redaction"].get("fields") or []) | set(merged.fields)))
    texts["report.json"] = render_json(rd)

    # 5. write -----------------------------------------------------------------------------------------
    written: Dict[str, str] = {}
    for name in ("report.json", "report.md", "report.html"):
        if name in texts:
            _write_text(ctx, name, texts[name])
            ctx.register_artifact(name, name)
            written[name] = name
    for rel, value in sorted(side.items()):
        _write_text(ctx, rel, json.dumps(value, ensure_ascii=False, indent=2) + "\n")
        ctx.register_artifact(rel, rel)
        written[rel] = rel

    # 6. console + result ---------------------------------------------------------------------------------
    try:
        _print_console(console_text(rd, rd.get("summary") or {}, catalog.t))
    except Exception:  # noqa: BLE001
        log.debug("console summary failed", exc_info=True)

    exit_code = exit_code_for(stage_results)
    data: Dict[str, Any] = {
        "files": written, "formats": [f for f in formats if f not in failed_formats],
        "exit_code": exit_code, "failed_stages": [r.name for r in stage_results if r.status == Status.FAILED],
        "validation": {"validator": outcome.validator, "ok": outcome.ok, "errors": outcome.errors[:20]},
    }
    if failed_formats:
        return StageResult.partial(NAME, data, warnings=warnings, reason="could not render: %s" % ", ".join(failed_formats))
    return StageResult.ok(NAME, data, warnings=warnings)
