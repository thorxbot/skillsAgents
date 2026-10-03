"""Report generation (WP8): Markdown / JSON / HTML renderers, i18n, redaction and schema validation.

The renderers work on the *report dict* (``Report.to_dict()`` or a loaded ``report.json``) and know
nothing about analysis stages; the ``report`` pipeline stage (``analyzers/report_stage.py``) wires them up.
"""
from __future__ import annotations

from .i18n import Catalog, I18nConflictError, I18nError, load_catalog, render_template
from .redact import RedactionStats, redact_obj, redact_report, redact_text
from .render_html import markdown_to_html, render_html
from .render_json import canonicalize, externalize_large, render_json
from .render_md import render_markdown
from .schema import ValidationOutcome, validate
from .summary import (build_summary, console_text, enrich_report, exec_rows, exit_code_for, explain_stage)

__all__ = [
    "Catalog", "I18nConflictError", "I18nError", "load_catalog", "render_template",
    "RedactionStats", "redact_obj", "redact_report", "redact_text",
    "markdown_to_html", "render_html", "canonicalize", "externalize_large", "render_json", "render_markdown",
    "ValidationOutcome", "validate",
    "build_summary", "console_text", "enrich_report", "exec_rows", "exit_code_for", "explain_stage",
]
