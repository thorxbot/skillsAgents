"""Project-type classification (game / media / lifestyle / ...) (WP4)."""
from __future__ import annotations

from .scorer import CATEGORY_LABELS, ClassifyInput, classify, load_rules

__all__ = ["CATEGORY_LABELS", "ClassifyInput", "classify", "load_rules"]
