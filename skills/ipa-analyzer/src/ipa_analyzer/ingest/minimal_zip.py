"""Compatibility alias: the WP0 minimal ``ZipSource`` was replaced by ``ingest.source.ZipSource`` (WP1)."""
from __future__ import annotations

from .source import ZipSource

__all__ = ["ZipSource"]
