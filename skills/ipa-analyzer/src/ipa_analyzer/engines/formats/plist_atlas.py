"""Classify Cocos-style plists (sprite-frame atlas, particle definition) from their keys.

Keys (Source: cocos2d-x v3 ``CCSpriteFrameCache.cpp``: top-level ``frames`` map and ``metadata`` with ``format`` and
``textureFileName``; ``CCParticleSystem.cpp``: ``maxParticles``, ``emitterType``, ``particleLifespan``,
``textureFileName`` / ``textureImageData``).  A bare plist + png in an otherwise native app proves nothing about
the engine -- callers must not use this alone to claim Cocos.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from ...util.plist_utils import load_plist

PARTICLE_KEYS = ("maxParticles", "emitterType", "particleLifespan")


def classify_plist_object(obj: Any) -> Tuple[str, Dict[str, Any]]:
    """``("atlas" | "particle" | "other", details)`` for an already parsed plist."""
    if not isinstance(obj, dict):
        return "other", {}
    if isinstance(obj.get("frames"), dict) and isinstance(obj.get("metadata"), dict):
        meta = obj["metadata"]
        return "atlas", {"frames": len(obj["frames"]), "format": meta.get("format"),
                         "texture": meta.get("textureFileName") or meta.get("realTextureFileName")}
    if sum(1 for k in PARTICLE_KEYS if k in obj) >= 2:
        return "particle", {"has_embedded_texture": "textureImageData" in obj}
    return "other", {}


def classify_plist_bytes(data: bytes) -> Tuple[str, Dict[str, Any]]:
    obj: Optional[Any] = load_plist(bytes(data))
    return classify_plist_object(obj)
