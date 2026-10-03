"""Shannon entropy helpers (bits per byte, range 0..8)."""
from __future__ import annotations

import math
from collections import Counter
from typing import BinaryIO

HEAD_BYTES = 64 * 1024
SAMPLE_BLOCKS = 16
SAMPLE_BLOCK_SIZE = 4096


def shannon(data: bytes) -> float:
    """Shannon entropy of ``data`` in bits per byte. Empty input -> 0.0."""
    n = len(data)
    if n == 0:
        return 0.0
    total = 0.0
    for c in Counter(data).values():
        p = c / n
        total -= p * math.log2(p)
    return total


def sampled_entropy(fileobj: BinaryIO, size: int, *, head: int = HEAD_BYTES, blocks: int = SAMPLE_BLOCKS,
                    block_size: int = SAMPLE_BLOCK_SIZE) -> float:
    """Entropy of the first ``head`` bytes plus ``blocks`` evenly spaced ``block_size`` blocks.

    ``fileobj`` must be seekable and ``size`` is the total length. Files that fit in the sampling
    budget are read fully. Deterministic (no randomness). Sampling can miss localised regions.
    """
    if size <= 0:
        return 0.0
    if size <= head + blocks * block_size:
        fileobj.seek(0)
        return shannon(fileobj.read(size))
    fileobj.seek(0)
    parts = [fileobj.read(head)]
    tail_start = head
    span = size - tail_start - block_size
    for i in range(blocks):
        off = tail_start + (span * i) // max(blocks - 1, 1)
        fileobj.seek(off)
        parts.append(fileobj.read(block_size))
    return shannon(b"".join(parts))
