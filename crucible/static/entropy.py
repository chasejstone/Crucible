"""Shannon entropy and simple packer heuristics.

High entropy in a code section is the classic fingerprint of compressed or
encrypted payloads. 7.2 bits per byte is the threshold most analysts use,
and it's the one we go with here.
"""

from __future__ import annotations

import math
from typing import Iterable, List, Mapping

PACKED_THRESHOLD = 7.2


def shannon(data: bytes) -> float:
    """Compute Shannon entropy of a byte string in bits per byte.

    Returns 0.0 for empty input. For a buffer of length N, the result is
    always in [0, 8].
    """
    if not data:
        return 0.0

    counts = [0] * 256
    for b in data:
        counts[b] += 1

    length = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


def is_likely_packed(section_entropies: Iterable[float],
                     threshold: float = PACKED_THRESHOLD) -> bool:
    """True if any section exceeds the threshold.

    A single high entropy section is enough to flag packing. We don't try
    to guess the packer name.
    """
    return any(e >= threshold for e in section_entropies)


def summarize_sections(sections: List[Mapping[str, object]]) -> dict:
    """Turn section entropy list into a compact summary for the report.

    Expects each section to have at least a ``name`` and ``entropy`` key.
    """
    entropies = [float(s["entropy"]) for s in sections if "entropy" in s]
    if not entropies:
        return {"max_entropy": 0.0, "avg_entropy": 0.0, "packed": False}
    return {
        "max_entropy": max(entropies),
        "avg_entropy": sum(entropies) / len(entropies),
        "packed": is_likely_packed(entropies),
    }
