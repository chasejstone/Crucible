"""Serialize a finding dict to JSON on disk."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


def write(findings: Dict[str, Any], out_path: Path) -> Path:
    """Write ``findings`` to ``out_path`` as pretty-printed JSON.

    Creates parent directories if needed. Returns the path written to.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, default=_fallback, sort_keys=False)
        f.write("\n")
    return out_path


def _fallback(obj: Any) -> Any:
    """Make non-JSON-native types serializable.

    Covers bytes, sets, and dataclasses without us having to chase down the
    exact source type.
    """
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if isinstance(obj, set):
        return sorted(obj)
    if hasattr(obj, "__dict__"):
        return vars(obj)
    return str(obj)
