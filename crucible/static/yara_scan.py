"""YARA rule compilation and matching.

Rules are loaded from a directory. The CLI defaults to the rules bundled with
the installed package.
All ``.yar`` and ``.yara`` files in that directory get compiled into one
namespace. If yara-python isn't installed we degrade gracefully instead of
exploding: the scan still runs, we just report no matches.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List

try:
    import yara  # type: ignore
except ImportError:  # pragma: no cover
    yara = None  # type: ignore

log = logging.getLogger("crucible")


def _collect_rule_files(rules_dir: Path) -> Dict[str, str]:
    """Return a mapping ``{namespace: filepath}`` suitable for yara.compile."""
    files: Dict[str, str] = {}
    if not rules_dir.is_dir():
        return files
    for p in sorted(rules_dir.iterdir()):
        if p.suffix.lower() in (".yar", ".yara") and p.is_file():
            files[p.stem] = str(p)
    return files


def scan(target: Path, rules_dir: Path) -> Dict[str, Any]:
    """Run all YARA rules in ``rules_dir`` against ``target``.

    Returns a dict with an ``available`` flag, a list of matches, and any
    errors encountered while compiling.
    """
    if yara is None:
        return {"available": False, "matches": [],
                "reason": "yara-python not installed"}

    rule_files = _collect_rule_files(rules_dir)
    if not rule_files:
        return {"available": True, "matches": [],
                "reason": f"no rules found under {rules_dir}"}

    try:
        compiled = yara.compile(filepaths=rule_files)
    except yara.Error as exc:
        log.warning("YARA compile failed: %s", exc)
        return {"available": True, "matches": [],
                "reason": f"compile error: {exc}"}

    matches: List[Dict[str, Any]] = []
    try:
        for m in compiled.match(str(target)):
            matches.append({
                "rule": m.rule,
                "namespace": m.namespace,
                "tags": list(m.tags),
                "meta": dict(m.meta),
            })
    except yara.Error as exc:
        log.warning("YARA match failed: %s", exc)
        return {"available": True, "matches": [],
                "reason": f"match error: {exc}"}

    return {"available": True, "matches": matches}
