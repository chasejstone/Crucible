"""Compute a 0-100 suspicion score from the combined findings.

The scoring is additive with per-category caps so one noisy category can't
dominate the total. Every point added also records which indicator fired,
and those indicator keys feed into the MITRE mapping downstream.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

# category: (weight_per_hit, cap)
WEIGHTS: Dict[str, Tuple[int, int]] = {
    "packed_sections":        (15, 15),
    "high_entropy":           (8, 8),
    "yara_hit":               (20, 40),
    "suspicious_api_import":  (5, 20),
    "reverse_shell_strings":  (15, 15),
    "shell_oneliner_strings": (10, 10),
    "url_strings":            (3, 9),
    "ipv4_strings":           (3, 9),
    "registry_strings":       (3, 6),
    "network_connect":        (15, 15),
    "network_send":           (10, 10),
    "child_spawn_shell":      (10, 10),
    "child_spawn_download":   (15, 15),
    "write_crontab":          (20, 20),
    "write_systemd":          (20, 20),
    "write_ssh":              (20, 20),
    "sensitive_write":        (15, 30),
}


@dataclass
class ScoreResult:
    """Final score plus the individual reasons it got there."""

    score: int
    label: str                                # low / medium / high / critical
    indicators: List[str] = field(default_factory=list)
    breakdown: List[Dict[str, Any]] = field(default_factory=list)


def _label(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _accumulate(category: str, hits: int, totals: Dict[str, int],
                breakdown: List[Dict[str, Any]]) -> None:
    if hits <= 0 or category not in WEIGHTS:
        return
    per_hit, cap = WEIGHTS[category]
    current = totals.get(category, 0)
    contribution = min(per_hit * hits, cap - current)
    if contribution <= 0:
        return
    totals[category] = current + contribution
    breakdown.append({
        "indicator": category,
        "hits": hits,
        "points": contribution,
    })


def score(findings: Dict[str, Any]) -> ScoreResult:
    """Walk the findings dict and produce a ScoreResult.

    ``findings`` is expected to contain ``static`` and ``dynamic`` sections
    with the shapes the analyzers produce. Missing keys are fine.
    """
    totals: Dict[str, int] = {}
    breakdown: List[Dict[str, Any]] = []

    static = findings.get("static", {}) or {}
    dynamic = findings.get("dynamic", {}) or {}

    # --- static signals ----------------------------------------------------
    pe = static.get("pe") or {}
    elf = static.get("elf") or {}
    binary = pe if pe.get("parsed") else elf

    if binary.get("parsed"):
        section_summary = static.get("section_summary") or {}
        if section_summary.get("packed"):
            _accumulate("packed_sections", 1, totals, breakdown)
        elif section_summary.get("max_entropy", 0) >= 6.8:
            _accumulate("high_entropy", 1, totals, breakdown)

    flagged = (static.get("strings") or {}).get("flagged") or {}
    _accumulate("suspicious_api_import", len(flagged.get("suspicious_api", [])),
                totals, breakdown)
    _accumulate("reverse_shell_strings", len(flagged.get("reverse_shell", [])),
                totals, breakdown)
    _accumulate("shell_oneliner_strings", len(flagged.get("shell_oneliner", [])),
                totals, breakdown)
    _accumulate("url_strings", len(flagged.get("url", [])), totals, breakdown)
    _accumulate("ipv4_strings", len(flagged.get("ipv4", [])), totals, breakdown)
    _accumulate("registry_strings", len(flagged.get("registry_key", [])),
                totals, breakdown)

    yara = static.get("yara") or {}
    _accumulate("yara_hit", len(yara.get("matches") or []), totals, breakdown)

    # --- dynamic signals ---------------------------------------------------
    if dynamic.get("ran"):
        net = dynamic.get("network") or {}
        _accumulate("network_connect", len(net.get("connect_attempts") or []),
                    totals, breakdown)
        _accumulate("network_send", len(net.get("send_attempts") or []),
                    totals, breakdown)

        fs = dynamic.get("filesystem") or {}
        sensitive = fs.get("sensitive_writes") or []
        _accumulate("sensitive_write", len(sensitive), totals, breakdown)
        for path in sensitive:
            if "cron" in path:
                _accumulate("write_crontab", 1, totals, breakdown)
            if "/etc/systemd" in path:
                _accumulate("write_systemd", 1, totals, breakdown)
            if ".ssh" in path:
                _accumulate("write_ssh", 1, totals, breakdown)

        procs = dynamic.get("processes") or {}
        for child in procs.get("suspicious_children") or []:
            name = child.get("name", "")
            if name in ("bash", "sh", "dash", "zsh"):
                _accumulate("child_spawn_shell", 1, totals, breakdown)
            if name in ("curl", "wget", "nc", "ncat"):
                _accumulate("child_spawn_download", 1, totals, breakdown)

    total = min(sum(totals.values()), 100)
    return ScoreResult(
        score=total,
        label=_label(total),
        indicators=sorted(totals.keys()),
        breakdown=breakdown,
    )
