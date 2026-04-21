"""Render findings into a human-readable Markdown report."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def _h(title: str, level: int = 2) -> str:
    return f"{'#' * level} {title}\n\n"


def _code_block(text: str, lang: str = "") -> str:
    return f"```{lang}\n{text}\n```\n\n"


def _bullet_list(items: List[str]) -> str:
    if not items:
        return "_none_\n\n"
    return "".join(f"- `{item}`\n" for item in items) + "\n"


def _flagged_section(flagged: Dict[str, List[str]]) -> str:
    if not flagged:
        return "_no flagged strings_\n\n"
    out: List[str] = []
    for label, items in flagged.items():
        out.append(f"**{label}** ({len(items)} unique)\n\n")
        out.append(_bullet_list(items[:15]))
        if len(items) > 15:
            out.append(f"_... and {len(items) - 15} more_\n\n")
    return "".join(out)


def _sections_table(sections: List[Dict[str, Any]]) -> str:
    if not sections:
        return "_no sections parsed_\n\n"
    rows = ["| Name | Size | Entropy |", "| --- | --- | --- |"]
    for s in sections[:30]:
        name = s.get("name") or "(unnamed)"
        size = s.get("size") or s.get("raw_size") or 0
        entropy = s.get("entropy", 0.0)
        rows.append(f"| `{name}` | {size} | {entropy:.2f} |")
    return "\n".join(rows) + "\n\n"


def render(findings: Dict[str, Any]) -> str:
    """Render the findings dict as a Markdown string."""
    meta = findings.get("meta", {})
    static = findings.get("static", {}) or {}
    dynamic = findings.get("dynamic", {}) or {}
    scoring = findings.get("scoring", {}) or {}
    techniques: List[Dict[str, str]] = findings.get("mitre", []) or []

    lines: List[str] = []
    lines.append(_h("Crucible analysis report", 1))
    lines.append(f"**File:** `{meta.get('path')}`  \n")
    lines.append(f"**Size:** {meta.get('size')} bytes  \n")
    lines.append(f"**Analyzed:** {meta.get('timestamp')}  \n")
    lines.append(f"**File type:** {meta.get('filetype')}  \n\n")

    lines.append(_h("Suspicion score"))
    score = scoring.get("score", 0)
    label = scoring.get("label", "low")
    lines.append(f"**{score} / 100** ({label.upper()})\n\n")

    if scoring.get("breakdown"):
        lines.append("| Indicator | Hits | Points |\n")
        lines.append("| --- | --- | --- |\n")
        for row in scoring["breakdown"]:
            lines.append(f"| {row['indicator']} | {row['hits']} | {row['points']} |\n")
        lines.append("\n")

    if techniques:
        lines.append(_h("MITRE ATT&CK mapping"))
        for t in techniques:
            lines.append(f"- **{t['id']}** — {t['name']}\n")
        lines.append("\n")

    lines.append(_h("Hashes"))
    hashes = static.get("hashes", {})
    for algo in ("md5", "sha1", "sha256"):
        if algo in hashes:
            lines.append(f"- **{algo.upper()}**: `{hashes[algo]}`\n")
    lines.append("\n")

    pe = static.get("pe") or {}
    elf = static.get("elf") or {}
    if pe.get("parsed"):
        lines.append(_h("PE header"))
        lines.append(f"- Architecture: `{pe.get('architecture')}`\n")
        lines.append(f"- Entry point: `0x{pe.get('entry_point', 0):x}`\n")
        lines.append(f"- DLL: `{pe.get('is_dll')}`\n")
        lines.append(f"- Import count: {sum(len(i['functions']) for i in pe.get('imports', []))}\n\n")
        lines.append(_h("PE sections", 3))
        lines.append(_sections_table(pe.get("sections", [])))
    elif elf.get("parsed"):
        lines.append(_h("ELF header"))
        lines.append(f"- Class: `{elf.get('class')}`\n")
        lines.append(f"- Architecture: `{elf.get('architecture')}`\n")
        lines.append(f"- Type: `{elf.get('type')}`\n")
        lines.append(f"- Entry point: `0x{elf.get('entry_point', 0):x}`\n\n")
        lines.append(_h("ELF sections", 3))
        lines.append(_sections_table(elf.get("sections", [])))

    lines.append(_h("Flagged strings"))
    lines.append(_flagged_section((static.get("strings") or {}).get("flagged") or {}))

    yara = static.get("yara") or {}
    lines.append(_h("YARA matches"))
    matches = yara.get("matches") or []
    if not matches:
        reason = yara.get("reason") or "no rule matches"
        lines.append(f"_no matches ({reason})_\n\n")
    else:
        for m in matches:
            lines.append(f"- **{m['rule']}** (tags: {', '.join(m.get('tags') or []) or 'none'})\n")
        lines.append("\n")

    lines.append(_h("Dynamic analysis"))
    if not dynamic.get("ran"):
        lines.append(f"_dynamic stage skipped: {dynamic.get('reason')}_\n\n")
    else:
        lines.append(f"- Duration: {dynamic.get('duration_seconds', 0)} s\n")
        lines.append(f"- Exit code: `{dynamic.get('exit_code')}`\n")
        lines.append(f"- Timed out: `{dynamic.get('timed_out')}`\n")
        lines.append(f"- Syscalls captured: {dynamic.get('syscall_count')}\n\n")

        summary = dynamic.get("syscall_summary") or {}
        if summary:
            lines.append("**Top syscalls**\n\n")
            lines.append("| Name | Count |\n| --- | --- |\n")
            for name, count in summary.items():
                lines.append(f"| `{name}` | {count} |\n")
            lines.append("\n")

        fs = dynamic.get("filesystem") or {}
        lines.append(_h("Filesystem activity", 3))
        lines.append("**Writes**\n\n")
        lines.append(_bullet_list(fs.get("writes") or []))
        lines.append("**Sensitive writes**\n\n")
        lines.append(_bullet_list(fs.get("sensitive_writes") or []))
        lines.append("**Deletes**\n\n")
        lines.append(_bullet_list(fs.get("deletes") or []))

        net = dynamic.get("network") or {}
        lines.append(_h("Network attempts", 3))
        connects = net.get("connect_attempts") or []
        if connects:
            for c in connects[:20]:
                lines.append(f"- connect `{c}`\n")
            lines.append("\n")
        else:
            lines.append("_none_\n\n")

        procs = dynamic.get("processes") or {}
        lines.append(_h("Processes observed", 3))
        for p in procs.get("processes", [])[:30]:
            cmd = " ".join(p.get("cmdline") or []) or p.get("name", "")
            lines.append(f"- pid {p.get('pid')} — `{cmd}`\n")
        lines.append("\n")

    lines.append("---\n")
    lines.append(f"_Generated by Crucible at {datetime.now(timezone.utc).isoformat()}_\n")

    return "".join(lines)


def write(findings: Dict[str, Any], out_path: Path) -> Path:
    """Render and write the Markdown report."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render(findings), encoding="utf-8")
    return out_path
