"""Extract printable strings and flag suspicious ones.

Mimics the GNU `strings` default of runs length 4 or more. Supports both
ASCII and UTF-16LE because PE files commonly embed wide strings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Pattern, Tuple

MIN_LEN = 4

# Compiled once. Each key is the category, value is a pattern tested against
# every extracted string.
_PATTERNS: Dict[str, Pattern[str]] = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    ),
    "url": re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]{4,}", re.IGNORECASE),
    "registry_key": re.compile(
        r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[\w\\ .-]{2,}", re.IGNORECASE
    ),
    "suspicious_api": re.compile(
        r"\b(?:VirtualAlloc(?:Ex)?|VirtualProtect|CreateRemoteThread|WriteProcessMemory|"
        r"ReadProcessMemory|WinExec|ShellExecute[AW]?|LoadLibrary[AW]?|GetProcAddress|"
        r"CreateProcess[AW]?|NtCreateThreadEx|RtlCreateUserThread|SetWindowsHookEx|"
        r"CryptEncrypt|InternetOpen[AW]?|URLDownloadToFile[AW]?)\b"
    ),
    "shell_oneliner": re.compile(
        r"(?:/bin/(?:ba)?sh\s+-[ic]|bash\s+-i|nc\s+-[el]|"
        r"python\s+-c\s+|perl\s+-e\s+|curl\s+[^|]*\|\s*(?:ba)?sh|wget\s+[^|]*\|\s*(?:ba)?sh)",
        re.IGNORECASE,
    ),
    "reverse_shell": re.compile(
        r"(?:/dev/tcp/|bash\s+-i\s*>&|\bexec\s+\d+<>|socket\.socket.*connect)",
        re.IGNORECASE,
    ),
    "crypto_wallet": re.compile(
        r"\b(?:bc1[a-z0-9]{20,}|[13][a-km-zA-HJ-NP-Z0-9]{25,34}|0x[a-fA-F0-9]{40})\b"
    ),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
}

_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_LEN)
_UTF16LE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_LEN)


@dataclass
class StringFindings:
    """Aggregated strings pulled from a file."""

    total: int = 0
    samples: List[str] = field(default_factory=list)
    flagged: Dict[str, List[str]] = field(default_factory=dict)


def _extract_raw(data: bytes, max_samples: int = 500) -> List[str]:
    """Pull ASCII and UTF-16LE runs out of the raw bytes.

    Returns a deduplicated, size capped list.
    """
    out: List[str] = []
    seen: set[str] = set()

    def _push(s: str) -> None:
        if s not in seen:
            seen.add(s)
            out.append(s)

    for m in _ASCII_RE.finditer(data):
        _push(m.group().decode("ascii", errors="replace"))
    for m in _UTF16LE_RE.finditer(data):
        # Drop the interleaved null bytes.
        _push(m.group().decode("utf-16-le", errors="replace"))

    return out


def analyze(path: Path, max_samples: int = 500) -> StringFindings:
    """Extract strings and flag any that match our suspicious regex set."""
    data = path.read_bytes()
    strings = _extract_raw(data)

    flagged: Dict[str, List[str]] = {}
    for s in strings:
        for label, pattern in _PATTERNS.items():
            if pattern.search(s):
                flagged.setdefault(label, []).append(s)

    # Dedup per category and cap output size for sanity.
    for label, items in flagged.items():
        seen = set()
        unique: List[str] = []
        for item in items:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        flagged[label] = unique[:100]

    return StringFindings(
        total=len(strings),
        samples=strings[:max_samples],
        flagged=flagged,
    )


def as_dict(findings: StringFindings) -> dict:
    """Serialize a StringFindings instance for the final report."""
    return {
        "total": findings.total,
        "flagged": findings.flagged,
        "sample_count": len(findings.samples),
    }
