"""Parser for strace output.

strace gives us one line per syscall in roughly this shape:

    [pid 12345] 1713600000.123456 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3

We don't try to perfectly round-trip every format. We just pull out the
fields the monitors care about: pid, timestamp, syscall name, raw args,
and return value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

_LINE_RE = re.compile(
    r"""
    ^(?:\[pid\s+(?P<pid1>\d+)\]\s+        # [pid N] form
       |(?P<pid2>\d+)\s+                  # bare PID prefix from strace -f
    )?
    (?:(?P<ts>\d+\.\d+)\s+)?              # optional timestamp
    (?P<name>[a-zA-Z_][a-zA-Z0-9_]*)      # syscall name
    \((?P<args>.*)\)                      # args, greedy on purpose
    \s*=\s*(?P<ret>-?\d+|\?|0x[0-9a-fA-F]+)  # return value
    """,
    re.VERBOSE,
)


@dataclass
class Syscall:
    """One parsed line of strace output."""

    name: str
    args: str
    ret: str
    pid: Optional[int] = None
    ts: Optional[float] = None


def parse_file(path: Path) -> List[Syscall]:
    """Read a trace log and return a list of Syscall records.

    Lines we can't parse are silently dropped (strace emits interrupted,
    resumed, and signal lines that don't match the normal shape).
    """
    results: List[Syscall] = []
    with path.open("r", errors="replace") as f:
        for line in f:
            sc = parse_line(line.rstrip("\n"))
            if sc is not None:
                results.append(sc)
    return results


def parse_line(line: str) -> Optional[Syscall]:
    """Parse a single strace line into a Syscall record, or None if it doesn't match."""
    m = _LINE_RE.match(line.strip())
    if not m:
        return None
    pid = m.group("pid1") or m.group("pid2")
    return Syscall(
        name=m.group("name"),
        args=m.group("args"),
        ret=m.group("ret"),
        pid=int(pid) if pid else None,
        ts=float(m.group("ts")) if m.group("ts") else None,
    )


def extract_string_arg(args: str, index: int = 0) -> Optional[str]:
    """Pull out the Nth quoted string from an args blob.

    strace quotes path-like arguments with ``"..."`` and escapes special
    chars. We do a cheap scan rather than a real parser since we only
    need readable output.
    """
    strings: List[str] = []
    i = 0
    while i < len(args):
        if args[i] == '"':
            j = i + 1
            buf = []
            while j < len(args):
                if args[j] == "\\" and j + 1 < len(args):
                    buf.append(args[j + 1])
                    j += 2
                    continue
                if args[j] == '"':
                    break
                buf.append(args[j])
                j += 1
            strings.append("".join(buf))
            i = j + 1
        else:
            i += 1
    if index < len(strings):
        return strings[index]
    return None
