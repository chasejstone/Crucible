"""Derive filesystem activity from a syscall trace.

We don't touch the real filesystem for monitoring. Instead we look at
open/openat/creat/unlink/rename/chmod lines from strace and extract their
path arguments. That's cheap and safe.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from crucible.dynamic.tracer import Syscall, extract_string_arg

_WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
_SENSITIVE_PREFIXES = (
    "/etc/",
    "/root/",
    "/boot/",
    "/usr/",
    "/var/spool/cron",
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/systemd/",
    "/.ssh/",
)


def _is_write_open(args: str) -> bool:
    return any(flag in args for flag in _WRITE_FLAGS)


def _is_sensitive(path: str) -> bool:
    return any(path.startswith(p) or p in path for p in _SENSITIVE_PREFIXES)


def analyze(syscalls: Iterable[Syscall]) -> Dict[str, Any]:
    """Classify syscall records into reads, writes, and deletes.

    Returns a summary with path lists plus a ``sensitive_writes`` bucket
    that the scorer keys off.
    """
    reads: List[str] = []
    writes: List[str] = []
    deletes: List[str] = []
    sensitive: List[str] = []

    for sc in syscalls:
        if sc.name in ("open", "openat", "creat"):
            # openat's first string arg is the path (AT_FDCWD comes before
            # but as a bare token, so extract_string_arg gets the path).
            path = extract_string_arg(sc.args, 0)
            if not path:
                continue
            if _is_write_open(sc.args) or sc.name == "creat":
                writes.append(path)
                if _is_sensitive(path):
                    sensitive.append(path)
            else:
                reads.append(path)
        elif sc.name in ("unlink", "unlinkat", "rmdir"):
            path = extract_string_arg(sc.args, 0)
            if path:
                deletes.append(path)
                if _is_sensitive(path):
                    sensitive.append(path)
        elif sc.name in ("rename", "renameat", "renameat2"):
            path = extract_string_arg(sc.args, 1) or extract_string_arg(sc.args, 0)
            if path:
                writes.append(path)
                if _is_sensitive(path):
                    sensitive.append(path)
        elif sc.name in ("chmod", "fchmodat"):
            path = extract_string_arg(sc.args, 0)
            if path:
                writes.append(path)

    return {
        "reads": _unique(reads)[:200],
        "writes": _unique(writes)[:200],
        "deletes": _unique(deletes)[:200],
        "sensitive_writes": _unique(sensitive)[:100],
    }


def _unique(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
