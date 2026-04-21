"""Sniff file type from magic bytes and extension hints.

We keep this intentionally small: the goal is just to route a sample to the
right static parser and decide whether the dynamic stage can run it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class FileType:
    """Result of a file type sniff."""

    kind: str           # "elf", "pe", "script", "text", "unknown"
    interpreter: Optional[str] = None   # for scripts, e.g. "/bin/bash"
    executable_on_linux: bool = False   # can the dynamic sandbox run it?


def _read_head(path: Path, n: int = 512) -> bytes:
    with path.open("rb") as f:
        return f.read(n)


def sniff(path: Path) -> FileType:
    """Identify a file's broad category.

    Detection order: ELF magic, PE "MZ" + PE header, shebang line,
    known script extensions, then falling back to text vs unknown.
    """
    head = _read_head(path)

    if head.startswith(b"\x7fELF"):
        return FileType(kind="elf", executable_on_linux=True)

    # PE files start with "MZ" and carry a "PE\0\0" further in.
    if head.startswith(b"MZ") and b"PE\x00\x00" in head:
        return FileType(kind="pe", executable_on_linux=False)

    if head.startswith(b"#!"):
        first_line = head.split(b"\n", 1)[0][2:].decode(errors="replace").strip()
        interp = first_line.split()[0] if first_line else ""
        return FileType(
            kind="script",
            interpreter=interp or None,
            executable_on_linux=bool(interp),
        )

    # Extension hints for scripts without a shebang.
    ext = path.suffix.lower()
    ext_map = {
        ".sh": "/bin/sh",
        ".bash": "/bin/bash",
        ".py": "/usr/bin/env python3",
        ".pl": "/usr/bin/env perl",
    }
    if ext in ext_map:
        return FileType(kind="script", interpreter=ext_map[ext],
                        executable_on_linux=True)

    # Heuristic: mostly printable ASCII means treat as text.
    printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13))
    if head and printable / len(head) > 0.9:
        return FileType(kind="text")

    return FileType(kind="unknown")
