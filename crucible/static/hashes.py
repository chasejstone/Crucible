"""File hashing utilities."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict

_CHUNK = 1024 * 1024


def hash_file(path: Path) -> Dict[str, str]:
    """Return MD5, SHA1, and SHA256 digests for a file.

    Reads in 1 MiB chunks so that large files don't blow up memory.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }
