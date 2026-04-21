"""Hash function sanity checks against known vectors."""

from pathlib import Path

from crucible.static.hashes import hash_file


def test_hash_file_known_empty(tmp_path: Path) -> None:
    target = tmp_path / "empty"
    target.write_bytes(b"")
    result = hash_file(target)
    assert result["md5"] == "d41d8cd98f00b204e9800998ecf8427e"
    assert result["sha1"] == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert result["sha256"] == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_hash_file_hello_world(tmp_path: Path) -> None:
    target = tmp_path / "hello"
    target.write_bytes(b"hello world")
    result = hash_file(target)
    assert result["md5"] == "5eb63bbbe01eeed093cb22bb8f5acdc3"
    assert result["sha1"] == "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
    assert result["sha256"] == (
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    )


def test_hash_file_large_chunks(tmp_path: Path) -> None:
    """Make sure chunked reads give the same digest as whole-file reads."""
    import hashlib

    data = b"A" * (1024 * 1024 * 3 + 17)   # 3 MiB + change
    target = tmp_path / "big"
    target.write_bytes(data)

    got = hash_file(target)
    assert got["sha256"] == hashlib.sha256(data).hexdigest()
