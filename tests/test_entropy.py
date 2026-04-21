"""Entropy math tests."""

import os

from crucible.static.entropy import is_likely_packed, shannon, summarize_sections


def test_shannon_empty_is_zero() -> None:
    assert shannon(b"") == 0.0


def test_shannon_uniform_is_zero() -> None:
    # A buffer of a single byte value has zero entropy.
    assert shannon(b"A" * 1000) == 0.0


def test_shannon_random_is_near_eight() -> None:
    # Cryptographic random bytes should be close to 8 bits per byte.
    data = os.urandom(64 * 1024)
    assert shannon(data) > 7.8


def test_shannon_two_equal_symbols_is_one_bit() -> None:
    # 50/50 distribution: entropy is exactly 1 bit per byte.
    data = b"AB" * 500
    assert abs(shannon(data) - 1.0) < 1e-9


def test_is_likely_packed_threshold() -> None:
    assert is_likely_packed([7.5, 3.0]) is True
    assert is_likely_packed([6.9, 6.5]) is False


def test_summarize_sections() -> None:
    summary = summarize_sections([
        {"name": ".text", "entropy": 6.5},
        {"name": ".data", "entropy": 7.4},
    ])
    assert summary["packed"] is True
    assert 6.4 < summary["avg_entropy"] < 7.5
    assert summary["max_entropy"] == 7.4
