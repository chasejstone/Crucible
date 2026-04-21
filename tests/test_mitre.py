"""MITRE mapping tests."""

from crucible.report.mitre import techniques_for


def test_known_indicator_maps() -> None:
    result = techniques_for(["reverse_shell_strings"])
    assert any(t["id"] == "T1059.004" for t in result)


def test_unknown_indicator_ignored() -> None:
    assert techniques_for(["not_a_real_indicator"]) == []


def test_multiple_indicators_dedup() -> None:
    result = techniques_for(["url_strings", "network_connect"])
    ids = sorted(t["id"] for t in result)
    # T1071 and T1071.001 both show up but should not duplicate.
    assert ids == sorted(set(ids))
    assert any(t["id"].startswith("T1071") for t in result)
