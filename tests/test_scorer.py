"""Scorer boundary and weighting tests."""

from crucible.report.scorer import score


def test_clean_sample_scores_zero() -> None:
    findings = {
        "static": {
            "strings": {"flagged": {}},
            "yara": {"matches": []},
            "elf": {"parsed": True, "sections": []},
            "section_summary": {"packed": False, "max_entropy": 5.0, "avg_entropy": 4.0},
        },
        "dynamic": {"ran": False},
    }
    result = score(findings)
    assert result.score == 0
    assert result.label == "low"


def test_score_caps_at_one_hundred() -> None:
    findings = {
        "static": {
            "strings": {"flagged": {
                "url": ["http://a"] * 10,
                "suspicious_api": ["VirtualAlloc"] * 10,
                "reverse_shell": ["bash -i"] * 5,
            }},
            "yara": {"matches": [{"rule": f"r{i}"} for i in range(5)]},
            "section_summary": {"packed": True, "max_entropy": 7.9},
        },
        "dynamic": {
            "ran": True,
            "network": {"connect_attempts": [{"address": "1.2.3.4"}]},
            "filesystem": {"sensitive_writes": ["/etc/cron.d/evil",
                                                 "/etc/systemd/system/x.service",
                                                 "/root/.ssh/authorized_keys"]},
            "processes": {"suspicious_children": [{"name": "bash"},
                                                   {"name": "curl"}]},
        },
    }
    result = score(findings)
    assert result.score == 100
    assert result.label == "critical"


def test_indicator_list_covers_hits() -> None:
    findings = {
        "static": {
            "strings": {"flagged": {"reverse_shell": ["bash -i"]}},
            "yara": {"matches": []},
            "section_summary": {"packed": False, "max_entropy": 5.0},
        },
        "dynamic": {"ran": False},
    }
    result = score(findings)
    assert "reverse_shell_strings" in result.indicators
    assert result.score > 0


def test_medium_label_threshold() -> None:
    findings = {
        "static": {
            "strings": {"flagged": {"url": ["http://x", "http://y", "http://z"],
                                     "suspicious_api": ["WinExec", "VirtualAlloc"]}},
            "yara": {"matches": []},
            "section_summary": {"packed": False, "max_entropy": 5.0},
        },
        "dynamic": {"ran": False},
    }
    result = score(findings)
    assert result.score >= 19


def test_repeated_hits_respect_category_cap() -> None:
    findings = {
        "static": {},
        "dynamic": {
            "ran": True,
            "filesystem": {
                "sensitive_writes": [
                    "/etc/cron.d/first",
                    "/etc/cron.d/second",
                    "/etc/cron.d/third",
                ],
            },
        },
    }

    result = score(findings)
    cron_points = sum(
        row["points"]
        for row in result.breakdown
        if row["indicator"] == "write_crontab"
    )

    assert cron_points == 20
    assert result.score == 50
