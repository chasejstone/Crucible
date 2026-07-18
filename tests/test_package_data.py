from crucible.cli import DEFAULT_REPORTS_DIR, DEFAULT_RULES_DIR


def test_default_rules_are_bundled_with_the_package() -> None:
    assert DEFAULT_RULES_DIR.is_dir()
    assert list(DEFAULT_RULES_DIR.glob("*.yar"))


def test_default_reports_directory_is_relative_to_the_working_directory() -> None:
    assert DEFAULT_REPORTS_DIR.as_posix() == "reports"
