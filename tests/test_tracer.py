"""Tracer output parsing tests."""

from crucible.dynamic.tracer import extract_string_arg, parse_line


def test_parse_simple_line() -> None:
    sc = parse_line('openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3')
    assert sc is not None
    assert sc.name == "openat"
    assert sc.ret == "3"
    assert '"/etc/passwd"' in sc.args


def test_parse_with_pid_and_timestamp() -> None:
    sc = parse_line(
        '[pid 12345] 1713600000.123456 connect(4, '
        '{sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}, '
        '16) = -1'
    )
    assert sc is not None
    assert sc.pid == 12345
    assert sc.ts is not None
    assert sc.name == "connect"
    assert sc.ret == "-1"


def test_extract_string_arg() -> None:
    args = 'AT_FDCWD, "/tmp/foo", O_RDONLY'
    assert extract_string_arg(args, 0) == "/tmp/foo"
    assert extract_string_arg(args, 1) is None


def test_parse_bare_pid_prefix_from_follow() -> None:
    """strace -f emits bare PID prefixes without the [pid N] wrapper."""
    sc = parse_line('4545  openat(AT_FDCWD, "/tmp/x", O_RDONLY) = 3')
    assert sc is not None
    assert sc.pid == 4545
    assert sc.name == "openat"


def test_parse_ignores_junk() -> None:
    assert parse_line("--- SIGCHLD ---") is None
    assert parse_line("") is None
