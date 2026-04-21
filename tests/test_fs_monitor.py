"""Filesystem monitor classification tests."""

from crucible.dynamic.fs_monitor import analyze
from crucible.dynamic.tracer import Syscall


def _sc(name: str, args: str, ret: str = "0") -> Syscall:
    return Syscall(name=name, args=args, ret=ret)


def test_writes_and_reads_split() -> None:
    syscalls = [
        _sc("openat", 'AT_FDCWD, "/etc/passwd", O_RDONLY'),
        _sc("openat", 'AT_FDCWD, "/tmp/out", O_WRONLY|O_CREAT'),
        _sc("unlink", '"/tmp/victim"'),
    ]
    out = analyze(syscalls)
    assert "/etc/passwd" in out["reads"]
    assert "/tmp/out" in out["writes"]
    assert "/tmp/victim" in out["deletes"]


def test_sensitive_writes_detected() -> None:
    syscalls = [
        _sc("openat", 'AT_FDCWD, "/etc/crontab", O_WRONLY'),
        _sc("openat", 'AT_FDCWD, "/root/.ssh/authorized_keys", O_RDWR'),
    ]
    out = analyze(syscalls)
    assert any("crontab" in p for p in out["sensitive_writes"])
    assert any(".ssh" in p for p in out["sensitive_writes"])
