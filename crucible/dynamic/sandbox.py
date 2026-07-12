"""Orchestrate a dynamic run: isolate, launch, trace, collect.

Steps each run takes:

1. Copy the target into a temporary workdir so it can't corrupt cwd.
2. Build a command that wraps the sample with ``strace`` and runs the
   whole thing inside an unshared network namespace, so any network
   syscalls fire but can't actually reach anything.
3. Spawn the child with ``subprocess.Popen``, kick off a psutil watcher
   for children, and wait with a timeout.
4. Feed the trace log to the fs/net monitors and package the lot.

This module is deliberately pragmatic. Real malware execution needs a
VM. What we provide is a fast loop with enough containment that running
a curious bash script doesn't wreck your host.
"""

from __future__ import annotations

import logging
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from crucible.dynamic import fs_monitor, net_monitor, proc_monitor, tracer
from crucible.utils.filetype import FileType

log = logging.getLogger("crucible")

_DEFAULT_TIMEOUT = 15


@dataclass
class DynamicResult:
    """Everything the dynamic stage discovered about one run."""

    ran: bool
    reason: Optional[str] = None
    exit_code: Optional[int] = None
    timed_out: bool = False
    duration_seconds: float = 0.0
    syscall_count: int = 0
    filesystem: Dict[str, Any] = field(default_factory=dict)
    network: Dict[str, Any] = field(default_factory=dict)
    processes: Dict[str, Any] = field(default_factory=dict)
    syscall_summary: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ran": self.ran,
            "reason": self.reason,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "duration_seconds": round(self.duration_seconds, 3),
            "syscall_count": self.syscall_count,
            "syscall_summary": self.syscall_summary,
            "filesystem": self.filesystem,
            "network": self.network,
            "processes": self.processes,
        }


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _build_invocation(target: Path, ftype: FileType,
                      trace_log: Path) -> Optional[List[str]]:
    """Compose the command line we'll hand to Popen.

    Returns None if the file type isn't runnable on Linux. Both ``unshare``
    and ``strace`` are required so a sample is never run with host networking.
    """
    if not ftype.executable_on_linux:
        return None

    if not _have("strace"):
        log.warning("strace not available, dynamic stage will be skipped")
        return None

    if not _have("unshare"):
        log.warning("unshare not available, dynamic stage will be skipped")
        return None

    runner: List[str] = ["unshare", "-rn"]

    runner += ["strace", "-f", "-qq", "-s", "256", "-o", str(trace_log)]

    if ftype.kind == "elf":
        runner.append(str(target))
    elif ftype.kind == "script" and ftype.interpreter:
        runner += ftype.interpreter.split() + [str(target)]
    else:
        return None

    return runner


def run(target: Path, ftype: FileType,
        timeout: int = _DEFAULT_TIMEOUT,
        workdir: Optional[Path] = None) -> DynamicResult:
    """Execute the sample under strace and collect observations."""
    if not ftype.executable_on_linux:
        return DynamicResult(ran=False,
                             reason=f"file type {ftype.kind!r} not runnable on Linux")

    owns_workdir = workdir is None
    workdir = workdir or Path(tempfile.mkdtemp(prefix="crucible_"))
    workdir.mkdir(parents=True, exist_ok=True)

    staged = workdir / target.name
    try:
        shutil.copy2(target, staged)
        staged.chmod(staged.stat().st_mode | stat.S_IXUSR | stat.S_IRUSR)
    except OSError as exc:
        return DynamicResult(ran=False, reason=f"staging failed: {exc}")

    trace_log = workdir / "trace.log"
    cmd = _build_invocation(staged, ftype, trace_log)
    if cmd is None:
        return DynamicResult(ran=False,
                             reason="no suitable invocation for this file type")

    log.info("launching sandbox: %s", " ".join(cmd))
    start = time.monotonic()
    timed_out = False
    exit_code: Optional[int] = None

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(workdir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        return DynamicResult(ran=False, reason=f"spawn failed: {exc}")

    watcher = proc_monitor.ProcessWatcher(proc.pid).start()

    try:
        exit_code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        try:
            exit_code = proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()

    duration = time.monotonic() - start
    proc_records = watcher.stop()

    syscalls = tracer.parse_file(trace_log) if trace_log.exists() else []
    syscall_counts: Dict[str, int] = {}
    for sc in syscalls:
        syscall_counts[sc.name] = syscall_counts.get(sc.name, 0) + 1

    result = DynamicResult(
        ran=True,
        exit_code=exit_code,
        timed_out=timed_out,
        duration_seconds=duration,
        syscall_count=len(syscalls),
        syscall_summary=_top_syscalls(syscall_counts),
        filesystem=fs_monitor.analyze(syscalls),
        network=net_monitor.analyze(syscalls),
        processes=proc_monitor.summarize(proc_records, proc.pid),
    )

    if owns_workdir:
        shutil.rmtree(workdir, ignore_errors=True)

    return result


def _kill_tree(proc: subprocess.Popen) -> None:
    """SIGTERM the process group, then SIGKILL if it lingers."""
    try:
        import os
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGTERM)
        time.sleep(0.2)
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.terminate()
        except OSError:
            pass


def _top_syscalls(counts: Dict[str, int], n: int = 20) -> Dict[str, int]:
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:n])
