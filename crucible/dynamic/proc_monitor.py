"""Track child processes of a running sample using psutil.

The watcher runs in a background thread while the sample is live. On each
poll it snapshots children of the root PID (and their descendants), keeping
a deduplicated record of every process we ever saw.
"""

from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

try:
    import psutil  # type: ignore
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore


@dataclass
class ProcessRecord:
    """One process we observed during the dynamic run."""

    pid: int
    name: str
    cmdline: List[str]
    create_time: float
    parent_pid: int = 0


class ProcessWatcher:
    """Background poller for descendants of a root PID.

    Usage:

        watcher = ProcessWatcher(root_pid).start()
        # ... run the sample ...
        records = watcher.stop()
    """

    def __init__(self, root_pid: int, interval: float = 0.1) -> None:
        self.root_pid = root_pid
        self.interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._seen: Dict[int, ProcessRecord] = {}
        self._lock = threading.Lock()

    def start(self) -> "ProcessWatcher":
        if psutil is not None:
            self._thread.start()
        return self

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                root = psutil.Process(self.root_pid)
                family = [root] + root.children(recursive=True)
                for proc in family:
                    try:
                        info = proc.as_dict(
                            attrs=["pid", "name", "cmdline", "create_time", "ppid"]
                        )
                    except psutil.Error:
                        continue
                    with self._lock:
                        if info["pid"] not in self._seen:
                            self._seen[info["pid"]] = ProcessRecord(
                                pid=info["pid"],
                                name=info.get("name") or "",
                                cmdline=list(info.get("cmdline") or []),
                                create_time=float(info.get("create_time") or 0.0),
                                parent_pid=int(info.get("ppid") or 0),
                            )
            except psutil.Error:
                pass  # root died, poll again
            self._stop.wait(self.interval)

    def stop(self) -> List[Dict[str, Any]]:
        """Signal the poller to exit and return all records we saw."""
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=2.0)
        with self._lock:
            return [asdict(r) for r in self._seen.values()]


def summarize(records: List[Dict[str, Any]], root_pid: int) -> Dict[str, Any]:
    """Turn raw records into a compact summary for the report."""
    children = [r for r in records if r["pid"] != root_pid]
    suspicious_names = {"bash", "sh", "dash", "zsh", "curl", "wget", "nc",
                        "ncat", "python", "python3", "perl", "ruby"}
    suspicious = [
        r for r in children
        if r["name"] in suspicious_names
    ]
    return {
        "total_processes": len(records),
        "child_count": len(children),
        "processes": records,
        "suspicious_children": suspicious,
    }
