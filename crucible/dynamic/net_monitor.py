"""Derive network activity from a syscall trace.

We pull out socket/connect/sendto/bind calls. Running inside `unshare -rn`
means the sample can't actually reach anywhere, but the syscalls still fire
and the trace captures the intent.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List

from crucible.dynamic.tracer import Syscall

_SOCKADDR_RE = re.compile(
    r"""
    sa_family=(?P<fam>[A-Z_]+)      # AF_INET, AF_INET6, AF_UNIX, ...
    (?:,\s*sin_port=htons\((?P<port>\d+)\))?
    (?:,\s*sin_addr=(?:inet_addr\(\")?(?P<addr>[\d.:a-fA-F]+)(?:\"\))?)?
    """,
    re.VERBOSE,
)


def _parse_sockaddr(args: str) -> Dict[str, Any]:
    m = _SOCKADDR_RE.search(args)
    if not m:
        return {}
    return {
        "family": m.group("fam"),
        "port": int(m.group("port")) if m.group("port") else None,
        "address": m.group("addr"),
    }


def analyze(syscalls: Iterable[Syscall]) -> Dict[str, Any]:
    """Pull out connect, bind, sendto, and DNS-ish calls."""
    sockets: List[Dict[str, Any]] = []
    connects: List[Dict[str, Any]] = []
    binds: List[Dict[str, Any]] = []
    sendtos: List[Dict[str, Any]] = []

    for sc in syscalls:
        if sc.name == "socket":
            # socket(AF_INET, SOCK_STREAM, ...) -> fd
            fam_match = re.search(r"(AF_[A-Z_0-9]+)", sc.args)
            type_match = re.search(r"(SOCK_[A-Z_0-9]+)", sc.args)
            sockets.append({
                "family": fam_match.group(1) if fam_match else None,
                "type": type_match.group(1) if type_match else None,
                "ret": sc.ret,
            })
        elif sc.name == "connect":
            info = _parse_sockaddr(sc.args)
            info["ret"] = sc.ret
            connects.append(info)
        elif sc.name == "bind":
            info = _parse_sockaddr(sc.args)
            info["ret"] = sc.ret
            binds.append(info)
        elif sc.name in ("sendto", "sendmsg"):
            info = _parse_sockaddr(sc.args)
            info["ret"] = sc.ret
            sendtos.append(info)

    return {
        "sockets": sockets[:100],
        "connect_attempts": connects[:100],
        "bind_attempts": binds[:100],
        "send_attempts": sendtos[:100],
        "attempted_network": bool(connects or sendtos),
    }
