"""Map Crucible indicators to MITRE ATT&CK technique IDs.

This isn't meant to be exhaustive. It's a starter mapping that covers the
indicators we actually produce, grouped by how they surface during
analysis.
"""

from __future__ import annotations

from typing import Dict, List

# indicator key -> list of (technique_id, short_label)
INDICATOR_MAP: Dict[str, List[tuple]] = {
    "packed_sections": [("T1027.002", "Software Packing")],
    "high_entropy":   [("T1027", "Obfuscated Files or Information")],
    "yara_hit":       [("T1027", "Obfuscated Files or Information")],
    "suspicious_api_import": [
        ("T1055", "Process Injection"),
        ("T1106", "Native API"),
    ],
    "reverse_shell_strings": [("T1059.004", "Unix Shell")],
    "shell_oneliner_strings": [("T1059", "Command and Scripting Interpreter")],
    "url_strings":    [("T1071.001", "Web Protocols")],
    "ipv4_strings":   [("T1071", "Application Layer Protocol")],
    "network_connect": [("T1071", "Application Layer Protocol")],
    "network_send":   [("T1041", "Exfiltration Over C2 Channel")],
    "child_spawn_shell": [("T1059.004", "Unix Shell")],
    "child_spawn_download": [("T1105", "Ingress Tool Transfer")],
    "write_crontab":  [("T1053.003", "Cron")],
    "write_systemd":  [("T1543.002", "Systemd Service")],
    "write_ssh":      [("T1098.004", "SSH Authorized Keys")],
    "registry_strings": [("T1112", "Modify Registry")],
}


def techniques_for(indicators: List[str]) -> List[Dict[str, str]]:
    """Return deduplicated technique entries for the given indicator keys."""
    seen: Dict[str, Dict[str, str]] = {}
    for key in indicators:
        for tid, label in INDICATOR_MAP.get(key, []):
            seen[tid] = {"id": tid, "name": label}
    return sorted(seen.values(), key=lambda e: e["id"])
