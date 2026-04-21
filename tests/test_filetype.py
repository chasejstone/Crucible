"""File type sniffing tests."""

from pathlib import Path

from crucible.utils.filetype import sniff


def test_sniff_elf(tmp_path: Path) -> None:
    target = tmp_path / "bin"
    # Minimal ELF magic is enough for the sniffer.
    target.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56)
    ft = sniff(target)
    assert ft.kind == "elf"
    assert ft.executable_on_linux is True


def test_sniff_pe(tmp_path: Path) -> None:
    target = tmp_path / "sample.exe"
    # "MZ" header plus "PE\0\0" later in the buffer.
    target.write_bytes(b"MZ" + b"\x00" * 58 + b"PE\x00\x00" + b"\x00" * 200)
    ft = sniff(target)
    assert ft.kind == "pe"
    assert ft.executable_on_linux is False


def test_sniff_script(tmp_path: Path) -> None:
    target = tmp_path / "run.sh"
    target.write_bytes(b"#!/bin/bash\necho hi\n")
    ft = sniff(target)
    assert ft.kind == "script"
    assert ft.interpreter == "/bin/bash"


def test_sniff_text(tmp_path: Path) -> None:
    target = tmp_path / "notes.txt"
    target.write_bytes(b"just some plain text notes for the reader\n")
    ft = sniff(target)
    assert ft.kind == "text"
    assert ft.executable_on_linux is False
