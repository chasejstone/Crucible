from pathlib import Path
from unittest.mock import patch

from crucible.dynamic import sandbox
from crucible.utils.filetype import FileType


def test_dynamic_invocation_requires_network_namespace() -> None:
    file_type = FileType(kind="elf", executable_on_linux=True)

    with patch.object(sandbox, "_have", side_effect=lambda command: command == "strace"):
        command = sandbox._build_invocation(Path("sample"), file_type, Path("trace.log"))

    assert command is None


def test_dynamic_invocation_uses_unshare() -> None:
    file_type = FileType(kind="elf", executable_on_linux=True)

    with patch.object(sandbox, "_have", return_value=True):
        command = sandbox._build_invocation(Path("sample"), file_type, Path("trace.log"))

    assert command is not None
    assert command[:2] == ["unshare", "-rn"]
    assert "strace" in command
