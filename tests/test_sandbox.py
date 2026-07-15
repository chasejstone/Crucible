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


def test_owned_workdir_is_removed_when_invocation_is_unavailable(tmp_path: Path) -> None:
    target = tmp_path / "sample"
    target.write_bytes(b"sample")
    generated_workdir = tmp_path / "crucible_work"
    generated_workdir.mkdir()
    file_type = FileType(kind="elf", executable_on_linux=True)

    with patch.object(
        sandbox.tempfile, "mkdtemp", return_value=str(generated_workdir)
    ):
        with patch.object(sandbox, "_build_invocation", return_value=None):
            result = sandbox.run(target, file_type)

    assert result.ran is False
    assert result.reason == "no suitable invocation for this file type"
    assert not generated_workdir.exists()
