"""CommandRunner 測試。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.security.vault.command import SubprocessCommandRunner


@dataclass(slots=True)
class Completed:
    returncode: int
    stdout: str
    stderr: str


def test_subprocess_command_runner(monkeypatch: Any) -> None:
    calls: list[tuple[list[str], str | None]] = []

    def fake_run(
        args: list[str],
        *,
        input: str | None,
        capture_output: bool,
        check: bool,
        text: bool,
    ) -> Completed:
        calls.append((args, input))
        assert capture_output is True
        assert check is False
        assert text is True
        return Completed(0, "out", "err")

    monkeypatch.setattr("subprocess.run", fake_run)
    result = SubprocessCommandRunner().run(["echo", "ok"], input_text="payload")
    assert result.ok is True
    assert result.stdout == "out"
    assert result.stderr == "err"
    assert calls == [(["echo", "ok"], "payload")]
