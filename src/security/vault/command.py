"""外部 CLI provider 的命令執行邊界。"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class CommandResult:
    """命令執行結果。stdout / stderr 進錯誤前必須避免包含 secret。"""

    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandRunner(Protocol):
    """可替換命令執行器。測試用 fake，避免碰真 Keychain / pass。"""

    def run(self, args: Sequence[str], input_text: str | None = None) -> CommandResult:
        """執行命令並回傳結果。"""


class SubprocessCommandRunner:
    """真 subprocess runner。S10 測試預設不使用。"""

    def run(self, args: Sequence[str], input_text: str | None = None) -> CommandResult:
        completed = subprocess.run(  # noqa: S603 - args 由 provider 建構且測試覆蓋，不走 shell。
            list(args),
            input=input_text,
            capture_output=True,
            check=False,
            text=True,
        )
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)
