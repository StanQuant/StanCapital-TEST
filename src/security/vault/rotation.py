"""S10 密鑰輪換輔助。"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from src.security.vault.types import SecretMetadata, SecretRotationPolicy


def rotation_due(metadata: SecretMetadata, policy: SecretRotationPolicy, *, now: datetime) -> bool:
    """是否已到強制輪換時間。"""
    if now.tzinfo is None:
        raise ValueError("now 必須是 tz-aware 時間")
    return now - metadata.updated_at >= timedelta(days=policy.max_age_days)


def rotation_notice_due(
    metadata: SecretMetadata, policy: SecretRotationPolicy, *, now: datetime
) -> bool:
    """是否進入輪換提醒期。"""
    if now.tzinfo is None:
        raise ValueError("now 必須是 tz-aware 時間")
    age = now - metadata.updated_at
    return age >= timedelta(days=policy.max_age_days - policy.notify_before_days)


@dataclass(frozen=True, slots=True)
class RotationTemplate:
    """cron 範本文字。S10 只產生範本，不建立真排程。"""

    schedule: str
    command: str

    def __post_init__(self) -> None:
        if not self.schedule:
            raise ValueError("schedule 不可為空")
        if not self.command:
            raise ValueError("command 不可為空")

    def render(self) -> str:
        return f"{self.schedule} {self.command}\n"


DEFAULT_ROTATION_TEMPLATE = RotationTemplate(
    schedule="0 3 * * *",
    command=(
        "cd /app && .venv/bin/python -m src.security.vault.rotate "
        "--policy max-age-days=90 --dry-run"
    ),
)


def utc_now() -> datetime:
    """測試可替換的 UTC now helper。"""
    return datetime.now(UTC)
