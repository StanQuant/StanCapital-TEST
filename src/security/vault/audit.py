"""S10 audit metadata builder。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, cast

from src.security.vault.redaction import redact_secret_payload
from src.security.vault.types import SecretAction, SecretMetadata


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class SecretAuditEvent:
    """可交給 S05/S28 的 redacted audit metadata。"""

    action: SecretAction
    metadata: SecretMetadata
    actor_id: str
    trace_id: str
    result: str
    reason: str
    failure_category: str | None = None
    timestamp: datetime = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        for field_name in ("actor_id", "trace_id", "result", "reason"):
            if not getattr(self, field_name):
                raise ValueError(f"{field_name} 不可為空")
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp 必須是 tz-aware 時間")
        if self.failure_category == "":
            raise ValueError("failure_category 不可為空字串")

    def to_metadata(self) -> dict[str, Any]:
        """輸出不含 secret 原文的 audit metadata。"""
        return cast(
            dict[str, Any],
            redact_secret_payload(
                {
                    "event_type": "secret_lifecycle",
                    "action": self.action.value,
                    "actor_id": self.actor_id,
                    "trace_id": self.trace_id,
                    "result": self.result,
                    "reason": self.reason,
                    "failure_category": self.failure_category,
                    "timestamp": self.timestamp.isoformat(),
                    "resource": self.metadata.to_audit_metadata(),
                }
            ),
        )
