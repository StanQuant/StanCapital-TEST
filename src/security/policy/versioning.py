"""Policy 版本控制與回滾。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from ulid import ULID

from src.security.policy.errors import PolicyVersionError
from src.security.policy.types import PolicySet


def _new_id() -> str:
    return str(ULID())


def _utc_now() -> datetime:
    return datetime.now(UTC)


class PolicyVersionStatus(StrEnum):
    """版本狀態。歷史不刪除，active pointer 另行保存。"""

    PUBLISHED = "published"
    ROLLED_BACK_TO = "rolled_back_to"


@dataclass(frozen=True, slots=True)
class PolicyVersionRecord:
    """append-only policy version registry 記錄。"""

    policy_set_id: str
    version: str
    content_hash: str
    created_by: str
    status: PolicyVersionStatus
    previous_version: str | None = None
    source_path: str | None = None
    created_at: datetime = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        for field_name in ("policy_set_id", "version", "content_hash", "created_by"):
            if not getattr(self, field_name):
                raise ValueError(f"{field_name} 不可為空")
        if self.source_path == "":
            raise ValueError("source_path 不可為空字串")
        if self.created_at.tzinfo is None:
            raise ValueError("created_at 必須是 tz-aware 時間")


@dataclass(frozen=True, slots=True)
class PolicyRollbackEvent:
    """rollback 不刪歷史，只移動 active pointer 並留下事件。"""

    policy_set_id: str
    from_version: str
    to_version: str
    rolled_back_by: str
    event_id: str = field(default_factory=_new_id)
    created_at: datetime = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        for field_name in (
            "policy_set_id",
            "from_version",
            "to_version",
            "rolled_back_by",
            "event_id",
        ):
            if not getattr(self, field_name):
                raise ValueError(f"{field_name} 不可為空")
        if self.created_at.tzinfo is None:
            raise ValueError("created_at 必須是 tz-aware 時間")


class InMemoryPolicyVersionRegistry:
    """S08 第一版 registry port 實作；DB 持久化留給 S26/S28。"""

    def __init__(self) -> None:
        self._records: list[PolicyVersionRecord] = []
        self._active: dict[str, str] = {}
        self._rollback_events: list[PolicyRollbackEvent] = []

    @property
    def records(self) -> tuple[PolicyVersionRecord, ...]:
        return tuple(self._records)

    @property
    def rollback_events(self) -> tuple[PolicyRollbackEvent, ...]:
        return tuple(self._rollback_events)

    def publish(
        self,
        policy_set: PolicySet,
        *,
        created_by: str,
        source_path: str | None = None,
    ) -> PolicyVersionRecord:
        """發佈新版本；同一 policy_set_id + version 不可覆寫。"""
        if self._find(policy_set.policy_set_id, policy_set.version) is not None:
            raise PolicyVersionError(
                f"policy version 已存在: {policy_set.policy_set_id}/{policy_set.version}"
            )
        record = PolicyVersionRecord(
            policy_set_id=policy_set.policy_set_id,
            version=policy_set.version,
            content_hash=policy_set.content_hash,
            created_by=created_by,
            status=PolicyVersionStatus.PUBLISHED,
            previous_version=self._active.get(policy_set.policy_set_id),
            source_path=source_path,
        )
        self._records.append(record)
        self._active[policy_set.policy_set_id] = record.version
        return record

    def active_record(self, policy_set_id: str) -> PolicyVersionRecord:
        """取得目前 active version。"""
        active_version = self._active.get(policy_set_id)
        if active_version is None:
            raise PolicyVersionError(f"policy set 尚無 active version: {policy_set_id}")
        record = self._find(policy_set_id, active_version)
        if record is None:
            raise PolicyVersionError(
                f"active pointer 指向不存在版本: {policy_set_id}/{active_version}"
            )
        return record

    def rollback(
        self,
        policy_set_id: str,
        *,
        target_version: str,
        rolled_back_by: str,
    ) -> PolicyRollbackEvent:
        """移動 active pointer 到既有版本並留下 rollback event。"""
        current = self.active_record(policy_set_id)
        if self._find(policy_set_id, target_version) is None:
            raise PolicyVersionError(f"rollback target 不存在: {policy_set_id}/{target_version}")
        if current.version == target_version:
            raise PolicyVersionError(f"rollback target 已是 active version: {target_version}")
        event = PolicyRollbackEvent(
            policy_set_id=policy_set_id,
            from_version=current.version,
            to_version=target_version,
            rolled_back_by=rolled_back_by,
        )
        self._rollback_events.append(event)
        self._active[policy_set_id] = target_version
        return event

    def _find(self, policy_set_id: str, version: str) -> PolicyVersionRecord | None:
        return next(
            (
                record
                for record in self._records
                if record.policy_set_id == policy_set_id and record.version == version
            ),
            None,
        )
