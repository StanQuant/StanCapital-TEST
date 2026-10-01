"""Policy version registry 測試。"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime

import pytest
from src.security.policy.dsl import parse_policy_set
from src.security.policy.errors import PolicyVersionError
from src.security.policy.versioning import (
    InMemoryPolicyVersionRegistry,
    PolicyRollbackEvent,
    PolicyVersionRecord,
    PolicyVersionStatus,
)

from .conftest import base_policy_set, policy_text, raises_starting


def test_version_status_values_are_stable_contracts() -> None:
    assert {status.name: status.value for status in PolicyVersionStatus} == {
        "PUBLISHED": "published",
        "ROLLED_BACK_TO": "rolled_back_to",
    }


def test_publish_active_record_and_rollback_are_append_only() -> None:
    registry = InMemoryPolicyVersionRegistry()
    v1 = base_policy_set()
    v2 = parse_policy_set(policy_text(version="2026.06.23-002"))
    first = registry.publish(v1, created_by="stanley", source_path="policies/security/base.yaml")
    second = registry.publish(v2, created_by="stanley")
    assert first.previous_version is None
    assert first.status is PolicyVersionStatus.PUBLISHED
    assert second.previous_version == v1.version
    assert registry.active_record(v1.policy_set_id).version == v2.version
    event = registry.rollback(v1.policy_set_id, target_version=v1.version, rolled_back_by="stanley")
    assert event.from_version == v2.version
    assert event.to_version == v1.version
    assert registry.active_record(v1.policy_set_id).version == v1.version
    assert len(registry.records) == 2
    assert registry.rollback_events == (event,)


def test_registry_rejects_duplicate_missing_and_noop_rollback() -> None:
    registry = InMemoryPolicyVersionRegistry()
    policy_set = base_policy_set()
    with raises_starting(PolicyVersionError, "policy set 尚無 active version"):
        registry.active_record(policy_set.policy_set_id)
    registry.publish(policy_set, created_by="stanley")
    with raises_starting(PolicyVersionError, "policy version 已存在"):
        registry.publish(policy_set, created_by="stanley")
    with raises_starting(PolicyVersionError, "rollback target 不存在"):
        registry.rollback(
            policy_set.policy_set_id, target_version="missing", rolled_back_by="stanley"
        )
    with raises_starting(PolicyVersionError, "rollback target 已是 active version"):
        registry.rollback(
            policy_set.policy_set_id,
            target_version=policy_set.version,
            rolled_back_by="stanley",
        )
    registry._active[policy_set.policy_set_id] = "ghost"
    with raises_starting(PolicyVersionError, "active pointer 指向不存在版本"):
        registry.active_record(policy_set.policy_set_id)


def test_version_record_and_rollback_event_are_frozen_slotted_value_objects() -> None:
    record = PolicyVersionRecord("base", "v1", "hash", "stanley", PolicyVersionStatus.PUBLISHED)
    assert not hasattr(record, "__dict__")
    assert record.previous_version is None
    assert record.source_path is None
    with pytest.raises(FrozenInstanceError):
        record.version = "v2"  # type: ignore[misc]
    event = PolicyRollbackEvent("base", "v2", "v1", "stanley")
    assert not hasattr(event, "__dict__")
    with pytest.raises(FrozenInstanceError):
        event.to_version = "v3"  # type: ignore[misc]


def test_version_record_and_rollback_event_validation() -> None:
    with raises_starting(ValueError, "policy_set_id 不可為空"):
        PolicyVersionRecord("", "v1", "hash", "stanley", PolicyVersionStatus.PUBLISHED)
    with raises_starting(ValueError, "source_path 不可為空字串"):
        PolicyVersionRecord(
            "base", "v1", "hash", "stanley", PolicyVersionStatus.PUBLISHED, source_path=""
        )
    with raises_starting(ValueError, "created_at 必須是 tz-aware 時間"):
        PolicyVersionRecord(
            "base",
            "v1",
            "hash",
            "stanley",
            PolicyVersionStatus.PUBLISHED,
            created_at=datetime(2026, 6, 23),
        )
    with raises_starting(ValueError, "from_version 不可為空"):
        PolicyRollbackEvent("base", "", "v1", "stanley")
    with raises_starting(ValueError, "created_at 必須是 tz-aware 時間"):
        PolicyRollbackEvent("base", "v2", "v1", "stanley", created_at=datetime(2026, 6, 23))
