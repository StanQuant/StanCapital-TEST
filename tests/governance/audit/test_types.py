"""S05 · Audit 領域物件的建構期驗證測試。

重點: 非法狀態(空 tenant、壞雜湊格式、naive 時間)連物件都做不出來。
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest
from src.governance.audit.errors import AuditError, AuditUnavailableError, ChainCorruptionError
from src.governance.audit.types import (
    GENESIS_HASH,
    AuditOutcome,
    AuditPage,
    AuditQuery,
    ChainHead,
    TamperReport,
)

from tests.governance.audit.conftest import SAMPLE_HASH, make_input, make_record

# ============================================================================
# 不可變值物件紀律: frozen + slots(與 L4/S04 同款，參數化全覆蓋)
# ============================================================================


@pytest.mark.parametrize(
    "instance",
    [
        make_input(),
        make_record(),
        ChainHead(tenant_id="t", last_sequence=0, last_hash=GENESIS_HASH),
        AuditQuery(tenant_id="t"),
        AuditPage(records=(), next_after_sequence=None),
        TamperReport(tenant_id="t", checked_count=0),
    ],
    ids=lambda obj: type(obj).__name__,
)
def test_frozen_and_slots(instance: object) -> None:
    params = dataclasses.fields(instance)  # type: ignore[arg-type]
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(instance, params[0].name, "tampered")
    assert not hasattr(instance, "__dict__")


# ============================================================================
# GENESIS_HASH 是對外契約(鏈的起點，改了全部鏈斷)
# ============================================================================


def test_genesis_hash_is_64_zeros() -> None:
    assert GENESIS_HASH == "0" * 64


# ============================================================================
# AuditOutcome: StrEnum 字串相容(JSON 序列化零摩擦)
# ============================================================================


def test_audit_outcome_values() -> None:
    assert AuditOutcome.SUCCESS == "success"
    assert AuditOutcome.FAILED == "failed"
    assert len(AuditOutcome) == 2


# ============================================================================
# AuditRecordInput 建構期驗證
# ============================================================================


def test_input_valid_construction() -> None:
    record_input = make_input()
    assert record_input.tenant_id == "tenant-a"
    assert record_input.risk_score == 0


@pytest.mark.parametrize(
    ("overrides", "message_part"),
    [
        ({"tenant_id": ""}, "tenant_id 不可為空"),
        ({"user_id": ""}, "user_id 不可為空"),
        ({"action": ""}, "action 不可為空或含空白"),
        ({"action": "order submit"}, "action 不可為空或含空白"),
        ({"resource": ""}, "resource 不可為空"),
        ({"request_payload_hash": "abc"}, "request_payload_hash"),
        ({"request_payload_hash": "Z" * 64}, "request_payload_hash"),
        ({"request_payload_hash": "A" * 64}, "request_payload_hash"),
        ({"ip_address": ""}, "ip_address 不可為空"),
        ({"user_agent": ""}, "user_agent 不可為空"),
        ({"risk_score": -1}, "risk_score 必須在 0-100 之間"),
        ({"risk_score": 101}, "risk_score 必須在 0-100 之間"),
    ],
)
def test_input_rejects_invalid(overrides: dict[str, object], message_part: str) -> None:
    with pytest.raises(ValueError, match=message_part):
        make_input(**overrides)


@pytest.mark.parametrize("score", [0, 50, 100])
def test_input_risk_score_boundaries_accepted(score: int) -> None:
    assert make_input(risk_score=score).risk_score == score


# ============================================================================
# AuditRecord 建構期驗證(含鏈欄位)
# ============================================================================


def test_record_valid_construction_generates_ulid() -> None:
    record = make_record()
    assert len(record.record_id) == 26  # ULID 標準長度


@pytest.mark.parametrize(
    ("overrides", "message_part"),
    [
        ({"tenant_id": ""}, "tenant_id 不可為空"),
        ({"timestamp": datetime(2026, 6, 12, 10, 0, 0)}, "timestamp 必須是 tz-aware"),
        ({"sequence": 0}, "sequence 必須 >= 1"),
        ({"sequence": -5}, "sequence 必須 >= 1"),
        ({"prev_hash": "xyz"}, "prev_hash"),
        ({"record_hash": ""}, "record_hash"),
        ({"record_id": ""}, "record_id 不可為空"),
    ],
)
def test_record_rejects_invalid(overrides: dict[str, object], message_part: str) -> None:
    with pytest.raises(ValueError, match=message_part):
        make_record(**overrides)


# ============================================================================
# ChainHead 建構期驗證
# ============================================================================


def test_chain_head_accepts_genesis_state() -> None:
    head = ChainHead(tenant_id="t", last_sequence=0, last_hash=GENESIS_HASH)
    assert head.last_sequence == 0


@pytest.mark.parametrize(
    ("kwargs", "message_part"),
    [
        ({"tenant_id": "", "last_sequence": 0, "last_hash": GENESIS_HASH}, "tenant_id 不可為空"),
        ({"tenant_id": "t", "last_sequence": -1, "last_hash": GENESIS_HASH}, "last_sequence"),
        ({"tenant_id": "t", "last_sequence": 0, "last_hash": "bad"}, "last_hash"),
    ],
)
def test_chain_head_rejects_invalid(kwargs: dict[str, object], message_part: str) -> None:
    with pytest.raises(ValueError, match=message_part):
        ChainHead(**kwargs)  # type: ignore[arg-type]


# ============================================================================
# AuditQuery 建構期驗證
# ============================================================================


def test_query_defaults() -> None:
    q = AuditQuery(tenant_id="t")
    assert q.after_sequence == 0
    assert q.limit == 100
    assert q.user_id is None


def test_query_accepts_full_filters() -> None:
    q = AuditQuery(
        tenant_id="t",
        user_id="u",
        action="order.submit",
        resource="order/1",
        response_status=AuditOutcome.FAILED,
        start_time=datetime(2026, 1, 1, tzinfo=UTC),
        end_time=datetime(2026, 12, 31, tzinfo=UTC),
        after_sequence=10,
        limit=1000,
    )
    assert q.limit == 1000


@pytest.mark.parametrize(
    ("kwargs", "message_part"),
    [
        ({"tenant_id": ""}, "tenant_id 不可為空"),
        ({"tenant_id": "t", "start_time": datetime(2026, 1, 1)}, "start_time 必須是 tz-aware"),
        ({"tenant_id": "t", "end_time": datetime(2026, 1, 1)}, "end_time 必須是 tz-aware"),
        (
            {
                "tenant_id": "t",
                "start_time": datetime(2026, 2, 1, tzinfo=UTC),
                "end_time": datetime(2026, 1, 1, tzinfo=UTC),
            },
            "start_time 不可晚於 end_time",
        ),
        ({"tenant_id": "t", "after_sequence": -1}, "after_sequence 必須 >= 0"),
        ({"tenant_id": "t", "limit": 0}, "limit 必須在 1-1000 之間"),
        ({"tenant_id": "t", "limit": 1001}, "limit 必須在 1-1000 之間"),
    ],
)
def test_query_rejects_invalid(kwargs: dict[str, object], message_part: str) -> None:
    with pytest.raises(ValueError, match=message_part):
        AuditQuery(**kwargs)  # type: ignore[arg-type]


def test_query_equal_start_end_time_accepted() -> None:
    moment = datetime(2026, 6, 12, tzinfo=UTC)
    q = AuditQuery(tenant_id="t", start_time=moment, end_time=moment)
    assert q.start_time == q.end_time


# ============================================================================
# TamperReport: is_intact 三類異常任一非空即 False
# ============================================================================


def test_tamper_report_intact_when_all_clear() -> None:
    report = TamperReport(tenant_id="t", checked_count=100)
    assert report.is_intact is True


@pytest.mark.parametrize(
    "overrides",
    [
        {"mismatched_sequences": (5,)},
        {"missing_sequences": (3, 4)},
        {"head_mismatch": True},
        {"mismatched_sequences": (5,), "missing_sequences": (3,), "head_mismatch": True},
    ],
)
def test_tamper_report_not_intact(overrides: dict[str, object]) -> None:
    report = TamperReport(tenant_id="t", checked_count=100, **overrides)  # type: ignore[arg-type]
    assert report.is_intact is False


@pytest.mark.parametrize(
    ("kwargs", "message_part"),
    [
        ({"tenant_id": "", "checked_count": 0}, "tenant_id 不可為空"),
        ({"tenant_id": "t", "checked_count": -1}, "checked_count 必須 >= 0"),
    ],
)
def test_tamper_report_rejects_invalid(kwargs: dict[str, object], message_part: str) -> None:
    with pytest.raises(ValueError, match=message_part):
        TamperReport(**kwargs)  # type: ignore[arg-type]


# ============================================================================
# 錯誤型別: 訊息與欄位是對外契約(完全相等釘住，S02 教訓)
# ============================================================================


def test_audit_unavailable_error_fields_and_message() -> None:
    err = AuditUnavailableError(tenant_id="t-1", action="order.submit", reason="db down")
    assert err.tenant_id == "t-1"
    assert err.action == "order.submit"
    assert err.reason == "db down"
    assert str(err) == (
        "稽核寫入失敗，操作已中止(fail-closed): tenant=t-1 action=order.submit reason=db down"
    )


def test_error_hierarchy() -> None:
    assert issubclass(AuditUnavailableError, AuditError)
    assert issubclass(ChainCorruptionError, AuditError)
    assert issubclass(AuditError, Exception)


def test_sample_hash_is_valid_format() -> None:
    # conftest 的樣本本身要合法，否則整組工廠都建立在壞樣本上
    assert len(SAMPLE_HASH) == 64
    assert make_input(request_payload_hash=SAMPLE_HASH)
