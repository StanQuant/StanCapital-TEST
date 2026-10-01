"""S05 · 雜湊鏈引擎測試。

重點: 決定性(同輸入同指紋)、敏感性(任一欄位變指紋必變)、跨時區正規化。
"""

from __future__ import annotations

import dataclasses
import hashlib
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum

import pytest
from src.governance.audit.chain import (
    canonical_json,
    compute_record_hash,
    hash_payload,
    recompute_hash,
)
from src.governance.audit.types import GENESIS_HASH, AuditOutcome
from src.governance.rbac.roles import Role

from tests.governance.audit.conftest import make_input, make_record

_TS = datetime(2026, 6, 12, 10, 30, 0, 123456, tzinfo=UTC)


def _mint(**overrides: object) -> str:
    """用預設參數鑄一個指紋，個別測試只覆寫關心的部分。"""
    defaults: dict[str, object] = {
        "prev_hash": GENESIS_HASH,
        "record_id": "01JXF0000000000000000000AA",
        "timestamp": _TS,
        "sequence": 1,
        "record_input": make_input(),
    }
    defaults.update(overrides)
    return compute_record_hash(**defaults)  # type: ignore[arg-type]


# ============================================================================
# 決定性: 同輸入永遠同指紋(驗證器不誤報的根基)
# ============================================================================


def test_hash_is_deterministic() -> None:
    assert _mint() == _mint()


def test_record_hash_golden_value() -> None:
    # 釘住已知正確雜湊(golden): 任何 preimage 鍵名 / 欄位順序 / 格式改動都會讓它變。
    # 這條同時是「跨版本相容契約」——舊鏈的雜湊未來必須仍算得出同值，否則全鏈失效。
    assert _mint() == "6dae6cc547004011b8dcad04c58fab42038007edcd599ac123afcba710770d30"


def test_hash_is_64_lowercase_hex() -> None:
    digest = _mint()
    assert len(digest) == 64
    assert digest == digest.lower()
    int(digest, 16)  # 全部是合法 hex 字元


# ============================================================================
# 敏感性: 任一輸入變，指紋必變(逐欄位參數化)
# ============================================================================


@pytest.mark.parametrize(
    "overrides",
    [
        {"prev_hash": "f" * 64},
        {"record_id": "01JXF0000000000000000000BB"},
        {"timestamp": _TS + timedelta(microseconds=1)},
        {"sequence": 2},
    ],
    ids=["prev_hash", "record_id", "timestamp", "sequence"],
)
def test_hash_changes_on_envelope_field(overrides: dict[str, object]) -> None:
    assert _mint(**overrides) != _mint()


@pytest.mark.parametrize(
    "input_overrides",
    [
        {"tenant_id": "tenant-b"},
        {"user_id": "user-2"},
        {"role": Role.AGENT},
        {"action": "order.cancel"},
        {"resource": "order/zzz"},
        {"request_payload_hash": "b" * 64},
        {"response_status": AuditOutcome.FAILED},
        {"ip_address": "10.0.0.1"},
        {"user_agent": "curl/8"},
        {"risk_score": 99},
    ],
    ids=lambda d: next(iter(d)),
)
def test_hash_changes_on_any_content_field(input_overrides: dict[str, object]) -> None:
    assert _mint(record_input=make_input(**input_overrides)) != _mint()


# ============================================================================
# 時間正規化: 不同時區的同一瞬間 → 同指紋
# ============================================================================


def test_hash_same_instant_different_timezone() -> None:
    taipei = timezone(timedelta(hours=8))
    same_instant = _TS.astimezone(taipei)
    assert _mint(timestamp=same_instant) == _mint()


# ============================================================================
# recompute_hash: 與鑄造路徑算出同指紋；改內容後必對不上
# ============================================================================


def test_recompute_matches_minted_hash() -> None:
    minted = _mint()
    record = make_record(
        record_id="01JXF0000000000000000000AA",
        timestamp=_TS,
        sequence=1,
        prev_hash=GENESIS_HASH,
        record_hash=minted,
    )
    assert recompute_hash(record) == minted == record.record_hash


def test_recompute_detects_tampered_content() -> None:
    record = make_record(
        record_id="01JXF0000000000000000000AA",
        timestamp=_TS,
        sequence=1,
        prev_hash=GENESIS_HASH,
        record_hash=_mint(),
    )
    tampered = dataclasses.replace(record, action="order.cancel")
    assert recompute_hash(tampered) != tampered.record_hash


# ============================================================================
# canonical_json: 鍵排序、緊湊、中文不逃脫、Decimal/datetime/Enum 降級
# ============================================================================


def test_canonical_json_sorts_keys_and_compact() -> None:
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_canonical_json_keeps_chinese_readable() -> None:
    assert canonical_json({"msg": "下單"}) == '{"msg":"下單"}'


def test_canonical_json_decimal_as_string_not_float() -> None:
    assert canonical_json({"qty": Decimal("0.10000000")}) == '{"qty":"0.10000000"}'


def test_canonical_json_datetime_as_utc_iso() -> None:
    taipei = timezone(timedelta(hours=8))
    value = datetime(2026, 6, 12, 18, 30, 0, tzinfo=taipei)
    assert canonical_json({"ts": value}) == '{"ts":"2026-06-12T10:30:00+00:00"}'


def test_canonical_json_enum_as_value() -> None:
    assert canonical_json({"role": Role.AGENT}) == '{"role":"agent"}'


def test_canonical_json_rejects_unknown_type() -> None:
    class Opaque:
        pass

    with pytest.raises(TypeError) as exc_info:
        canonical_json({"x": Opaque()})
    # 完全相等釘住訊息(子字串 match 殺不掉前後加料的字串 mutant，S02 教訓)
    assert str(exc_info.value) == "無法序列化進稽核雜湊的型別: Opaque"


class _IntFlavor(Enum):
    A = 7


def test_canonical_json_non_str_enum_value_coerced_to_string() -> None:
    # Enum value 非字串時也降級成字串，維持指紋穩定
    assert canonical_json({"v": _IntFlavor.A}) == '{"v":"7"}'


# ============================================================================
# hash_payload: 與 canonical_json 的關係是「先正規化再 SHA256」
# ============================================================================


def test_hash_payload_equals_sha256_of_canonical_json() -> None:
    payload = {"symbol": "2330", "qty": Decimal("100")}
    expected = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    assert hash_payload(payload) == expected


def test_hash_payload_golden_value() -> None:
    # golden: 釘住 payload 指紋演算法(裝飾器算 request_payload_hash 的對外契約)
    assert (
        hash_payload({"symbol": "2330", "qty": 100})
        == "07318d2e209dc7649cb8ce8262f4f0bb0fb1037c2fc50353c35af2b7a7f91d5e"
    )


def test_hash_payload_key_order_irrelevant() -> None:
    assert hash_payload({"a": 1, "b": 2}) == hash_payload({"b": 2, "a": 1})


def test_hash_payload_differs_on_value_change() -> None:
    assert hash_payload({"a": 1}) != hash_payload({"a": 2})
