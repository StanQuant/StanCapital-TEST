"""src/data/compliance.py 單元測試 · gate 全狀態矩陣 / 恆真 validator / 限流邊界。"""

from __future__ import annotations

import dataclasses
from datetime import UTC, date, datetime

import pytest
from src.data.compliance import (
    ActualConnectGate,
    ComplianceError,
    ComplianceGateError,
    ProviderComplianceProfile,
    RateLimitPolicy,
    RateLimitSource,
    ensure_may_actual_connect,
)


def make_policy(**overrides: object) -> RateLimitPolicy:
    values: dict[str, object] = {
        "max_concurrency": 1,
        "min_interval_ms": 1000,
        "max_requests_per_window": 60,
        "window_seconds": 60,
        "backoff_on_limit": True,
    }
    values.update(overrides)
    return RateLimitPolicy(**values)  # type: ignore[arg-type]


def make_profile(**overrides: object) -> ProviderComplianceProfile:
    values: dict[str, object] = {
        "terms_url": "https://example.com/terms",
        "terms_last_checked": date(2026, 7, 2),
        "commercial_use_allowed": True,
        "redistribution_allowed": False,
        "attribution_required": False,
        "third_party_terms_required": False,
        "rate_limit_source": RateLimitSource.OFFICIAL,
        "internal_safe_rate_limit": make_policy(),
        "sandbox_available": True,
        "sandbox_scope": "securities_only_until_confirmed",
        "testnet_endpoint_rest": "https://test.example.com/api",
        "testnet_endpoint_ws": "wss://test.example.com/ws",
        "production_endpoint_rest": "https://api.example.com",
        "production_endpoint_ws": "wss://api.example.com/ws",
        "credentials_required": True,
        "secret_provider_required": True,
        "actual_connect_gate": ActualConnectGate.MOCK_ONLY,
        "region_restrictions": ("TW",),
    }
    values.update(overrides)
    return ProviderComplianceProfile(**values)  # type: ignore[arg-type]


class TestEnums:
    def test_rate_limit_source_pinned(self) -> None:
        assert {m.name: m.value for m in RateLimitSource} == {
            "OFFICIAL": "official",
            "UNPUBLISHED": "unpublished",
            "EXCHANGE_INFO": "exchange_info",
            "ENDPOINT_DOCS": "endpoint_docs",
        }

    def test_actual_connect_gate_pinned(self) -> None:
        assert {m.name: m.value for m in ActualConnectGate} == {
            "MOCK_ONLY": "mock_only",
            "PAPER_ONLY": "paper_only",
            "CONTRACT_REVIEW_REQUIRED": "contract_review_required",
            "ACCOUNT_GATED": "account_gated",
            "READY_FOR_SANDBOX": "ready_for_sandbox",
        }

    def test_compliance_error_is_value_error(self) -> None:
        # 泛用 ValueError 處理也能接住(不破壞既有錯誤處理慣例)
        assert issubclass(ComplianceError, ValueError)


class TestRateLimitPolicy:
    def test_valid_full_and_windowless(self) -> None:
        assert make_policy().max_concurrency == 1
        windowless = make_policy(max_requests_per_window=None, window_seconds=None)
        assert windowless.max_requests_per_window is None

    @pytest.mark.parametrize("bad", [0, -1])
    def test_non_positive_concurrency_rejected(self, bad: int) -> None:
        with pytest.raises(ComplianceError) as exc:
            make_policy(max_concurrency=bad)
        assert str(exc.value) == f"max_concurrency 必須 >= 1：{bad}"

    def test_bool_concurrency_rejected(self) -> None:
        with pytest.raises(ComplianceError) as exc:
            make_policy(max_concurrency=True)
        assert str(exc.value) == "max_concurrency 必須是正整數，不可為 bool"

    def test_negative_interval_rejected(self) -> None:
        with pytest.raises(ComplianceError) as exc:
            make_policy(min_interval_ms=-1)
        assert str(exc.value) == "min_interval_ms 不可為負：-1"

    def test_bool_interval_rejected(self) -> None:
        with pytest.raises(ComplianceError) as exc:
            make_policy(min_interval_ms=False)
        assert str(exc.value) == "min_interval_ms 必須是非負整數，不可為 bool"

    def test_zero_interval_allowed(self) -> None:
        assert make_policy(min_interval_ms=0).min_interval_ms == 0

    @pytest.mark.parametrize(
        ("requests", "window"),
        [(60, None), (None, 60)],
    )
    def test_unpaired_window_rejected(self, requests: int | None, window: int | None) -> None:
        with pytest.raises(ComplianceError) as exc:
            make_policy(max_requests_per_window=requests, window_seconds=window)
        assert str(exc.value).startswith("max_requests_per_window 與 window_seconds 必須成對")

    def test_zero_window_fields_rejected(self) -> None:
        with pytest.raises(ComplianceError):
            make_policy(max_requests_per_window=0, window_seconds=60)
        with pytest.raises(ComplianceError):
            make_policy(max_requests_per_window=60, window_seconds=0)


class TestProviderComplianceProfile:
    def test_schema_fields_pinned(self) -> None:
        # 藍圖 §13.5 全欄位(D8)；S15/S28 直接沿用，動欄位前先 rg 構造點
        assert [f.name for f in dataclasses.fields(ProviderComplianceProfile)] == [
            "terms_url",
            "terms_last_checked",
            "commercial_use_allowed",
            "redistribution_allowed",
            "attribution_required",
            "third_party_terms_required",
            "rate_limit_source",
            "internal_safe_rate_limit",
            "sandbox_available",
            "sandbox_scope",
            "testnet_endpoint_rest",
            "testnet_endpoint_ws",
            "production_endpoint_rest",
            "production_endpoint_ws",
            "credentials_required",
            "secret_provider_required",
            "actual_connect_gate",
            "region_restrictions",
        ]

    def test_valid(self) -> None:
        assert make_profile().actual_connect_gate is ActualConnectGate.MOCK_ONLY

    def test_bad_terms_url_rejected(self) -> None:
        with pytest.raises(ComplianceError) as exc:
            make_profile(terms_url="example.com/terms")
        assert str(exc.value).startswith("terms_url 必須以 http:// 或 https:// 開頭")

    def test_datetime_terms_last_checked_rejected(self) -> None:
        with pytest.raises(ComplianceError) as exc:
            make_profile(terms_last_checked=datetime(2026, 7, 2, tzinfo=UTC))
        assert str(exc.value) == "terms_last_checked 必須是 date(不可為 datetime)"

    def test_secret_provider_required_false_rejected(self) -> None:
        # 鐵律：恆為 True，沒有合法的 False(規格 §12.2)
        with pytest.raises(ComplianceError) as exc:
            make_profile(secret_provider_required=False)
        assert str(exc.value).startswith("secret_provider_required 恆為 True")

    def test_sandbox_scope_without_sandbox_rejected(self) -> None:
        with pytest.raises(ComplianceError) as exc:
            make_profile(sandbox_available=False, sandbox_scope="whatever")
        assert str(exc.value).startswith("sandbox_scope 已填但 sandbox_available=False")

    def test_empty_sandbox_scope_rejected(self) -> None:
        with pytest.raises(ValueError):
            make_profile(sandbox_scope="")

    def test_sandbox_without_scope_allowed(self) -> None:
        profile = make_profile(sandbox_scope=None)
        assert profile.sandbox_scope is None

    def test_no_sandbox_no_scope_allowed(self) -> None:
        profile = make_profile(sandbox_available=False, sandbox_scope=None)
        assert profile.sandbox_available is False

    @pytest.mark.parametrize("field_name", ["testnet_endpoint_rest", "production_endpoint_rest"])
    def test_bad_rest_endpoint_rejected(self, field_name: str) -> None:
        with pytest.raises(ComplianceError) as exc:
            make_profile(**{field_name: "wss://wrong.example.com"})
        assert str(exc.value).startswith(f"{field_name} 必須以 http:// 或 https:// 開頭")

    @pytest.mark.parametrize("field_name", ["testnet_endpoint_ws", "production_endpoint_ws"])
    def test_bad_ws_endpoint_rejected(self, field_name: str) -> None:
        with pytest.raises(ComplianceError) as exc:
            make_profile(**{field_name: "https://wrong.example.com"})
        assert str(exc.value).startswith(f"{field_name} 必須以 ws:// 或 wss:// 開頭")

    def test_all_endpoints_optional(self) -> None:
        profile = make_profile(
            testnet_endpoint_rest=None,
            testnet_endpoint_ws=None,
            production_endpoint_rest=None,
            production_endpoint_ws=None,
        )
        assert profile.testnet_endpoint_ws is None

    def test_empty_region_element_rejected(self) -> None:
        with pytest.raises(ComplianceError) as exc:
            make_profile(region_restrictions=("",))
        assert str(exc.value) == "region_restrictions 元素不可為空字串"

    def test_empty_region_tuple_allowed(self) -> None:
        assert make_profile(region_restrictions=()).region_restrictions == ()

    def test_frozen_and_slots(self) -> None:
        profile = make_profile()
        with pytest.raises(dataclasses.FrozenInstanceError):
            profile.terms_url = "https://other.example.com"  # type: ignore[misc]
        assert not hasattr(profile, "__dict__")
        policy = make_policy()
        with pytest.raises(dataclasses.FrozenInstanceError):
            policy.max_concurrency = 99  # type: ignore[misc]
        assert not hasattr(policy, "__dict__")


class TestActualConnectGateBehavior:
    @pytest.mark.parametrize(
        ("gate", "expected"),
        [
            (ActualConnectGate.MOCK_ONLY, False),
            (ActualConnectGate.PAPER_ONLY, False),
            (ActualConnectGate.CONTRACT_REVIEW_REQUIRED, False),
            (ActualConnectGate.ACCOUNT_GATED, False),
            (ActualConnectGate.READY_FOR_SANDBOX, True),
        ],
    )
    def test_may_actual_connect_matrix(self, gate: ActualConnectGate, expected: bool) -> None:
        # 白名單思維：只有 READY_FOR_SANDBOX 可無條件真連線
        assert make_profile(actual_connect_gate=gate).may_actual_connect() is expected

    def test_ready_for_sandbox_passes(self) -> None:
        profile = make_profile(actual_connect_gate=ActualConnectGate.READY_FOR_SANDBOX)
        ensure_may_actual_connect(profile, "p1")  # 不拋錯即通過

    @pytest.mark.parametrize(
        "gate",
        [
            ActualConnectGate.MOCK_ONLY,
            ActualConnectGate.PAPER_ONLY,
            ActualConnectGate.CONTRACT_REVIEW_REQUIRED,
            ActualConnectGate.ACCOUNT_GATED,
        ],
    )
    def test_non_ready_gates_blocked_by_default(self, gate: ActualConnectGate) -> None:
        profile = make_profile(actual_connect_gate=gate)
        with pytest.raises(ComplianceGateError) as exc:
            ensure_may_actual_connect(profile, "p1")
        assert str(exc.value).startswith(f"provider 'p1' 的 actual-connect gate 為 {gate.value}")

    def test_account_gated_unlocked_only_with_approval(self) -> None:
        profile = make_profile(actual_connect_gate=ActualConnectGate.ACCOUNT_GATED)
        ensure_may_actual_connect(profile, "p1", account_gated_approved=True)  # 三條件成立才傳 True

    @pytest.mark.parametrize(
        "gate",
        [
            ActualConnectGate.MOCK_ONLY,
            ActualConnectGate.PAPER_ONLY,
            ActualConnectGate.CONTRACT_REVIEW_REQUIRED,
        ],
    )
    def test_approval_flag_cannot_unlock_other_gates(self, gate: ActualConnectGate) -> None:
        # approved 旗標只對 ACCOUNT_GATED 有意義；不能拿來偷渡 MOCK_ONLY 等
        profile = make_profile(actual_connect_gate=gate)
        with pytest.raises(ComplianceGateError):
            ensure_may_actual_connect(profile, "p1", account_gated_approved=True)
