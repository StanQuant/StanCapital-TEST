"""§12.3 v0 profile 登記表測試 · gate 全表釘住 + 法遵紅線落實。"""

from __future__ import annotations

import pytest
from src.data.compliance import ActualConnectGate, v0_profile_ledger
from src.data.replay.provider import replay_compliance_profile


class TestLedger:
    def test_gate_table_pinned(self) -> None:
        # §12.3 登記表(外部來源部分)：gate 全表相等釘住
        ledger = v0_profile_ledger()
        assert {pid: p.actual_connect_gate for pid, p in ledger.items()} == {
            "twse-openapi": ActualConnectGate.MOCK_ONLY,
            "tpex-openapi": ActualConnectGate.MOCK_ONLY,
            "taifex-openapi": ActualConnectGate.MOCK_ONLY,
            "polygon-massive": ActualConnectGate.CONTRACT_REVIEW_REQUIRED,
            "gdelt": ActualConnectGate.MOCK_ONLY,
            "binance-spot-testnet": ActualConnectGate.MOCK_ONLY,
            "okx-demo": ActualConnectGate.MOCK_ONLY,
            "bybit-demo": ActualConnectGate.MOCK_ONLY,
            "deribit-test": ActualConnectGate.MOCK_ONLY,
            "polymarket": ActualConnectGate.PAPER_ONLY,
            "kalshi": ActualConnectGate.PAPER_ONLY,
        }

    def test_full_table_with_adapter_profiles(self) -> None:
        # 完整表 = 登記表 + 隨實作存放的側寫(紅線：核心不含供應商名稱)
        full = dict(v0_profile_ledger())
        full["replay"] = replay_compliance_profile()
        assert full["replay"].actual_connect_gate is ActualConnectGate.READY_FOR_SANDBOX
        assert len(full) == 12

    def test_no_ledger_entry_may_actual_connect(self) -> None:
        # 外部來源 v0 全部不得無條件真連線(fail-closed)
        for provider_id, profile in v0_profile_ledger().items():
            assert profile.may_actual_connect() is False, provider_id

    @pytest.mark.parametrize(
        "crypto_id", ["binance-spot-testnet", "okx-demo", "bybit-demo", "deribit-test"]
    )
    def test_vasp_region_gate_on_crypto(self, crypto_id: str) -> None:
        # 台灣 VASP 法遵：crypto venue 第一天就標 region(紅線 §13-8)
        assert v0_profile_ledger()[crypto_id].region_restrictions == ("TW",)

    def test_polygon_conservatism(self) -> None:
        profile = v0_profile_ledger()["polygon-massive"]
        assert profile.commercial_use_allowed is False  # 商業條款未簽
        assert profile.redistribution_allowed is False  # 不轉售不再分發
        assert profile.third_party_terms_required is True  # 交易所條款另行約束
        assert profile.internal_safe_rate_limit.max_concurrency == 1  # 同 asset class 1 條

    def test_gdelt_attribution_required(self) -> None:
        assert v0_profile_ledger()["gdelt"].attribution_required is True

    def test_tw_official_sources_throttled_conservatively(self) -> None:
        # 限流未公開 → 單線 + 間隔 >= 1 秒 + 退避(紅線 §13-3，不爬蟲)
        for provider_id in ("twse-openapi", "tpex-openapi", "taifex-openapi"):
            policy = v0_profile_ledger()[provider_id].internal_safe_rate_limit
            assert policy.max_concurrency == 1, provider_id
            assert policy.min_interval_ms == 1000, provider_id
            assert policy.backoff_on_limit is True, provider_id

    def test_prediction_markets_are_paper_only_with_regions(self) -> None:
        ledger = v0_profile_ledger()
        assert ledger["polymarket"].region_restrictions == (
            "US",
            "UK",
            "DE",
            "FR",
            "AU",
            "IT",
            "NL",
        )
        assert ledger["kalshi"].region_restrictions == ("US",)

    def test_all_secret_provider_required(self) -> None:
        for provider_id, profile in v0_profile_ledger().items():
            assert profile.secret_provider_required is True, provider_id

    def test_terms_urls_pinned(self) -> None:
        # 條款連結是查證結論的一部分：全表相等釘住(打錯字＝合規紀錄錯誤)
        assert {pid: p.terms_url for pid, p in v0_profile_ledger().items()} == {
            "twse-openapi": "https://openapi.twse.com.tw/",
            "tpex-openapi": "https://www.tpex.org.tw/openapi/",
            "taifex-openapi": "https://openapi.taifex.com.tw/",
            "polygon-massive": "https://polygon.io/terms",
            "gdelt": "https://www.gdeltproject.org/about.html",
            "binance-spot-testnet": "https://www.binance.com/en/terms",
            "okx-demo": "https://www.okx.com/",
            "bybit-demo": "https://www.bybit.com/",
            "deribit-test": "https://www.deribit.com/",
            "polymarket": "https://polymarket.com/",
            "kalshi": "https://kalshi.com/",
        }

    def test_endpoints_pinned(self) -> None:
        ledger = v0_profile_ledger()
        assert {
            pid: (p.production_endpoint_rest, p.testnet_endpoint_rest) for pid, p in ledger.items()
        } == {
            "twse-openapi": ("https://openapi.twse.com.tw", None),
            "tpex-openapi": ("https://www.tpex.org.tw/openapi", None),
            "taifex-openapi": ("https://openapi.taifex.com.tw", None),
            "polygon-massive": ("https://api.polygon.io", None),
            "gdelt": ("https://api.gdeltproject.org", None),
            "binance-spot-testnet": (None, "https://testnet.binance.vision"),
            "okx-demo": (None, None),  # 未逐一查證的端點留 None，不猜
            "bybit-demo": (None, None),
            "deribit-test": (None, None),
            "polymarket": (None, None),
            "kalshi": (None, None),
        }

    def test_verification_metadata_pinned(self) -> None:
        from datetime import date

        from src.data.compliance import RateLimitSource

        ledger = v0_profile_ledger()
        for provider_id, profile in ledger.items():
            assert profile.terms_last_checked == date(2026, 7, 2), provider_id
        assert {pid: p.rate_limit_source for pid, p in ledger.items()} == {
            "twse-openapi": RateLimitSource.UNPUBLISHED,
            "tpex-openapi": RateLimitSource.UNPUBLISHED,
            "taifex-openapi": RateLimitSource.UNPUBLISHED,
            "polygon-massive": RateLimitSource.ENDPOINT_DOCS,
            "gdelt": RateLimitSource.UNPUBLISHED,
            "binance-spot-testnet": RateLimitSource.EXCHANGE_INFO,
            "okx-demo": RateLimitSource.ENDPOINT_DOCS,
            "bybit-demo": RateLimitSource.ENDPOINT_DOCS,
            "deribit-test": RateLimitSource.ENDPOINT_DOCS,
            "polymarket": RateLimitSource.UNPUBLISHED,
            "kalshi": RateLimitSource.UNPUBLISHED,
        }

    def test_credentials_flags_pinned(self) -> None:
        assert {pid: p.credentials_required for pid, p in v0_profile_ledger().items()} == {
            "twse-openapi": False,
            "tpex-openapi": False,
            "taifex-openapi": False,
            "polygon-massive": True,
            "gdelt": False,
            "binance-spot-testnet": True,
            "okx-demo": True,
            "bybit-demo": True,
            "deribit-test": True,
            "polymarket": False,
            "kalshi": True,
        }
