"""L2 ProviderRegistry 雛形 · 無合規側寫不得註冊、未註冊不得被呼叫。

完整版(能力查詢 / 授權查詢 / region gate / 品質分級)在 S15/S30(B-119)；
本切片只立接口與最小行為，欄位設計預留擴充。

雙層防護(規格 §12.2)：
1. 無 ProviderComplianceProfile → 註冊直接拒絕(fail-closed)。
2. 未註冊的 provider → bridge / consumer 呼叫前 ensure_registered 必炸。
"""

from __future__ import annotations

from src.data.compliance import ProviderComplianceProfile
from src.data.provider import MarketDataProvider, ProviderCapabilities
from src.data.types import AssetClass


class RegistryError(Exception):
    """註冊 / 查詢失敗(fail-closed：查無不回 None，一律拋錯)。"""


class ProviderRegistry:
    """provider 名冊 · v0 in-memory 單執行緒(asyncio)版本。"""

    def __init__(self) -> None:
        self._providers: dict[str, MarketDataProvider] = {}

    def register(self, provider: MarketDataProvider) -> None:
        """註冊 provider。無合規側寫 / 能力宣告 / 重複 id 一律拒絕。"""
        provider_id = provider.provider_id
        if not isinstance(provider_id, str) or not provider_id:
            raise RegistryError("provider_id 必須是非空字串，拒絕註冊")
        profile = provider.compliance_profile()
        if not isinstance(profile, ProviderComplianceProfile):
            raise RegistryError(
                f"provider {provider_id!r} 沒有合法的 ProviderComplianceProfile，"
                "拒絕註冊(fail-closed；條款/限流/憑證不明的來源不得進名冊)"
            )
        capabilities = provider.capabilities()
        if not isinstance(capabilities, ProviderCapabilities):
            raise RegistryError(
                f"provider {provider_id!r} 沒有合法的 ProviderCapabilities，拒絕註冊"
            )
        if provider_id in self._providers:
            raise RegistryError(f"provider_id {provider_id!r} 已註冊，拒絕重複註冊")
        self._providers[provider_id] = provider

    def get(self, provider_id: str) -> MarketDataProvider:
        """取得已註冊 provider。查無直接拋錯，不回 None(呼叫端不必猜)。"""
        try:
            return self._providers[provider_id]
        except KeyError:
            raise RegistryError(f"provider_id {provider_id!r} 未註冊") from None

    def ensure_registered(self, provider_id: str) -> None:
        """bridge / consumer 呼叫 provider 前的守門：未註冊直接炸。"""
        if provider_id not in self._providers:
            raise RegistryError(
                f"provider_id {provider_id!r} 未註冊，不得被呼叫(先 register 過雙層防護)"
            )

    def list_by_asset_class(self, asset_class: AssetClass) -> tuple[MarketDataProvider, ...]:
        """列出宣告支援某資產類別的 providers(依註冊順序)。"""
        if not isinstance(asset_class, AssetClass):
            raise RegistryError(
                f"asset_class 必須是 AssetClass，不可為 {type(asset_class).__name__}"
            )
        return tuple(
            provider
            for provider in self._providers.values()
            if asset_class in provider.capabilities().asset_classes
        )

    def registered_ids(self) -> tuple[str, ...]:
        """已註冊的 provider_id 清單(依註冊順序；除錯 / 遙測用)。"""
        return tuple(self._providers)
