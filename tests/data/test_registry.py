"""src/data/registry.py 單元測試 · 雙層防護(無側寫拒註冊、未註冊拒呼叫)。"""

from __future__ import annotations

import pytest
from src.data.registry import ProviderRegistry, RegistryError
from src.data.types import AssetClass

from tests.data.test_compliance_gate import make_profile
from tests.data.test_provider_capabilities import make_capabilities


class FakeProvider:
    """最小可註冊 provider(只實作 Registry 會碰到的介面)。"""

    def __init__(
        self,
        provider_id: str = "fake-1",
        *,
        profile: object | None = None,
        capabilities: object | None = None,
        asset_classes: frozenset[AssetClass] | None = None,
    ) -> None:
        self._provider_id = provider_id
        self._profile = profile if profile is not None else make_profile()
        if capabilities is not None:
            self._capabilities = capabilities
        elif asset_classes is not None:
            self._capabilities = make_capabilities(asset_classes=asset_classes)
        else:
            self._capabilities = make_capabilities()

    @property
    def provider_id(self) -> str:
        return self._provider_id  # type: ignore[return-value]

    @property
    def tenant_id(self) -> str:
        return "acme"

    def capabilities(self) -> object:
        return self._capabilities

    def compliance_profile(self) -> object:
        return self._profile


class TestRegister:
    def test_register_and_get_roundtrip(self) -> None:
        registry = ProviderRegistry()
        provider = FakeProvider()
        registry.register(provider)  # type: ignore[arg-type]
        assert registry.get("fake-1") is provider

    def test_missing_profile_rejected(self) -> None:
        # 雙層防護第 1 層：無合規側寫不得註冊(規格 §7 / §12.2)
        registry = ProviderRegistry()
        with pytest.raises(RegistryError) as exc:
            registry.register(FakeProvider(profile="not-a-profile"))  # type: ignore[arg-type]
        assert str(exc.value).startswith("provider 'fake-1' 沒有合法的 ProviderComplianceProfile")

    def test_missing_capabilities_rejected(self) -> None:
        registry = ProviderRegistry()
        with pytest.raises(RegistryError) as exc:
            registry.register(FakeProvider(capabilities="nope"))  # type: ignore[arg-type]
        assert str(exc.value) == "provider 'fake-1' 沒有合法的 ProviderCapabilities，拒絕註冊"

    @pytest.mark.parametrize("bad_id", ["", None, 123])
    def test_bad_provider_id_rejected(self, bad_id: object) -> None:
        registry = ProviderRegistry()
        with pytest.raises(RegistryError) as exc:
            registry.register(FakeProvider(bad_id))  # type: ignore[arg-type]
        assert str(exc.value) == "provider_id 必須是非空字串，拒絕註冊"

    def test_duplicate_id_rejected(self) -> None:
        registry = ProviderRegistry()
        registry.register(FakeProvider())  # type: ignore[arg-type]
        with pytest.raises(RegistryError) as exc:
            registry.register(FakeProvider())  # type: ignore[arg-type]
        assert str(exc.value) == "provider_id 'fake-1' 已註冊，拒絕重複註冊"


class TestLookup:
    def test_get_unknown_raises(self) -> None:
        # fail-closed：查無不回 None，一律拋錯
        with pytest.raises(RegistryError) as exc:
            ProviderRegistry().get("ghost")
        assert str(exc.value) == "provider_id 'ghost' 未註冊"

    def test_ensure_registered_passes_for_known(self) -> None:
        registry = ProviderRegistry()
        registry.register(FakeProvider())  # type: ignore[arg-type]
        registry.ensure_registered("fake-1")  # 不拋錯即通過

    def test_ensure_registered_raises_for_unknown(self) -> None:
        # 雙層防護第 2 層：未註冊不得被呼叫
        with pytest.raises(RegistryError) as exc:
            ProviderRegistry().ensure_registered("ghost")
        assert str(exc.value).startswith("provider_id 'ghost' 未註冊，不得被呼叫")

    def test_list_by_asset_class_filters_and_preserves_order(self) -> None:
        registry = ProviderRegistry()
        tw_a = FakeProvider("tw-a", asset_classes=frozenset({AssetClass.TW_STOCK}))
        us_b = FakeProvider("us-b", asset_classes=frozenset({AssetClass.US_STOCK}))
        both_c = FakeProvider(
            "both-c", asset_classes=frozenset({AssetClass.TW_STOCK, AssetClass.US_STOCK})
        )
        for provider in (tw_a, us_b, both_c):
            registry.register(provider)  # type: ignore[arg-type]
        assert registry.list_by_asset_class(AssetClass.TW_STOCK) == (tw_a, both_c)
        assert registry.list_by_asset_class(AssetClass.US_STOCK) == (us_b, both_c)
        assert registry.list_by_asset_class(AssetClass.CRYPTO_SPOT) == ()

    def test_list_by_asset_class_rejects_wrong_type(self) -> None:
        with pytest.raises(RegistryError) as exc:
            ProviderRegistry().list_by_asset_class("tw_stock")  # type: ignore[arg-type]
        assert str(exc.value) == "asset_class 必須是 AssetClass，不可為 str"

    def test_registered_ids_in_order(self) -> None:
        registry = ProviderRegistry()
        registry.register(FakeProvider("p-1"))  # type: ignore[arg-type]
        registry.register(FakeProvider("p-2"))  # type: ignore[arg-type]
        assert registry.registered_ids() == ("p-1", "p-2")
