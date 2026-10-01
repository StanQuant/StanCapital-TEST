"""L2 來源合規側寫 · ProviderComplianceProfile / ActualConnectGate / RateLimitPolicy。

法遵紅線落地(規格 §12-§13、藍圖 §13.5、B-116)：
- 條款 / 限流 / 憑證流程不明的來源一律停在 MOCK_ONLY，fail-closed。
- secret_provider_required 恆為 True：任何 profile 試圖設 False 直接被 validator 拒絕
  (憑證只有 S10 SecretProvider 一條路，沒有第二條)。
- region_restrictions 第一天就進 schema(台灣 VASP 法遵硬需求；強制邏輯屬 S28)。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import StrEnum

from src.core.validation import ensure_non_empty
from src.data.types import _ensure_http_url  # 同 package 內共用私有驗證


class ComplianceError(ValueError):
    """合規側寫本身的資料錯誤(建構期驗證失敗)。"""


class ComplianceGateError(Exception):
    """actual-connect gate 擋下的連線嘗試(執行期 fail-closed)。"""


class RateLimitSource(StrEnum):
    """限流資訊的出處 · 決定 internal_safe_rate_limit 的可信度。"""

    OFFICIAL = "official"  # 官方文件明載
    UNPUBLISHED = "unpublished"  # 未公開 → 必須配保守自我節流
    EXCHANGE_INFO = "exchange_info"  # 交易所 API 可查(如 Binance exchangeInfo)
    ENDPOINT_DOCS = "endpoint_docs"  # 端點文件記載


class ActualConnectGate(StrEnum):
    """真連線關卡 · 預設 MOCK_ONLY，逐級解鎖(規格 §12.2)。"""

    MOCK_ONLY = "mock_only"  # 預設；條款/限流/憑證不明一律停這
    PAPER_ONLY = "paper_only"  # 資料可研究、真錢路徑不存在(B-116)
    CONTRACT_REVIEW_REQUIRED = "contract_review_required"  # 商業條款待審
    ACCOUNT_GATED = "account_gated"  # 需 Stanley 帳號 + 明確同意
    READY_FOR_SANDBOX = "ready_for_sandbox"  # 可連 sandbox / 本地資料


# 允許真連線的 gate(白名單思維：不在清單內＝一律擋下)
_CONNECTABLE_GATES = frozenset({ActualConnectGate.READY_FOR_SANDBOX})


def _ensure_ws_url(name: str, value: str) -> None:
    """WebSocket 端點必須以 ws:// 或 wss:// 開頭。"""
    ensure_non_empty(name, value)
    if not (value.startswith("wss://") or value.startswith("ws://")):
        raise ComplianceError(f"{name} 必須以 ws:// 或 wss:// 開頭：{value!r}")


def _ensure_gate_count(name: str, value: int) -> None:
    """限流計數必須是正整數(bool 不算)。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ComplianceError(f"{name} 必須是正整數，不可為 {type(value).__name__}")
    if value < 1:
        raise ComplianceError(f"{name} 必須 >= 1：{value}")


@dataclass(frozen=True, slots=True)
class RateLimitPolicy:
    """內部保守節流閥 · 官方未公開限流時的自我保護(規格 §12.1)。

    超限一律退避不硬打(Binance 418 封 IP 前例)；backoff_on_limit=False 只允許
    本地來源(replay)使用。
    """

    max_concurrency: int  # 例：TPEx/TAIFEX 保守閥 = 1
    min_interval_ms: int  # 例：1000-3000
    max_requests_per_window: int | None
    window_seconds: int | None
    backoff_on_limit: bool

    def __post_init__(self) -> None:
        _ensure_gate_count("max_concurrency", self.max_concurrency)
        if isinstance(self.min_interval_ms, bool) or not isinstance(self.min_interval_ms, int):
            raise ComplianceError(
                f"min_interval_ms 必須是非負整數，不可為 {type(self.min_interval_ms).__name__}"
            )
        if self.min_interval_ms < 0:
            raise ComplianceError(f"min_interval_ms 不可為負：{self.min_interval_ms}")
        # 視窗兩欄位必須成對出現：只給一半的限流宣告是無法執行的假保護
        if (self.max_requests_per_window is None) != (self.window_seconds is None):
            raise ComplianceError(
                "max_requests_per_window 與 window_seconds 必須成對(同時給或同時 None)"
            )
        if self.max_requests_per_window is not None:
            _ensure_gate_count("max_requests_per_window", self.max_requests_per_window)
        if self.window_seconds is not None:
            _ensure_gate_count("window_seconds", self.window_seconds)


@dataclass(frozen=True, slots=True)
class ProviderComplianceProfile:
    """來源合規側寫 · 藍圖 §13.5 全欄位(D8)。

    每個來源的查證結論有結構化落點；S15 DataLicenseRegistry / S28 gate
    直接沿用不改 schema。
    """

    terms_url: str
    terms_last_checked: date  # 例：2026-07-02
    commercial_use_allowed: bool
    redistribution_allowed: bool  # Polygon/Massive 類預設 False
    attribution_required: bool  # GDELT 類為 True
    third_party_terms_required: bool  # 背後交易所條款另行約束
    rate_limit_source: RateLimitSource
    internal_safe_rate_limit: RateLimitPolicy  # 官方未公開時的自我保護閥
    sandbox_available: bool
    sandbox_scope: str | None
    testnet_endpoint_rest: str | None
    testnet_endpoint_ws: str | None
    production_endpoint_rest: str | None
    production_endpoint_ws: str | None
    credentials_required: bool
    secret_provider_required: bool  # 恆為 True，validator 強制
    actual_connect_gate: ActualConnectGate
    region_restrictions: tuple[str, ...]  # B-116 region gate 預留

    def __post_init__(self) -> None:
        try:
            _ensure_http_url("terms_url", self.terms_url)
        except ValueError as exc:
            raise ComplianceError(str(exc)) from exc
        # datetime 是 date 子類；查證日是日曆日概念，混入時分秒＝時區歧義
        if type(self.terms_last_checked) is not date:
            raise ComplianceError(
                f"terms_last_checked 必須是 date(不可為 {type(self.terms_last_checked).__name__})"
            )
        # 鐵律：憑證只走 S10 SecretProvider，本欄位不存在合法的 False
        if self.secret_provider_required is not True:
            raise ComplianceError(
                "secret_provider_required 恆為 True：憑證只走 S10 SecretProvider，"
                "任何 profile 不得繞過"
            )
        if self.sandbox_scope is not None:
            if not self.sandbox_available:
                raise ComplianceError("sandbox_scope 已填但 sandbox_available=False：側寫自相矛盾")
            ensure_non_empty("sandbox_scope", self.sandbox_scope)
        for field_name in ("testnet_endpoint_rest", "production_endpoint_rest"):
            value = getattr(self, field_name)
            if value is not None:
                try:
                    _ensure_http_url(field_name, value)
                except ValueError as exc:
                    raise ComplianceError(str(exc)) from exc
        for field_name in ("testnet_endpoint_ws", "production_endpoint_ws"):
            value = getattr(self, field_name)
            if value is not None:
                _ensure_ws_url(field_name, value)
        for region in self.region_restrictions:
            if not region:
                raise ComplianceError("region_restrictions 元素不可為空字串")

    def may_actual_connect(self) -> bool:
        """本側寫是否允許無條件真連線(白名單，只有 READY_FOR_SANDBOX)。"""
        return self.actual_connect_gate in _CONNECTABLE_GATES


def ensure_may_actual_connect(
    profile: ProviderComplianceProfile,
    provider_id: str,
    *,
    account_gated_approved: bool = False,
) -> None:
    """connect() 前的 gate 檢查(規格 §12.2，fail-closed)。

    account_gated_approved 預設 False：ACCOUNT_GATED 來源必須由呼叫端在
    「測試標記 opt-in + 憑證已在 S10 vault + Stanley 明確同意」三條件都成立時
    才傳 True；其餘 gate 一律拒絕真連線。
    """
    gate = profile.actual_connect_gate
    if profile.may_actual_connect():
        return
    if gate is ActualConnectGate.ACCOUNT_GATED and account_gated_approved:
        return
    raise ComplianceGateError(
        f"provider {provider_id!r} 的 actual-connect gate 為 {gate.value}，"
        "不允許真連線(fail-closed；解鎖條件見規格 §12.2)"
    )


def v0_profile_ledger() -> dict[str, ProviderComplianceProfile]:
    """§12.3 v0 來源登記表 · 外部來源(本切片只登記、不實接)。

    附錄 A / 官方文件查證結論的結構化落點(查證日 2026-07-02)：
    - 台灣官方 OpenAPI 三來源：限流未公開 → MOCK_ONLY + 保守閥(單線、
      間隔 >= 1 秒、退避)，只走官方端點、不爬蟲(紅線 §13-3)。
    - polygon-massive：商用需商業條款 → CONTRACT_REVIEW_REQUIRED；
      redistribution 預設禁止、背後交易所條款另行約束、WS 同 asset class 1 條。
    - gdelt：attribution 必須；全文不落地(schema 層已無全文欄位，D10)。
    - crypto testnet 四所(D11 優先順序：binance → okx → bybit → deribit)：
      只驗 connector contract、不作績效證明；台灣 VASP 法遵 → region 標 TW。
    - prediction market 兩所：PAPER_ONLY，真錢路徑不存在(B-116/D12)。

    條款連結 v0 記到官方網域層級；逐條授權細節於實接切片再查證更新。
    aggregator 與 broker 的側寫隨其 adapter 實作存放(核心模組不含供應商名稱)。
    """
    checked = date(2026, 7, 2)
    conservative = RateLimitPolicy(
        max_concurrency=1,
        min_interval_ms=1000,
        max_requests_per_window=None,
        window_seconds=None,
        backoff_on_limit=True,
    )

    def entry(
        *,
        terms_url: str,
        gate: ActualConnectGate,
        commercial: bool = False,
        redistribution: bool = False,
        attribution: bool = False,
        third_party: bool = False,
        rate_source: RateLimitSource = RateLimitSource.UNPUBLISHED,
        rate_limit: RateLimitPolicy = conservative,
        credentials: bool = True,
        production_rest: str | None = None,
        testnet_rest: str | None = None,
        regions: tuple[str, ...] = (),
    ) -> ProviderComplianceProfile:
        return ProviderComplianceProfile(
            terms_url=terms_url,
            terms_last_checked=checked,
            commercial_use_allowed=commercial,
            redistribution_allowed=redistribution,
            attribution_required=attribution,
            third_party_terms_required=third_party,
            rate_limit_source=rate_source,
            internal_safe_rate_limit=rate_limit,
            sandbox_available=testnet_rest is not None,
            sandbox_scope="connector_contract_only" if testnet_rest is not None else None,
            testnet_endpoint_rest=testnet_rest,
            testnet_endpoint_ws=None,
            production_endpoint_rest=production_rest,
            production_endpoint_ws=None,
            credentials_required=credentials,
            secret_provider_required=True,
            actual_connect_gate=gate,
            region_restrictions=regions,
        )

    return {
        # 台灣官方 OpenAPI(政府資料開放授權：可用需標示來源)
        "twse-openapi": entry(
            terms_url="https://openapi.twse.com.tw/",
            gate=ActualConnectGate.MOCK_ONLY,
            commercial=True,
            attribution=True,
            credentials=False,
            production_rest="https://openapi.twse.com.tw",
        ),
        "tpex-openapi": entry(
            terms_url="https://www.tpex.org.tw/openapi/",
            gate=ActualConnectGate.MOCK_ONLY,
            commercial=True,
            attribution=True,
            credentials=False,
            production_rest="https://www.tpex.org.tw/openapi",
        ),
        "taifex-openapi": entry(
            terms_url="https://openapi.taifex.com.tw/",
            gate=ActualConnectGate.MOCK_ONLY,
            commercial=True,
            attribution=True,
            credentials=False,
            production_rest="https://openapi.taifex.com.tw",
        ),
        # 美股 aggregator：商業條款未簽 → 一律不得實接
        "polygon-massive": entry(
            terms_url="https://polygon.io/terms",
            gate=ActualConnectGate.CONTRACT_REVIEW_REQUIRED,
            third_party=True,
            rate_source=RateLimitSource.ENDPOINT_DOCS,
            production_rest="https://api.polygon.io",
        ),
        # 新聞/輿情(D10：attribution 必填、schema 無全文欄位)
        "gdelt": entry(
            terms_url="https://www.gdeltproject.org/about.html",
            gate=ActualConnectGate.MOCK_ONLY,
            commercial=True,
            attribution=True,
            credentials=False,
            production_rest="https://api.gdeltproject.org",
        ),
        # crypto testnet(D11 優先順序即下列排序；VASP → region 標 TW)
        "binance-spot-testnet": entry(
            terms_url="https://www.binance.com/en/terms",
            gate=ActualConnectGate.MOCK_ONLY,
            rate_source=RateLimitSource.EXCHANGE_INFO,
            testnet_rest="https://testnet.binance.vision",
            regions=("TW",),
        ),
        "okx-demo": entry(
            terms_url="https://www.okx.com/",
            gate=ActualConnectGate.MOCK_ONLY,
            rate_source=RateLimitSource.ENDPOINT_DOCS,
            regions=("TW",),
        ),
        "bybit-demo": entry(
            terms_url="https://www.bybit.com/",
            gate=ActualConnectGate.MOCK_ONLY,
            rate_source=RateLimitSource.ENDPOINT_DOCS,
            regions=("TW",),
        ),
        "deribit-test": entry(
            terms_url="https://www.deribit.com/",
            gate=ActualConnectGate.MOCK_ONLY,
            rate_source=RateLimitSource.ENDPOINT_DOCS,
            regions=("TW",),
        ),
        # prediction market(B-116/D12：paper-only、真錢路徑不存在)
        "polymarket": entry(
            terms_url="https://polymarket.com/",
            gate=ActualConnectGate.PAPER_ONLY,
            credentials=False,
            regions=("US", "UK", "DE", "FR", "AU", "IT", "NL"),
        ),
        "kalshi": entry(
            terms_url="https://kalshi.com/",
            gate=ActualConnectGate.PAPER_ONLY,
            regions=("US",),
        ),
    }
