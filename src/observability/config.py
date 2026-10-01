"""S09 Observability 設定值物件。

服務級設定（resource 屬性、匯出端點、取樣率等）。租戶層級的 tenant_id 不在此
（屬請求範圍，於 logging/tracing context 綁定，無預設）——避免把 per-request 資料
誤鎖進 per-service 設定。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Environment(StrEnum):
    """部署環境。對應 OTEL resource 屬性 deployment.environment。"""

    LOCAL = "local"
    STAGING = "staging"
    PRODUCTION = "production"


@dataclass(frozen=True, slots=True)
class ObservabilityConfig:
    """可觀測性服務級設定（不可變值物件）。

    otlp_endpoint 為 None 時匯出走 no-op（D2 fallback）：本機/測試零負擔，
    且遙測未設定不會讓系統崩潰。
    """

    service_name: str
    service_version: str
    environment: Environment
    otlp_endpoint: str | None = None
    log_level: str = "INFO"
    console_logs: bool = False
    metric_export_interval_ms: int = 60_000
    trace_sample_ratio: float = 1.0

    def __post_init__(self) -> None:
        # fail-closed：設定不合法立即拒絕，不容忍「悄悄帶壞值上線」。
        if not self.service_name:
            raise ValueError("service_name 不可為空")
        if not self.service_version:
            raise ValueError("service_version 不可為空")
        if not 0.0 <= self.trace_sample_ratio <= 1.0:
            raise ValueError("trace_sample_ratio 必須在 0.0–1.0 之間")
        if self.metric_export_interval_ms <= 0:
            raise ValueError("metric_export_interval_ms 必須為正整數")

    @property
    def exporters_enabled(self) -> bool:
        """有 OTLP endpoint 才啟用匯出；否則走 no-op（D2 fallback）。"""
        return self.otlp_endpoint is not None

    def resource_attributes(self) -> dict[str, str]:
        """OTEL Resource 屬性（traces / metrics / logs 共用的服務身分）。"""
        return {
            "service.name": self.service_name,
            "service.version": self.service_version,
            "deployment.environment": self.environment.value,
        }
