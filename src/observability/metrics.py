"""指標（D3：registry + exporter + domain helper）。

- build_meter_provider：有 OTLP endpoint 才掛週期匯出（no-op fallback）。
- Metrics：counter / histogram / gauge 三原語 + 儀器快取（同名只建一次 = registry）。
- domain helper 只涵蓋「現有模組」（policy / ATR / audit / request）；未來模組的領域
  指標隨各自切片用本工廠註冊，不回頭改 S09（見 S09 規格 D3）。
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource

from src.observability.config import ObservabilityConfig
from src.observability.redaction import safe_attributes

# 高基數 label 守門：這些 key 會在 Prometheus 炸 series（成本/效能風險）。
# 規則：以 "_id" 結尾者（tenant_id 除外）+ 明列的高基數鍵，一律不入 metric label。
_HIGH_CARDINALITY_KEYS: frozenset[str] = frozenset(
    {"email", "ip", "ip_address", "user", "username"}
)


def _is_high_cardinality(key: str) -> bool:
    low = key.lower()
    if low == "tenant_id":
        return False
    return low.endswith("_id") or low in _HIGH_CARDINALITY_KEYS


def safe_labels(attributes: Mapping[str, Any]) -> dict[str, Any]:
    """遮蔽 + 丟棄高基數 label（user_id / order_id / decision_id / email…），保留 tenant_id。"""
    return {
        key: value
        for key, value in safe_attributes(attributes).items()
        if not _is_high_cardinality(key)
    }


def build_meter_provider(config: ObservabilityConfig) -> MeterProvider:
    """建 MeterProvider；有 endpoint 才掛 OTLP 週期匯出（no-op fallback）。"""
    resource = Resource.create(config.resource_attributes())
    readers: list[PeriodicExportingMetricReader] = []
    if config.exporters_enabled:
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
            OTLPMetricExporter,
        )

        exporter = OTLPMetricExporter(endpoint=f"{config.otlp_endpoint}/v1/metrics")
        readers.append(
            PeriodicExportingMetricReader(
                exporter,
                export_interval_millis=config.metric_export_interval_ms,
            )
        )
    return MeterProvider(resource=resource, metric_readers=readers)


class Metrics:
    """OTEL meter 薄封裝 + 儀器快取。標籤一律過遮蔽。"""

    __slots__ = ("_counters", "_gauges", "_histograms", "_meter")

    def __init__(self, meter: Any) -> None:
        self._meter = meter
        self._counters: dict[str, Any] = {}
        self._histograms: dict[str, Any] = {}
        self._gauges: dict[str, Any] = {}

    def _counter(self, name: str) -> Any:
        inst = self._counters.get(name)
        if inst is None:
            inst = self._meter.create_counter(name)
            self._counters[name] = inst
        return inst

    def _histogram(self, name: str) -> Any:
        inst = self._histograms.get(name)
        if inst is None:
            inst = self._meter.create_histogram(name)
            self._histograms[name] = inst
        return inst

    def _gauge(self, name: str) -> Any:
        inst = self._gauges.get(name)
        if inst is None:
            inst = self._meter.create_gauge(name)
            self._gauges[name] = inst
        return inst

    def increment(
        self, name: str, amount: int = 1, attributes: Mapping[str, Any] | None = None
    ) -> None:
        """累加 counter。"""
        self._counter(name).add(amount, safe_labels(attributes or {}))

    def record(self, name: str, value: float, attributes: Mapping[str, Any] | None = None) -> None:
        """記錄 histogram（延遲分布等）。"""
        self._histogram(name).record(value, safe_labels(attributes or {}))

    def set_gauge(
        self, name: str, value: float, attributes: Mapping[str, Any] | None = None
    ) -> None:
        """設定 gauge 即時值（水位等）。"""
        self._gauge(name).set(value, safe_labels(attributes or {}))

    # ---- domain helpers（現有模組）----

    def record_policy_decision(self, decision: str, tenant_id: str) -> None:
        """S08 policy 決策計數。"""
        self.increment(
            "policy_decisions_total",
            attributes={"decision": decision, "tenant_id": tenant_id},
        )

    def record_atr_decision(self, level: str, action: str, tenant_id: str) -> None:
        """S07 ATR 決策計數（按風險級別 / 處置）。"""
        self.increment(
            "atr_decisions_total",
            attributes={"level": level, "action": action, "tenant_id": tenant_id},
        )

    def record_audit_write_ms(self, duration_ms: float, tenant_id: str) -> None:
        """S05 稽核寫入延遲（觀測指標，非證據；不碰 audit 證據鏈）。"""
        self.record("audit_write_ms", duration_ms, attributes={"tenant_id": tenant_id})

    def record_request_ms(
        self, duration_ms: float, attributes: Mapping[str, Any] | None = None
    ) -> None:
        """一般請求延遲。"""
        self.record("request_duration_ms", duration_ms, attributes=attributes)
