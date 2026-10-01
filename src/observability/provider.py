"""ObservabilityProvider（D2：封裝 + DI 注入 + no-op fallback）。

把三大支柱（logging / tracing / metrics）集中在一個可注入的物件：
- 上層模組透過建構子接收 provider（DI，乾淨、可測、無隱藏全域）。
- create()：依設定建好整套；無 OTLP endpoint 時匯出自動 no-op（fallback）。
- noop()：完全不外送、也不重設全域 logging，供測試 / 未接線環境當預設。
"""

from __future__ import annotations

from typing import Any

from src.observability.config import Environment, ObservabilityConfig
from src.observability.logging import configure_logging, get_logger
from src.observability.metrics import Metrics, build_meter_provider
from src.observability.tracing import Tracer, build_tracer_provider

_NOOP_CONFIG = ObservabilityConfig(
    service_name="noop",
    service_version="0",
    environment=Environment.LOCAL,
)


class ObservabilityProvider:
    """可注入的可觀測性入口。"""

    __slots__ = ("_config", "_meter_provider", "_metrics", "_tracer", "_tracer_provider")

    def __init__(
        self,
        config: ObservabilityConfig,
        tracer: Tracer,
        metrics: Metrics,
        tracer_provider: Any,
        meter_provider: Any,
    ) -> None:
        self._config = config
        self._tracer = tracer
        self._metrics = metrics
        self._tracer_provider = tracer_provider
        self._meter_provider = meter_provider

    @classmethod
    def create(
        cls, config: ObservabilityConfig, *, configure_logs: bool = True
    ) -> ObservabilityProvider:
        """依設定建好整套；configure_logs=False 時不動全域 logging。"""
        if configure_logs:
            configure_logging(config)
        tracer_provider = build_tracer_provider(config)
        meter_provider = build_meter_provider(config)
        tracer = Tracer(tracer_provider.get_tracer(config.service_name))
        metrics = Metrics(meter_provider.get_meter(config.service_name))
        return cls(config, tracer, metrics, tracer_provider, meter_provider)

    @classmethod
    def noop(cls) -> ObservabilityProvider:
        """no-op fallback：不外送、不重設全域 logging。"""
        return cls.create(_NOOP_CONFIG, configure_logs=False)

    @property
    def config(self) -> ObservabilityConfig:
        return self._config

    @property
    def tracer(self) -> Tracer:
        return self._tracer

    @property
    def metrics(self) -> Metrics:
        return self._metrics

    def logger(self, name: str | None = None) -> Any:
        """取得結構化 logger。"""
        return get_logger(name)

    def shutdown(self) -> None:
        """關閉 provider，flush 匯出器（程序結束時呼叫）。"""
        self._tracer_provider.shutdown()
        self._meter_provider.shutdown()
