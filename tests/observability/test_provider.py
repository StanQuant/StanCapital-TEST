"""ObservabilityProvider 測試。"""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest
import structlog
from src.observability.config import Environment, ObservabilityConfig
from src.observability.metrics import Metrics
from src.observability.provider import ObservabilityProvider
from src.observability.tracing import Tracer


@pytest.fixture(autouse=True)
def _reset() -> Iterator[None]:
    yield
    structlog.reset_defaults()
    structlog.contextvars.clear_contextvars()
    logging.getLogger().handlers.clear()


def _cfg() -> ObservabilityConfig:
    return ObservabilityConfig(
        service_name="svc",
        service_version="1.0",
        environment=Environment.LOCAL,
    )


def test_create_wires_components() -> None:
    provider = ObservabilityProvider.create(_cfg())
    assert isinstance(provider.tracer, Tracer)
    assert isinstance(provider.metrics, Metrics)
    assert provider.config.service_name == "svc"
    provider.shutdown()


def test_create_configures_logging() -> None:
    ObservabilityProvider.create(_cfg())
    # 設定後 root logger 應有 handler
    assert logging.getLogger().handlers


def test_create_without_log_config() -> None:
    logging.getLogger().handlers.clear()
    provider = ObservabilityProvider.create(_cfg(), configure_logs=False)
    assert not logging.getLogger().handlers
    provider.shutdown()


def test_noop_does_not_configure_logging() -> None:
    logging.getLogger().handlers.clear()
    provider = ObservabilityProvider.noop()
    assert not logging.getLogger().handlers
    assert isinstance(provider.tracer, Tracer)
    provider.shutdown()


def test_logger_accessor() -> None:
    provider = ObservabilityProvider.create(_cfg())
    assert provider.logger("x") is not None
    assert provider.logger() is not None
    provider.shutdown()


def test_tracer_and_metrics_functional() -> None:
    provider = ObservabilityProvider.create(_cfg())
    with provider.tracer.span("op", tenant_id="stanley"):
        provider.metrics.increment("calls_total", 1, {"tenant_id": "stanley"})
    provider.shutdown()


def test_shutdown_idempotent() -> None:
    provider = ObservabilityProvider.create(_cfg())
    provider.shutdown()
    provider.shutdown()


def test_provider_slots_no_dict() -> None:
    provider = ObservabilityProvider.noop()
    assert not hasattr(provider, "__dict__")
    provider.shutdown()


# ---- mutation killers ----


def test_noop_config_identity() -> None:
    # 殺 _NOOP_CONFIG service_name/version 字串變異
    provider = ObservabilityProvider.noop()
    assert provider.config.service_name == "noop"
    assert provider.config.service_version == "0"
    assert provider.config.environment is Environment.LOCAL
    provider.shutdown()
