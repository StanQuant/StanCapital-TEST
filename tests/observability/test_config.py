"""ObservabilityConfig 值物件測試。"""

from __future__ import annotations

import pytest
from src.observability.config import Environment, ObservabilityConfig


def _valid() -> ObservabilityConfig:
    return ObservabilityConfig(
        service_name="stanquant-app",
        service_version="0.1.0",
        environment=Environment.LOCAL,
    )


def test_defaults() -> None:
    cfg = _valid()
    assert cfg.otlp_endpoint is None
    assert cfg.log_level == "INFO"
    assert cfg.console_logs is False
    assert cfg.metric_export_interval_ms == 60_000
    assert cfg.trace_sample_ratio == 1.0


def test_frozen() -> None:
    cfg = _valid()
    with pytest.raises(AttributeError):
        cfg.service_name = "other"  # type: ignore[misc]


def test_slots_no_dict() -> None:
    # slots 值物件不應有 __dict__（避免動態加欄位、省記憶體）
    assert not hasattr(_valid(), "__dict__")


def test_exporters_disabled_when_no_endpoint() -> None:
    assert _valid().exporters_enabled is False


def test_exporters_enabled_with_endpoint() -> None:
    cfg = ObservabilityConfig(
        service_name="svc",
        service_version="1.0",
        environment=Environment.PRODUCTION,
        otlp_endpoint="http://collector:4318",
    )
    assert cfg.exporters_enabled is True


def test_resource_attributes() -> None:
    cfg = ObservabilityConfig(
        service_name="svc",
        service_version="1.2.3",
        environment=Environment.STAGING,
    )
    assert cfg.resource_attributes() == {
        "service.name": "svc",
        "service.version": "1.2.3",
        "deployment.environment": "staging",
    }


def test_reject_empty_service_name() -> None:
    with pytest.raises(ValueError, match="service_name 不可為空"):
        ObservabilityConfig(
            service_name="",
            service_version="1.0",
            environment=Environment.LOCAL,
        )


def test_reject_empty_service_version() -> None:
    with pytest.raises(ValueError, match="service_version 不可為空"):
        ObservabilityConfig(
            service_name="svc",
            service_version="",
            environment=Environment.LOCAL,
        )


@pytest.mark.parametrize("ratio", [-0.1, 1.1])
def test_reject_invalid_sample_ratio(ratio: float) -> None:
    with pytest.raises(ValueError, match="trace_sample_ratio 必須在"):
        ObservabilityConfig(
            service_name="svc",
            service_version="1.0",
            environment=Environment.LOCAL,
            trace_sample_ratio=ratio,
        )


@pytest.mark.parametrize("ratio", [0.0, 0.5, 1.0])
def test_accept_boundary_sample_ratio(ratio: float) -> None:
    cfg = ObservabilityConfig(
        service_name="svc",
        service_version="1.0",
        environment=Environment.LOCAL,
        trace_sample_ratio=ratio,
    )
    assert cfg.trace_sample_ratio == ratio


@pytest.mark.parametrize("interval", [0, -1])
def test_reject_nonpositive_interval(interval: int) -> None:
    with pytest.raises(ValueError, match="metric_export_interval_ms 必須為正整數"):
        ObservabilityConfig(
            service_name="svc",
            service_version="1.0",
            environment=Environment.LOCAL,
            metric_export_interval_ms=interval,
        )


# ---- mutation killers ----


@pytest.mark.parametrize(
    ("env", "value"),
    [
        (Environment.LOCAL, "local"),
        (Environment.STAGING, "staging"),
        (Environment.PRODUCTION, "production"),
    ],
)
def test_environment_values(env: Environment, value: str) -> None:
    assert env.value == value


def test_accept_interval_one_boundary() -> None:
    # 邊界：1 應被接受（殺 <=0 變 <=1 的變異）
    cfg = ObservabilityConfig(
        service_name="svc",
        service_version="1.0",
        environment=Environment.LOCAL,
        metric_export_interval_ms=1,
    )
    assert cfg.metric_export_interval_ms == 1


def test_empty_service_name_exact_message() -> None:
    with pytest.raises(ValueError) as exc:
        ObservabilityConfig(service_name="", service_version="1.0", environment=Environment.LOCAL)
    assert str(exc.value) == "service_name 不可為空"


def test_empty_service_version_exact_message() -> None:
    with pytest.raises(ValueError) as exc:
        ObservabilityConfig(service_name="svc", service_version="", environment=Environment.LOCAL)
    assert str(exc.value) == "service_version 不可為空"


def test_bad_ratio_exact_message() -> None:
    with pytest.raises(ValueError) as exc:
        ObservabilityConfig(
            service_name="svc",
            service_version="1.0",
            environment=Environment.LOCAL,
            trace_sample_ratio=2.0,
        )
    assert str(exc.value) == "trace_sample_ratio 必須在 0.0–1.0 之間"


def test_bad_interval_exact_message() -> None:
    with pytest.raises(ValueError) as exc:
        ObservabilityConfig(
            service_name="svc",
            service_version="1.0",
            environment=Environment.LOCAL,
            metric_export_interval_ms=0,
        )
    assert str(exc.value) == "metric_export_interval_ms 必須為正整數"
