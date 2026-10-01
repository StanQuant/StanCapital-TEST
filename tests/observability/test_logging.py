"""結構化日誌測試。"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator

import pytest
import structlog
from opentelemetry.sdk.trace import TracerProvider
from src.observability import logging as obs_logging
from src.observability.config import Environment, ObservabilityConfig
from src.observability.logging import (
    add_otel_context,
    bind_request_context,
    clear_request_context,
    configure_logging,
    get_logger,
    redact_event,
)


@pytest.fixture(autouse=True)
def _reset_structlog() -> Iterator[None]:
    yield
    structlog.reset_defaults()
    structlog.contextvars.clear_contextvars()
    logging.getLogger().handlers.clear()


def _cfg(*, console: bool = False) -> ObservabilityConfig:
    return ObservabilityConfig(
        service_name="svc",
        service_version="1.0",
        environment=Environment.LOCAL,
        console_logs=console,
    )


def test_add_otel_context_no_span() -> None:
    # 無有效 span：不注入 trace_id
    out = add_otel_context(None, "info", {})
    assert "trace_id" not in out


def test_add_otel_context_with_span() -> None:
    tracer = TracerProvider().get_tracer("test")
    with tracer.start_as_current_span("s"):
        out = add_otel_context(None, "info", {})
    assert len(out["trace_id"]) == 32
    assert len(out["span_id"]) == 16


def test_redact_event_processor() -> None:
    out = redact_event(None, "info", {"password": "x", "ok": "y"})
    assert out["password"] == "***REDACTED***"
    assert out["ok"] == "y"


def test_json_output(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(_cfg())
    get_logger("t").info("hello", foo="bar")
    line = capsys.readouterr().err.strip()
    payload = json.loads(line)
    assert payload["event"] == "hello"
    assert payload["foo"] == "bar"
    assert payload["level"] == "info"
    assert payload["logger"] == "t"
    assert "timestamp" in payload


def test_json_output_redacts(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(_cfg())
    get_logger("t").info("login", password="hunter2")  # pragma: allowlist secret
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["password"] == "***REDACTED***"


def test_context_binding_appears(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(_cfg())
    bind_request_context("stanley", workflow_id="wf1")
    get_logger("t").info("evt")
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["tenant_id"] == "stanley"
    assert payload["workflow_id"] == "wf1"


def test_stdlib_bridge(capsys: pytest.CaptureFixture[str]) -> None:
    # 既有 stdlib logging 呼叫點也走 JSON 管線
    configure_logging(_cfg())
    logging.getLogger("legacy").warning("old style")
    payload = json.loads(capsys.readouterr().err.strip())
    assert payload["event"] == "old style"
    assert payload["level"] == "warning"


def test_console_mode(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(_cfg(console=True))
    get_logger("t").info("pretty")
    out = capsys.readouterr().err
    assert "pretty" in out


def test_trace_id_in_log(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(_cfg())
    tracer = TracerProvider().get_tracer("test")
    with tracer.start_as_current_span("s"):
        get_logger("t").info("traced")
    payload = json.loads(capsys.readouterr().err.strip())
    assert len(payload["trace_id"]) == 32


def test_bind_rejects_empty_tenant() -> None:
    with pytest.raises(ValueError, match="tenant_id 不可為空"):
        bind_request_context("")


def test_clear_request_context(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(_cfg())
    bind_request_context("stanley")
    clear_request_context()
    get_logger("t").info("after_clear")
    payload = json.loads(capsys.readouterr().err.strip())
    assert "tenant_id" not in payload


def test_get_logger_default_name() -> None:
    configure_logging(_cfg())
    assert get_logger() is not None


def test_module_logger_alias() -> None:
    # 確保模組可作為命名空間匯入（覆蓋 import 形式）
    assert obs_logging.get_logger is get_logger


# ---- mutation killers ----


def test_timestamp_is_iso_utc(capsys: pytest.CaptureFixture[str]) -> None:
    # 殺 fmt="iso"→亂字串 與 utc=True→False 變異
    configure_logging(_cfg())
    get_logger("t").info("evt")
    ts = json.loads(capsys.readouterr().err.strip())["timestamp"]
    assert "T" in ts
    assert ts.endswith("Z")


def test_bind_empty_tenant_exact_message() -> None:
    with pytest.raises(ValueError) as exc:
        bind_request_context("")
    assert str(exc.value) == "tenant_id 不可為空"
