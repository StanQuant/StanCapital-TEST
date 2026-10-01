"""完整 observability stack 整合測試（D9 · docker compose 部分）。

預設略過（marker: integration）。需先起 stack：
    docker compose -f infra/observability/docker-compose.yml up -d
再以：
    STANQUANT_OBS_STACK=1 .venv/bin/python -m pytest tests/observability \
        -m integration
執行。會送一條 5 層 trace 到 Collector，再向 Tempo 查回該 trace_id。
"""

from __future__ import annotations

import os
import time

import pytest

pytestmark = pytest.mark.integration

_STACK_ENABLED = os.environ.get("STANQUANT_OBS_STACK") == "1"
_OTLP = os.environ.get("OTLP_ENDPOINT", "http://localhost:4318")
_TEMPO = os.environ.get("TEMPO_ENDPOINT", "http://localhost:3200")


@pytest.mark.skipif(not _STACK_ENABLED, reason="需 STANQUANT_OBS_STACK=1 且 stack 已啟動")
def test_trace_reaches_tempo() -> None:
    import requests
    from src.observability.config import Environment, ObservabilityConfig
    from src.observability.demo import run_five_layer_demo
    from src.observability.provider import ObservabilityProvider

    provider = ObservabilityProvider.create(
        ObservabilityConfig(
            service_name="stanquant-itest",
            service_version="0.1.0",
            environment=Environment.LOCAL,
            otlp_endpoint=_OTLP,
        )
    )
    trace_id = run_five_layer_demo(provider)
    provider.shutdown()  # flush BatchSpanProcessor

    # Tempo 接收 + 索引有延遲，輪詢數秒
    deadline = time.time() + 30
    last_status = None
    while time.time() < deadline:
        resp = requests.get(f"{_TEMPO}/api/traces/{trace_id}", timeout=5)
        last_status = resp.status_code
        if resp.status_code == 200:
            break
        time.sleep(2)
    assert last_status == 200, f"Tempo 找不到 trace {trace_id}（status={last_status}）"
