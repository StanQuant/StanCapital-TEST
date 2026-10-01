"""S09 demo：模擬「UI 點按鈕 → 一條 trace 跨 5 層」。

5 層：L4 event-bus → L5 application → L11 governance → L10 security → L9 observability。
無真 UI，以巢狀 span 串出單一 trace；最內層同時 emit 結構化 log 與指標。
可執行：uv run python -m src.observability.demo
"""

from __future__ import annotations

from src.observability.config import Environment, ObservabilityConfig
from src.observability.logging import bind_request_context, clear_request_context
from src.observability.provider import ObservabilityProvider

# (層名, 操作名)；由外而內串成一條 trace。
_LAYERS: tuple[tuple[str, str], ...] = (
    ("L4.event_bus", "receive_click_event"),
    ("L5.application", "handle_submit_order"),
    ("L11.governance", "rbac_abac_check"),
    ("L10.security", "atr_policy_evaluate"),
    ("L9.observability", "emit_telemetry"),
)


def run_five_layer_demo(provider: ObservabilityProvider, tenant_id: str = "stanley") -> str:
    """跑一條跨 5 層的 trace，回傳 trace_id（16 進位 32 字元）。"""
    bind_request_context(tenant_id, workflow_id="demo_submit_order")
    try:
        trace_id = _descend(provider, 0, tenant_id)
        # 在 context 清除前發出，使 demo_complete 與各層 log 欄位一致（帶 tenant_id / workflow_id）。
        provider.logger(__name__).info("demo_complete", trace_id=trace_id)
        return trace_id
    finally:
        clear_request_context()


def _descend(provider: ObservabilityProvider, index: int, tenant_id: str) -> str:
    name, op = _LAYERS[index]
    with provider.tracer.span(f"{name}.{op}", tenant_id=tenant_id) as span:
        provider.logger(__name__).info("layer_enter", layer=name, op=op)
        if index + 1 < len(_LAYERS):
            return _descend(provider, index + 1, tenant_id)
        provider.metrics.record_request_ms(4.2, {"tenant_id": tenant_id})
        return format(span.get_span_context().trace_id, "032x")


def main() -> None:  # pragma: no cover
    provider = ObservabilityProvider.create(
        ObservabilityConfig(
            service_name="stanquant-demo",
            service_version="0.1.0",
            environment=Environment.LOCAL,
        )
    )
    run_five_layer_demo(provider)
    provider.shutdown()


if __name__ == "__main__":  # pragma: no cover
    main()
