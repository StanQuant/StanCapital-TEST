"""SOC 通知 port 測試。"""

from __future__ import annotations

from src.observability.ports import (
    InMemorySocNotificationPort,
    NoopSocNotificationPort,
    SocAlert,
)


def _alert() -> SocAlert:
    return SocAlert(
        tenant_id="stanley",
        source="atr",
        severity="critical",
        title="t",
        decision_id="d1",
        trace_id="tr1",
        timestamp="2026-06-29T00:00:00+00:00",
    )


def test_alert_defaults_empty_attributes() -> None:
    assert _alert().attributes == {}


def test_alert_frozen_slots() -> None:
    assert not hasattr(_alert(), "__dict__")


def test_noop_port_returns_none() -> None:
    assert NoopSocNotificationPort().send(_alert()) is None


def test_in_memory_port_collects() -> None:
    port = InMemorySocNotificationPort()
    port.send(_alert())
    assert len(port.alerts) == 1
    assert port.alerts[0].tenant_id == "stanley"
