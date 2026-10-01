"""SOC 通知出口（D10）。

S09 只定義 port 與測試用實作；真送 Slack / Email / PagerDuty / SOC 後端由
S22 / S24 / S25 接線。本機預設 Noop（不外送）。
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True, slots=True)
class SocAlert:
    """送給 SOC 的結構化告警（從安全事件提煉，屬性已遮蔽）。"""

    tenant_id: str
    source: str  # "atr" / "policy"
    severity: str  # "info" / "warning" / "critical"
    title: str
    decision_id: str
    trace_id: str
    timestamp: str
    attributes: Mapping[str, str] = field(default_factory=dict)


class SocNotificationPort(Protocol):
    """SOC 通知出口。"""

    def send(self, alert: SocAlert) -> None:
        """送出告警。"""


class NoopSocNotificationPort:
    """本機預設：不外送。"""

    def send(self, alert: SocAlert) -> None:
        _ = alert


class InMemorySocNotificationPort:
    """測試用：收集告警。"""

    def __init__(self) -> None:
        self.alerts: list[SocAlert] = []

    def send(self, alert: SocAlert) -> None:
        self.alerts.append(alert)
