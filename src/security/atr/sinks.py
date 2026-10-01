"""ATR sink ports · 通知安全負責人與控制 Agent。

S07 不直連 Slack / Email / Agent registry；這裡只定 port 與測試用 in-memory 實作。
未來 S09/S22/S24 接上真通道時，不需要推翻 ATR 核心。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from src.security.atr.types import AgentBehavior, AtrDecision


@dataclass(frozen=True, slots=True)
class SecurityNotification:
    """送給 Security Officer / SOC 的結構化通知。"""

    tenant_id: str
    agent_id: str
    decision_id: str
    score: int
    level: str
    action: str
    triggered_rules: tuple[str, ...]
    target: str
    trace_id: str
    timestamp: str


class SecurityOfficerSink(Protocol):
    """Security Officer 通知出口。"""

    def notify(self, notification: SecurityNotification) -> None:
        """送出安全通知。"""


class AgentControlSink(Protocol):
    """Agent 控制出口。未來接 Agent registry。"""

    def suspend(self, behavior: AgentBehavior, decision: AtrDecision) -> None:
        """暫停 Agent。"""

    def terminate(self, behavior: AgentBehavior, decision: AtrDecision) -> None:
        """終止 Agent session。"""


class NoopSecurityOfficerSink:
    """本機預設 sink：不送出通知。"""

    def notify(self, notification: SecurityNotification) -> None:
        _ = notification


class NoopAgentControlSink:
    """本機預設 Agent control sink：不操作真 Agent。"""

    def suspend(self, behavior: AgentBehavior, decision: AtrDecision) -> None:
        _ = (behavior, decision)

    def terminate(self, behavior: AgentBehavior, decision: AtrDecision) -> None:
        _ = (behavior, decision)


class InMemorySecurityOfficerSink:
    """測試用 sink，收集通知。"""

    def __init__(self) -> None:
        self.notifications: list[SecurityNotification] = []

    def notify(self, notification: SecurityNotification) -> None:
        self.notifications.append(notification)


class InMemoryAgentControlSink:
    """測試用 Agent control sink，收集暫停/終止命令。"""

    def __init__(self) -> None:
        self.suspended: list[tuple[AgentBehavior, AtrDecision]] = []
        self.terminated: list[tuple[AgentBehavior, AtrDecision]] = []

    def suspend(self, behavior: AgentBehavior, decision: AtrDecision) -> None:
        self.suspended.append((behavior, decision))

    def terminate(self, behavior: AgentBehavior, decision: AtrDecision) -> None:
        self.terminated.append((behavior, decision))


def notification_from_decision(
    behavior: AgentBehavior, decision: AtrDecision
) -> SecurityNotification:
    """把 ATR 決策轉成未來 Slack / Email / SOC 都能吃的 payload。"""
    score = decision.score
    return SecurityNotification(
        tenant_id=score.tenant_id,
        agent_id=score.agent_id,
        decision_id=decision.decision_id,
        score=score.value,
        level=score.level.value,
        action=decision.action.value,
        triggered_rules=tuple(code.value for code in score.triggered_codes),
        target=behavior.target,
        trace_id=score.trace_id,
        timestamp=score.timestamp.isoformat(),
    )
