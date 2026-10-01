"""ATR Guard · 評分、回應、通知、Agent control 的編排層。"""

from __future__ import annotations

import logging

from src.governance.audit.decorator import AuditContext
from src.security.atr.engine import AtrEngine
from src.security.atr.response import AtrResponseHandler
from src.security.atr.sinks import (
    AgentControlSink,
    NoopAgentControlSink,
    NoopSecurityOfficerSink,
    SecurityOfficerSink,
    notification_from_decision,
)
from src.security.atr.types import AgentBehavior, AtrDecision

logger = logging.getLogger(__name__)


class AtrGuard:
    """ATR 唯一編排入口。

    核心 engine / response 保持純淨；通知和 Agent 控制透過 sink port 注入。
    sink 失敗不可把高風險決策變放行，只能 CRITICAL 告警。
    """

    def __init__(
        self,
        engine: AtrEngine,
        response_handler: AtrResponseHandler,
        *,
        security_sink: SecurityOfficerSink | None = None,
        agent_control_sink: AgentControlSink | None = None,
    ) -> None:
        self._engine = engine
        self._response_handler = response_handler
        self._security_sink = security_sink or NoopSecurityOfficerSink()
        self._agent_control_sink = agent_control_sink or NoopAgentControlSink()

    def evaluate(self, behavior: AgentBehavior) -> AtrDecision:
        """評分並執行必要 sink side effects。"""
        score = self._engine.score(behavior)
        decision = self._response_handler.decide(score)
        self._apply_agent_control(behavior, decision)
        self._notify_security_officer(behavior, decision)
        return decision

    def audit_context_with_risk(self, ctx: AuditContext, decision: AtrDecision) -> AuditContext:
        """產生帶 ATR risk_score 的 AuditContext，不修改原物件。"""
        return AuditContext(
            tenant_id=ctx.tenant_id,
            user_id=ctx.user_id,
            role=ctx.role,
            ip_address=ctx.ip_address,
            user_agent=ctx.user_agent,
            risk_score=decision.score.value,
        )

    def _apply_agent_control(self, behavior: AgentBehavior, decision: AtrDecision) -> None:
        try:
            if decision.terminate_session:
                self._agent_control_sink.terminate(behavior, decision)
            elif decision.suspend_agent:
                self._agent_control_sink.suspend(behavior, decision)
        except Exception as sink_error:
            logger.critical(
                "ATR Agent control sink 失敗(決策仍生效): tenant=%s agent=%s decision=%s 原因=%s",
                behavior.agent.tenant_id,
                behavior.agent.agent_id,
                decision.decision_id,
                sink_error,
            )

    def _notify_security_officer(self, behavior: AgentBehavior, decision: AtrDecision) -> None:
        if not decision.notify_security_officer:
            return
        notification = notification_from_decision(behavior, decision)
        try:
            self._security_sink.notify(notification)
        except Exception as sink_error:
            logger.critical(
                "ATR SecurityOfficer sink 失敗(決策仍生效): tenant=%s agent=%s decision=%s 原因=%s",
                behavior.agent.tenant_id,
                behavior.agent.agent_id,
                decision.decision_id,
                sink_error,
            )
