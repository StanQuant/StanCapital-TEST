"""ATR 評分引擎 · rule-based fast path + 上下文加權 + ML disabled port."""

from __future__ import annotations

from typing import Protocol

from src.security.atr.rules import AtrRule
from src.security.atr.types import (
    AgentBehavior,
    ThreatScore,
    TriggeredRule,
    level_for_score,
)

HIGH_RISK_MULTIPLIER = 1.2
HIGH_RISK_LEVEL_THRESHOLD = 7


class RiskModelPort(Protocol):
    """未來 ML slow path 的接點。S07 只定介面，不接真模型。"""

    def predict(self, behavior: AgentBehavior) -> int:
        """回傳 0-100 ML 風險分數。"""


class AtrEngine:
    """對 Agent 行為打 0-100 分。"""

    def __init__(
        self,
        rules: tuple[AtrRule, ...],
        *,
        ml_model: RiskModelPort | None = None,
        ml_model_enabled: bool = False,
    ) -> None:
        self._rules = rules
        self._ml_model = ml_model
        self._ml_model_enabled = ml_model_enabled

    def score(self, behavior: AgentBehavior) -> ThreatScore:
        """規則命中加總 → 可選 ML max → 高風險 Agent 1.2 倍 → clamp 100。"""
        triggered: list[TriggeredRule] = []
        raw_score = 0
        for rule in self._rules:
            if rule.matches(behavior):
                definition = rule.definition
                raw_score += definition.weight
                triggered.append(
                    TriggeredRule(
                        code=definition.code,
                        category=definition.category,
                        weight=definition.weight,
                        risk_category=definition.risk_category,
                    )
                )

        if self._ml_model_enabled and self._ml_model is not None and raw_score < 80:
            raw_score = max(raw_score, self._ml_model.predict(behavior))

        multiplier = (
            HIGH_RISK_MULTIPLIER if behavior.agent.risk_level > HIGH_RISK_LEVEL_THRESHOLD else 1.0
        )
        value = min(int(raw_score * multiplier), 100)
        risk_category = triggered[0].risk_category if triggered else "safe"
        return ThreatScore(
            value=value,
            level=level_for_score(value),
            triggered_rules=tuple(triggered),
            context_multiplier=multiplier,
            agent_id=behavior.agent.agent_id,
            tenant_id=behavior.agent.tenant_id,
            risk_category=risk_category,
            trace_id=behavior.trace_id,
        )
