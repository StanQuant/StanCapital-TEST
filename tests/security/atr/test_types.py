"""ATR 型別測試。"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest
from src.security.atr.types import (
    AgentBehavior,
    AgentIdentity,
    AtrAction,
    AtrDecision,
    AtrRuleDefinition,
    MetadataValue,
    SuppressionRule,
    ThreatCode,
    ThreatLevel,
    ThreatScore,
    TriggeredRule,
    level_for_score,
)


def test_public_enum_values_are_stable_contracts() -> None:
    assert {level.name: level.value for level in ThreatLevel} == {
        "SAFE": "safe",
        "LOW": "low",
        "MEDIUM": "medium",
        "HIGH": "high",
        "CRITICAL": "critical",
    }
    assert {action.name: action.value for action in AtrAction} == {
        "ALLOW": "allow",
        "LOG": "log",
        "ENCRYPT": "encrypt",
        "SUSPEND": "suspend",
        "TERMINATE": "terminate",
    }
    assert {code.name: code.value for code in ThreatCode} == {
        "T001": "T001",
        "T002": "T002",
        "T003": "T003",
        "T004": "T004",
        "T005": "T005",
        "T006": "T006",
        "T007": "T007",
        "T008": "T008",
    }


@pytest.mark.parametrize(
    ("score", "level"),
    [
        (0, ThreatLevel.SAFE),
        (20, ThreatLevel.SAFE),
        (21, ThreatLevel.LOW),
        (40, ThreatLevel.LOW),
        (41, ThreatLevel.MEDIUM),
        (60, ThreatLevel.MEDIUM),
        (61, ThreatLevel.HIGH),
        (80, ThreatLevel.HIGH),
        (81, ThreatLevel.CRITICAL),
        (100, ThreatLevel.CRITICAL),
    ],
)
def test_level_for_score_boundaries(score: int, level: ThreatLevel) -> None:
    assert level_for_score(score) is level


@pytest.mark.parametrize("score", [-1, 101])
def test_level_for_score_rejects_out_of_range(score: int) -> None:
    with pytest.raises(ValueError) as exc:
        level_for_score(score)
    assert str(exc.value).startswith("score 必須在 0-100 之間")


def test_agent_identity_is_frozen_slots_and_validates() -> None:
    agent = AgentIdentity(tenant_id="stanley", agent_id="agent-1", risk_level=5)
    assert not hasattr(agent, "__dict__")
    assert AgentIdentity(tenant_id="stanley", agent_id="agent-low", risk_level=1).risk_level == 1
    assert AgentIdentity(tenant_id="stanley", agent_id="agent-high", risk_level=10).risk_level == 10
    with pytest.raises(FrozenInstanceError):
        agent.risk_level = 6  # type: ignore[misc]
    with pytest.raises(ValueError) as exc_tenant:
        AgentIdentity(tenant_id="", agent_id="agent-1", risk_level=5)
    assert str(exc_tenant.value) == "tenant_id 不可為空"
    with pytest.raises(ValueError) as exc_agent:
        AgentIdentity(tenant_id="stanley", agent_id="", risk_level=5)
    assert str(exc_agent.value) == "agent_id 不可為空"
    with pytest.raises(ValueError) as exc:
        AgentIdentity(tenant_id="stanley", agent_id="agent-1", risk_level=0)
    assert str(exc.value) == "risk_level 必須在 1-10 之間: 0"
    with pytest.raises(ValueError) as exc_high:
        AgentIdentity(tenant_id="stanley", agent_id="agent-1", risk_level=11)
    assert str(exc_high.value) == "risk_level 必須在 1-10 之間: 11"


def test_agent_behavior_validates_metadata() -> None:
    agent = AgentIdentity(tenant_id="stanley", agent_id="agent-1", risk_level=5)
    behavior = AgentBehavior(
        agent=agent,
        tool_name="shell",
        action="read",
        target="/workspace/a",
        payload_summary="ok",
        metadata={"count": 1, "ok": True, "none": None},
        trace_id="trace-1",
    )
    assert not hasattr(behavior, "__dict__")
    with pytest.raises(FrozenInstanceError):
        behavior.action = "write"  # type: ignore[misc]
    with pytest.raises(ValueError) as exc_tool:
        AgentBehavior(agent=agent, tool_name="", action="read", target="", payload_summary="")
    assert str(exc_tool.value) == "tool_name 不可為空"
    with pytest.raises(ValueError) as exc_action:
        AgentBehavior(agent=agent, tool_name="shell", action="", target="", payload_summary="")
    assert str(exc_action.value) == "action 不可為空"
    with pytest.raises(ValueError) as exc_trace:
        AgentBehavior(
            agent=agent,
            tool_name="shell",
            action="read",
            target="",
            payload_summary="",
            trace_id="",
        )
    assert str(exc_trace.value) == "trace_id 不可為空"
    bad_metadata: dict[str, MetadataValue | object] = {"bad": object()}
    with pytest.raises(ValueError) as exc_metadata_value:
        AgentBehavior(
            agent=agent,
            tool_name="shell",
            action="read",
            target="",
            payload_summary="",
            metadata=bad_metadata,  # type: ignore[arg-type]
        )
    assert str(exc_metadata_value.value).startswith("metadata 值型別不支援: bad=")
    with pytest.raises(ValueError) as exc_metadata_key:
        AgentBehavior(
            agent=agent,
            tool_name="shell",
            action="read",
            target="",
            payload_summary="",
            metadata={"": "x"},
        )
    assert str(exc_metadata_key.value) == "metadata key 不可為空"


def test_rule_definition_validation() -> None:
    rule = AtrRuleDefinition(
        code=ThreatCode.T002,
        category="Sensitive File Access",
        weight=75,
        risk_category="sensitive_file_access",
        description="讀敏感檔案",
    )
    assert not hasattr(rule, "__dict__")
    with pytest.raises(FrozenInstanceError):
        rule.weight = 80  # type: ignore[misc]
    with pytest.raises(ValueError) as exc_category:
        AtrRuleDefinition(ThreatCode.T002, "", 75, "risk", "desc")
    assert str(exc_category.value) == "category 不可為空"
    with pytest.raises(ValueError) as exc:
        AtrRuleDefinition(ThreatCode.T002, "cat", 101, "risk", "desc")
    assert str(exc.value) == "weight 必須在 0-100 之間: 101"
    with pytest.raises(ValueError) as exc_risk_category:
        AtrRuleDefinition(ThreatCode.T002, "cat", 75, "", "desc")
    assert str(exc_risk_category.value) == "risk_category 不可為空"
    with pytest.raises(ValueError) as exc_description:
        AtrRuleDefinition(ThreatCode.T002, "cat", 75, "risk", "")
    assert str(exc_description.value) == "description 不可為空"
    with pytest.raises(ValueError) as exc2:
        AtrRuleDefinition(ThreatCode.T002, "cat", 75, "risk", "desc", version=0)
    assert str(exc2.value) == "version 必須 >= 1: 0"


def _score(value: int = 75, level: ThreatLevel = ThreatLevel.HIGH) -> ThreatScore:
    return ThreatScore(
        value=value,
        level=level,
        triggered_rules=(
            TriggeredRule(
                code=ThreatCode.T002,
                category="Sensitive File Access",
                weight=75,
                risk_category="sensitive_file_access",
            ),
        ),
        context_multiplier=1.0,
        agent_id="agent-1",
        tenant_id="stanley",
        risk_category="sensitive_file_access",
        trace_id="trace-1",
        timestamp=datetime(2026, 6, 22, tzinfo=UTC),
    )


def test_threat_score_validation_and_triggered_codes() -> None:
    score = _score()
    assert score.triggered_codes == (ThreatCode.T002,)
    with pytest.raises(FrozenInstanceError):
        score.value = 76  # type: ignore[misc]
    with pytest.raises(ValueError) as exc0:
        ThreatScore(
            value=101,
            level=ThreatLevel.CRITICAL,
            triggered_rules=(),
            context_multiplier=1.0,
            agent_id="agent-1",
            tenant_id="stanley",
            risk_category="safe",
            trace_id="trace-1",
        )
    assert str(exc0.value) == "value 必須在 0-100 之間: 101"
    with pytest.raises(ValueError) as exc:
        ThreatScore(
            value=75,
            level=ThreatLevel.LOW,
            triggered_rules=(),
            context_multiplier=1.0,
            agent_id="agent-1",
            tenant_id="stanley",
            risk_category="safe",
            trace_id="trace-1",
        )
    assert str(exc.value) == "level 與 value 不一致: low / 75"
    with pytest.raises(ValueError) as exc2:
        ThreatScore(
            value=0,
            level=ThreatLevel.SAFE,
            triggered_rules=(),
            context_multiplier=0.9,
            agent_id="agent-1",
            tenant_id="stanley",
            risk_category="safe",
            trace_id="trace-1",
        )
    assert str(exc2.value) == "context_multiplier 必須 >= 1.0: 0.9"
    with pytest.raises(ValueError) as exc_agent_id:
        ThreatScore(0, ThreatLevel.SAFE, (), 1.0, "", "stanley", "safe", "trace-1")
    assert str(exc_agent_id.value) == "agent_id 不可為空"
    with pytest.raises(ValueError) as exc_tenant_id:
        ThreatScore(0, ThreatLevel.SAFE, (), 1.0, "agent-1", "", "safe", "trace-1")
    assert str(exc_tenant_id.value) == "tenant_id 不可為空"
    with pytest.raises(ValueError) as exc_risk_category_empty:
        ThreatScore(0, ThreatLevel.SAFE, (), 1.0, "agent-1", "stanley", "", "trace-1")
    assert str(exc_risk_category_empty.value) == "risk_category 不可為空"
    with pytest.raises(ValueError) as exc_trace_id:
        ThreatScore(0, ThreatLevel.SAFE, (), 1.0, "agent-1", "stanley", "safe", "")
    assert str(exc_trace_id.value) == "trace_id 不可為空"
    with pytest.raises(ValueError) as exc_timestamp:
        ThreatScore(
            0,
            ThreatLevel.SAFE,
            (),
            1.0,
            "agent-1",
            "stanley",
            "safe",
            "trace-1",
            datetime(2026, 6, 22),
        )
    assert str(exc_timestamp.value) == "timestamp 必須是 tz-aware 時間"


def test_atr_decision_validation_and_audit_metadata() -> None:
    decision = AtrDecision(
        score=_score(),
        action=AtrAction.SUSPEND,
        audit_required=True,
        encrypt_trace=True,
        suspend_agent=True,
        terminate_session=False,
        notify_security_officer=True,
        requires_human_approval=False,
        decision_id="DEC-001",
    )
    with pytest.raises(FrozenInstanceError):
        decision.action = AtrAction.ALLOW  # type: ignore[misc]
    assert decision.to_audit_metadata() == {
        "decision_id": "DEC-001",
        "risk_score": 75,
        "risk_category": "sensitive_file_access",
        "threat_level": "high",
        "atr_action": "suspend",
        "triggered_rules": ["T002"],
        "trace_id": "trace-1",
    }
    with pytest.raises(ValueError) as exc_allow_encrypt:
        AtrDecision(
            _score(0, ThreatLevel.SAFE), AtrAction.ALLOW, True, True, False, False, False, False
        )
    assert str(exc_allow_encrypt.value) == "ALLOW 不可同時要求加密/暫停/終止"
    with pytest.raises(ValueError) as exc_allow_suspend:
        AtrDecision(
            _score(0, ThreatLevel.SAFE), AtrAction.ALLOW, True, False, True, False, False, False
        )
    assert str(exc_allow_suspend.value) == "ALLOW 不可同時要求加密/暫停/終止"
    with pytest.raises(ValueError) as exc_allow_terminate:
        AtrDecision(
            _score(0, ThreatLevel.SAFE), AtrAction.ALLOW, True, False, False, True, False, True
        )
    assert str(exc_allow_terminate.value) == "ALLOW 不可同時要求加密/暫停/終止"
    with pytest.raises(ValueError) as exc_suspend:
        AtrDecision(_score(), AtrAction.SUSPEND, True, True, False, False, True, False)
    assert str(exc_suspend.value) == "SUSPEND 決策必須 suspend_agent=True"
    with pytest.raises(ValueError) as exc_terminate:
        AtrDecision(
            _score(90, ThreatLevel.CRITICAL),
            AtrAction.TERMINATE,
            True,
            True,
            True,
            False,
            True,
            True,
        )
    assert str(exc_terminate.value) == "TERMINATE 決策必須 terminate_session=True"
    with pytest.raises(ValueError) as exc_human:
        AtrDecision(
            _score(90, ThreatLevel.CRITICAL),
            AtrAction.TERMINATE,
            True,
            True,
            True,
            True,
            True,
            False,
        )
    assert str(exc_human.value) == "終止 Session 必須要求人類審批"
    with pytest.raises(ValueError) as exc_decision_id:
        AtrDecision(
            _score(), AtrAction.SUSPEND, True, True, True, False, True, False, decision_id=""
        )
    assert str(exc_decision_id.value) == "decision_id 不可為空"


def test_suppression_rule_validation() -> None:
    rule = SuppressionRule(
        suppression_id="SUP-1",
        tenant_id="stanley",
        threat_code=ThreatCode.T005,
        reason="測試",
        approved_by="security",
    )
    assert not hasattr(rule, "__dict__")
    with pytest.raises(FrozenInstanceError):
        rule.reason = "改寫"  # type: ignore[misc]
    with pytest.raises(ValueError) as exc_suppression_id:
        SuppressionRule("", "stanley", ThreatCode.T005, "reason", "security")
    assert str(exc_suppression_id.value) == "suppression_id 不可為空"
    with pytest.raises(ValueError) as exc_suppression_tenant:
        SuppressionRule("SUP-1", "", ThreatCode.T005, "reason", "security")
    assert str(exc_suppression_tenant.value) == "tenant_id 不可為空"
    with pytest.raises(ValueError) as exc_reason:
        SuppressionRule("SUP-1", "stanley", ThreatCode.T005, "", "security")
    assert str(exc_reason.value) == "reason 不可為空"
    with pytest.raises(ValueError) as exc_approved_by:
        SuppressionRule("SUP-1", "stanley", ThreatCode.T005, "reason", "")
    assert str(exc_approved_by.value) == "approved_by 不可為空"
    with pytest.raises(ValueError) as exc:
        SuppressionRule("SUP-1", "stanley", ThreatCode.T005, "reason", "security", 2)
    assert str(exc.value) == "max_level_reduction 必須為 0 或 1: 2"
