"""AbacEvaluator 衝突解析測試（DENY > REQUIRE_APPROVAL > ALLOW；無命中 deny）。"""

from __future__ import annotations

from src.governance.abac.decisions import AbacEffect
from src.governance.abac.evaluator import AbacEvaluator
from src.governance.abac.policy import Condition, Operator, PolicyRule

from tests.governance.abac.conftest import make_request


def _rule(policy_id: str, effect: AbacEffect, *, attr: str, value: str) -> PolicyRule:
    return PolicyRule(
        policy_id=policy_id,
        effect=effect,
        target=(Condition(attr, Operator.EQ, value),),
        description=f"{policy_id}-理由",
    )


def test_no_policies_denies_by_default() -> None:
    decision = AbacEvaluator([]).evaluate(make_request())
    assert decision.effect is AbacEffect.DENY
    assert decision.matched_policy is None
    assert decision.reason == "無政策命中 → deny-by-default"


def test_no_matching_policy_denies_by_default() -> None:
    # 政策針對 department=risk，但請求是 trading → 不命中 → 預設拒絕
    evaluator = AbacEvaluator([_rule("p", AbacEffect.ALLOW, attr="department", value="risk")])
    decision = evaluator.evaluate(make_request(department="trading"))
    assert decision.effect is AbacEffect.DENY
    assert decision.matched_policy is None


def test_single_allow_match() -> None:
    evaluator = AbacEvaluator(
        [_rule("allow-p", AbacEffect.ALLOW, attr="department", value="trading")]
    )
    decision = evaluator.evaluate(make_request(department="trading"))
    assert decision.effect is AbacEffect.ALLOW
    assert decision.matched_policy == "allow-p"
    assert decision.reason == "allow-p-理由"


def test_single_deny_match() -> None:
    evaluator = AbacEvaluator(
        [_rule("deny-p", AbacEffect.DENY, attr="department", value="trading")]
    )
    decision = evaluator.evaluate(make_request(department="trading"))
    assert decision.effect is AbacEffect.DENY
    assert decision.matched_policy == "deny-p"


def test_single_approval_match() -> None:
    rule = _rule("appr-p", AbacEffect.REQUIRE_APPROVAL, attr="department", value="trading")
    decision = AbacEvaluator([rule]).evaluate(make_request(department="trading"))
    assert decision.effect is AbacEffect.REQUIRE_APPROVAL
    assert decision.matched_policy == "appr-p"


def test_deny_overrides_approval_and_allow() -> None:
    # 三條都命中（同 department）→ deny 必須勝出
    rules = [
        _rule("a", AbacEffect.ALLOW, attr="department", value="trading"),
        _rule("b", AbacEffect.REQUIRE_APPROVAL, attr="department", value="trading"),
        _rule("c", AbacEffect.DENY, attr="department", value="trading"),
    ]
    decision = AbacEvaluator(rules).evaluate(make_request(department="trading"))
    assert decision.effect is AbacEffect.DENY
    assert decision.matched_policy == "c"


def test_approval_overrides_allow_when_no_deny() -> None:
    rules = [
        _rule("a", AbacEffect.ALLOW, attr="department", value="trading"),
        _rule("b", AbacEffect.REQUIRE_APPROVAL, attr="department", value="trading"),
    ]
    decision = AbacEvaluator(rules).evaluate(make_request(department="trading"))
    assert decision.effect is AbacEffect.REQUIRE_APPROVAL
    assert decision.matched_policy == "b"
