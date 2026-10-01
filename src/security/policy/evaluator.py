"""L10 Policy Evaluator · 純記憶體政策評估核心。"""

from __future__ import annotations

from collections.abc import Iterable

from src.security.policy.errors import PolicyEvaluationError
from src.security.policy.expressions import evaluate_expression
from src.security.policy.types import (
    PolicyDecision,
    PolicyEffect,
    PolicyRequest,
    PolicyRule,
    PolicySet,
)

_PRIORITY: tuple[PolicyEffect, ...] = (
    PolicyEffect.DENY,
    PolicyEffect.REQUIRE_APPROVAL,
    PolicyEffect.ALLOW,
)

_NO_MATCH_REASON = "無政策命中 → deny-by-default"


class PolicyEvaluator:
    """Policy 評估器。policy sets 已在建構前嚴格解析，評估時不碰 DB。"""

    def __init__(self, policy_sets: Iterable[PolicySet]) -> None:
        self._policy_sets = tuple(policy_sets)

    def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        """回傳三態決策；任何評估錯誤都 fail-closed 成 deny。"""
        try:
            matched = tuple(self._matched_rules(request))
        except PolicyEvaluationError as exc:
            return self._decision(
                request,
                effect=PolicyEffect.DENY,
                matched=(),
                reason=f"政策評估失敗 → fail-closed: {exc}",
            )
        for effect in _PRIORITY:
            chosen = tuple(item for item in matched if item[1].effect is effect)
            if chosen:
                return self._decision(
                    request,
                    effect=effect,
                    matched=matched,
                    reason=chosen[0][1].description,
                )
        return self._decision(
            request,
            effect=PolicyEffect.DENY,
            matched=(),
            reason=_NO_MATCH_REASON,
        )

    def _matched_rules(self, request: PolicyRequest) -> Iterable[tuple[PolicySet, PolicyRule]]:
        for policy_set in self._policy_sets:
            if not policy_set.scope.matches(request):
                continue
            for rule in policy_set.rules:
                if _rule_matches(rule, request):
                    yield policy_set, rule

    def _decision(
        self,
        request: PolicyRequest,
        *,
        effect: PolicyEffect,
        matched: tuple[tuple[PolicySet, PolicyRule], ...],
        reason: str,
    ) -> PolicyDecision:
        approval = next((rule.approval for _, rule in matched if rule.effect is effect), None)
        return PolicyDecision(
            tenant_id=request.tenant_id,
            effect=effect,
            matched_rule_ids=tuple(rule.rule_id for _, rule in matched),
            policy_set_ids=tuple(
                dict.fromkeys(policy_set.policy_set_id for policy_set, _ in matched)
            ),
            policy_versions=tuple(dict.fromkeys(policy_set.version for policy_set, _ in matched)),
            reason=reason,
            trace_id=request.trace_id,
            requires_approval=effect is PolicyEffect.REQUIRE_APPROVAL,
            audit_required=True,
            audit_mandatory=_audit_mandatory(request, effect),
            approval=approval,
        )


def _rule_matches(rule: PolicyRule, request: PolicyRequest) -> bool:
    all_match = all(evaluate_expression(expression, request) for expression in rule.all_expressions)
    any_match = True
    if rule.any_expressions:
        any_match = any(
            evaluate_expression(expression, request) for expression in rule.any_expressions
        )
    return all_match and any_match


def _audit_mandatory(request: PolicyRequest, effect: PolicyEffect) -> bool:
    if effect is not PolicyEffect.ALLOW:
        return True
    return (
        request.sensitivity_level >= 4
        or (request.atr_risk_score is not None and request.atr_risk_score >= 61)
        or request.action in {"submit_real_order", "external_upload"}
    )
