"""L11 ABAC 評估器 · AccessRequest → AbacDecision(業務邏輯核心)。

衝突解析(D5)：多條政策同時命中時，依固定優先級
DENY > REQUIRE_APPROVAL > ALLOW(deny-overrides，業界 XACML 標準)。
完全無政策命中 → DENY(deny-by-default，fail-closed，對齊 RBAC 與
Stanley「安全疑慮一律 fail-closed」總原則)。

純評估(無 DB)：對應 RBACChecker.effective_permissions 的純淨設計，
保住 Charter §14.2 的 < 5ms 預算(ABAC 不新增任何資料庫往返)。
"""

from __future__ import annotations

from collections.abc import Iterable

from src.governance.abac.attributes import AccessRequest
from src.governance.abac.decisions import AbacDecision, AbacEffect
from src.governance.abac.policy import PolicyRule, matches

# 衝突解析優先級：愈前面愈優先(deny 壓過 approval 壓過 allow)
_PRIORITY: tuple[AbacEffect, ...] = (
    AbacEffect.DENY,
    AbacEffect.REQUIRE_APPROVAL,
    AbacEffect.ALLOW,
)

_NO_MATCH_REASON = "無政策命中 → deny-by-default"


class AbacEvaluator:
    """ABAC 評估器。建構時注入一組已凍結的政策；評估為純記憶體運算。"""

    def __init__(self, policies: Iterable[PolicyRule]) -> None:
        self._policies = tuple(policies)

    def evaluate(self, request: AccessRequest) -> AbacDecision:
        """回傳三態決策。優先級 DENY > REQUIRE_APPROVAL > ALLOW；無命中 deny。"""
        matched = tuple(rule for rule in self._policies if matches(rule, request))
        for effect in _PRIORITY:
            hit = next((rule for rule in matched if rule.effect is effect), None)
            if hit is not None:
                return AbacDecision(
                    effect=hit.effect, matched_policy=hit.policy_id, reason=hit.description
                )
        return AbacDecision(effect=AbacEffect.DENY, matched_policy=None, reason=_NO_MATCH_REASON)
