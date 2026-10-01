"""L11 ABAC 子層 · 屬性式存取控制(S06 切片產出)。

RBAC 看「角色」、ABAC 看「情境屬性」(部門/區域/專案/敏感度/風險類別)。
RBAC 先過 → ABAC 細審，回 Allow / Deny / RequireApproval 三態。
對外匯出常用名稱，呼叫端不用記內部檔案位置。
"""

from src.governance.abac.attributes import AccessRequest
from src.governance.abac.decisions import AbacDecision, AbacEffect
from src.governance.abac.dsl import load_policies, parse_policies
from src.governance.abac.errors import AbacError, ApprovalRequiredError, PolicyLoadError
from src.governance.abac.evaluator import AbacEvaluator
from src.governance.abac.policy import Condition, Operator, PolicyRule, matches

__all__ = [
    "AbacDecision",
    "AbacEffect",
    "AbacError",
    "AbacEvaluator",
    "AccessRequest",
    "ApprovalRequiredError",
    "Condition",
    "Operator",
    "PolicyLoadError",
    "PolicyRule",
    "load_policies",
    "matches",
    "parse_policies",
]
