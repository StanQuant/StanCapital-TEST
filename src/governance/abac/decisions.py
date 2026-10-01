"""L11 ABAC 決策型別 · 三態結論 + 決策結果值物件。

為什麼是三態(不是 RBAC 的二元)：RBAC 只答「能/不能」；ABAC 多一個
require_approval(敏感但非絕對禁止的灰色地帶)——動作先擋住、丟去人工/HITL 審批。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class AbacEffect(StrEnum):
    """ABAC 決策三態。值同時當 DSL 政策的 effect 字面值(YAML 可讀)。"""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True, slots=True)
class AbacDecision:
    """一次 ABAC 評估的結論(frozen + slots 值物件，與 L4/RBAC 同紀律)。

    matched_policy 為命中的政策 id(deny-by-default 時為 None)；
    reason 為人類可讀理由，直接寫進稽核與除錯日誌。
    """

    effect: AbacEffect
    matched_policy: str | None
    reason: str
