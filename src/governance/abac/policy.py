"""L11 ABAC 政策模型 · Condition / PolicyRule + 純函式 matches。

政策 = 一組「條件」(target)全部成立(AND)時，套用一個 effect。
matches 是純函式(不碰 DB、無副作用)，方便單元測試與 mutation 殺手測試。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from src.governance.abac.attributes import AccessRequest
from src.governance.abac.decisions import AbacEffect

# 條件值的型別：純量(eq/ne/gte/lte)或值集合(in)
ConditionValue = str | int | tuple[str | int, ...]


class Operator(StrEnum):
    """條件運算子。值同時當 DSL 的 op 字面值(YAML 可讀)。

    gte/lte 僅用於數值屬性(由 DSL 載入器強制)；in 的右運算元必為值集合。
    """

    EQ = "eq"
    NE = "ne"
    IN = "in"
    GTE = "gte"
    LTE = "lte"


@dataclass(frozen=True, slots=True)
class Condition:
    """單一屬性的比對條件。attribute 必為 AccessRequest 的合法欄位名。"""

    attribute: str
    operator: Operator
    value: ConditionValue


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """一條政策 · target 全部條件成立(AND)時，結論為 effect。"""

    policy_id: str
    effect: AbacEffect
    target: tuple[Condition, ...]
    description: str


def _matches_condition(condition: Condition, request: AccessRequest) -> bool:
    """單一條件是否成立。attribute 由 DSL 保證合法，此處 getattr 安全。"""
    actual = getattr(request, condition.attribute)
    operator = condition.operator
    value = condition.value
    if operator is Operator.EQ:
        return bool(actual == value)
    if operator is Operator.NE:
        return bool(actual != value)
    if operator is Operator.IN:
        # DSL 保證 in 的 value 為 tuple；StrEnum 成員即字串故成員測試直觀
        return actual in cast("tuple[str | int, ...]", value)
    if operator is Operator.GTE:
        return bool(actual >= value)
    # LTE(列舉只有五種運算子，此為最後一種)
    return bool(actual <= value)


def matches(rule: PolicyRule, request: AccessRequest) -> bool:
    """政策是否命中：target 內所有條件都成立才算命中(AND 語義)。

    空 target 視為「無條件命中」，但 DSL 載入器要求 target 非空，
    避免不小心寫出 match-all 政策(catch-all 由評估器的 deny-by-default 負責)。
    """
    return all(_matches_condition(condition, request) for condition in rule.target)
