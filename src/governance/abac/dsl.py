"""L11 ABAC Policy DSL · YAML 政策檔解析 + 嚴格驗證(D1)。

D1 裁定：基底政策寫 YAML(法遵可讀、版控)；租戶覆寫存 DB 但只能加嚴
(S06 交付 base-only，覆寫合併留給 S26——屆時把基底 + 租戶政策合成一個清單
餵給 AbacEvaluator 即可，evaluator 不需改)。

fail-closed：政策檔任何欄位不合法 → 拋 PolicyLoadError，啟動就炸，
絕不帶半套政策上線(壞政策 = 門禁破洞)。
"""

from __future__ import annotations

from dataclasses import fields
from pathlib import Path
from typing import Any

import yaml

from src.governance.abac.attributes import AccessRequest
from src.governance.abac.decisions import AbacEffect
from src.governance.abac.errors import PolicyLoadError
from src.governance.abac.policy import Condition, ConditionValue, Operator, PolicyRule

# AccessRequest 的合法屬性名(政策只能比對這些欄位)
_KNOWN_ATTRIBUTES: frozenset[str] = frozenset(f.name for f in fields(AccessRequest))
# 可用於 gte/lte 的數值屬性
_NUMERIC_ATTRIBUTES: frozenset[str] = frozenset({"sensitivity_level"})


def parse_policies(text: str) -> tuple[PolicyRule, ...]:
    """解析 YAML 文字成凍結政策物件(純函式，不讀檔，方便測試)。"""
    raw = yaml.safe_load(text)
    if not isinstance(raw, dict) or "policies" not in raw:
        raise PolicyLoadError("政策檔頂層必須是含 'policies' 鍵的對應")
    entries = raw["policies"]
    if not isinstance(entries, list):
        raise PolicyLoadError("'policies' 必須是清單")

    rules: list[PolicyRule] = []
    seen_ids: set[str] = set()
    for entry in entries:
        rule = _parse_rule(entry)
        if rule.policy_id in seen_ids:
            raise PolicyLoadError(f"政策 id 重複: {rule.policy_id}")
        seen_ids.add(rule.policy_id)
        rules.append(rule)
    return tuple(rules)


def load_policies(path: Path | str) -> tuple[PolicyRule, ...]:
    """從檔案載入政策。檔案讀取後交給 parse_policies。"""
    return parse_policies(Path(path).read_text(encoding="utf-8"))


def _parse_rule(entry: Any) -> PolicyRule:
    if not isinstance(entry, dict):
        raise PolicyLoadError(f"政策項目必須是對應: {entry!r}")
    policy_id = entry.get("id")
    if not isinstance(policy_id, str) or not policy_id:
        raise PolicyLoadError(f"政策缺少合法 id: {entry!r}")
    effect_raw = entry.get("effect")
    try:
        effect = AbacEffect(str(effect_raw))
    except ValueError:
        raise PolicyLoadError(f"政策 {policy_id} 使用未知 effect: {effect_raw!r}") from None
    description = entry.get("description", "")
    if not isinstance(description, str):
        raise PolicyLoadError(f"政策 {policy_id} 的 description 必須是字串")
    target_raw = entry.get("target")
    if not isinstance(target_raw, list) or not target_raw:
        raise PolicyLoadError(f"政策 {policy_id} 的 target 必須是非空清單")
    target = tuple(_parse_condition(item, policy_id) for item in target_raw)
    return PolicyRule(policy_id=policy_id, effect=effect, target=target, description=description)


def _parse_condition(raw: Any, policy_id: str) -> Condition:
    if not isinstance(raw, dict):
        raise PolicyLoadError(f"政策 {policy_id} 的 target 條件必須是對應")
    attribute = raw.get("attr")
    if attribute not in _KNOWN_ATTRIBUTES:
        raise PolicyLoadError(f"政策 {policy_id} 使用未知屬性: {attribute!r}")
    op_raw = raw.get("op")
    try:
        operator = Operator(str(op_raw))
    except ValueError:
        raise PolicyLoadError(f"政策 {policy_id} 使用未知運算子: {op_raw!r}") from None
    value = _parse_value(raw.get("value"), operator, attribute, policy_id)
    return Condition(attribute=attribute, operator=operator, value=value)


def _parse_value(value: Any, operator: Operator, attribute: str, policy_id: str) -> ConditionValue:
    if operator is Operator.IN:
        if not isinstance(value, list) or not value:
            raise PolicyLoadError(f"政策 {policy_id} 的 in value 必須是非空清單")
        return tuple(_require_scalar(item, operator, policy_id) for item in value)
    if operator in (Operator.GTE, Operator.LTE):
        if attribute not in _NUMERIC_ATTRIBUTES:
            raise PolicyLoadError(
                f"政策 {policy_id} 的 {operator.value} 只能用於數值屬性: {attribute}"
            )
        if not isinstance(value, int) or isinstance(value, bool):
            raise PolicyLoadError(f"政策 {policy_id} 的 {operator.value} value 必須是整數")
        return value
    # eq / ne
    return _require_scalar(value, operator, policy_id)


def _require_scalar(value: Any, operator: Operator, policy_id: str) -> str | int:
    if isinstance(value, bool) or not isinstance(value, str | int):
        raise PolicyLoadError(
            f"政策 {policy_id} 的 {operator.value} value 必須是字串或整數: {value!r}"
        )
    return value
