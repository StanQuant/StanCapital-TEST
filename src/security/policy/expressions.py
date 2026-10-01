"""安全 expression AST interpreter。

S08 禁止用 Python eval / exec。這裡只借用 Python AST 當 parser，
再用白名單節點手寫 interpreter，避免政策字串取得任意執行能力。
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

from src.security.policy.errors import PolicyEvaluationError, PolicyExpressionError

if TYPE_CHECKING:
    from src.security.policy.types import PolicyRequest

type Scalar = str | int | bool | None
type ExpressionValue = Scalar | tuple[Scalar, ...]

_ALLOWED_NAMES = frozenset(
    {
        "tenant_id",
        "subject_id",
        "subject_type",
        "department",
        "project",
        "agent_id",
        "action",
        "resource_type",
        "resource_id",
        "sensitivity_level",
        "risk_category",
        "trace_id",
        "subject",
        "resource",
        "atr",
    }
)


@dataclass(frozen=True, slots=True)
class PolicyExpression:
    """已驗證的政策 expression。"""

    source: str
    tree: ast.Expression = field(repr=False, compare=False)
    referenced_paths: frozenset[str]


def compile_expression(source: str) -> PolicyExpression:
    """把 expression 解析成安全 AST。"""
    if not source.strip():
        raise PolicyExpressionError("expression 不可為空")
    try:
        tree = ast.parse(source, mode="eval")
    except SyntaxError as exc:
        raise PolicyExpressionError(f"expression 語法錯誤: {source}") from exc
    paths: set[str] = set()
    _validate_node(tree.body, paths)
    return PolicyExpression(source=source, tree=tree, referenced_paths=frozenset(paths))


def evaluate_expression(expression: PolicyExpression, request: PolicyRequest) -> bool:
    """評估 expression；任何不支援或缺欄位都拋錯，交由 evaluator fail-closed。"""
    value = _eval_node(expression.tree.body, _context_from_request(request))
    if not isinstance(value, bool):
        raise PolicyEvaluationError(f"expression 必須回傳 bool: {expression.source}")
    return value


def _validate_node(node: ast.AST, paths: set[str]) -> None:
    if isinstance(node, ast.BoolOp):
        if not isinstance(node.op, ast.And | ast.Or):
            raise PolicyExpressionError("只支援 and / or")
        for value in node.values:
            _validate_node(value, paths)
        return
    if isinstance(node, ast.UnaryOp):
        if not isinstance(node.op, ast.Not):
            raise PolicyExpressionError("只支援 not 一元運算")
        _validate_node(node.operand, paths)
        return
    if isinstance(node, ast.Compare):
        _validate_node(node.left, paths)
        for operator in node.ops:
            if not isinstance(
                operator,
                ast.Eq | ast.NotEq | ast.Lt | ast.LtE | ast.Gt | ast.GtE | ast.In | ast.NotIn,
            ):
                raise PolicyExpressionError("只支援比較與 in / not in")
        for comparator in node.comparators:
            _validate_node(comparator, paths)
        return
    if isinstance(node, ast.Name):
        if node.id not in _ALLOWED_NAMES:
            raise PolicyExpressionError(f"未知 expression 名稱: {node.id}")
        paths.add(node.id)
        return
    if isinstance(node, ast.Attribute):
        paths.add(_attribute_path(node))
        return
    if isinstance(node, ast.Constant):
        if not isinstance(node.value, str | int | bool | None):
            raise PolicyExpressionError(f"不支援的常數型別: {node.value!r}")
        return
    if isinstance(node, ast.List | ast.Tuple):
        if not node.elts:
            raise PolicyExpressionError("集合常數不可為空")
        for element in node.elts:
            if not isinstance(element, ast.Constant) or not isinstance(
                element.value, str | int | bool | None
            ):
                raise PolicyExpressionError("集合常數只能包含 string / int / bool / null")
        return
    raise PolicyExpressionError(f"不支援的 expression 節點: {type(node).__name__}")


def _attribute_path(node: ast.Attribute) -> str:
    parts: list[str] = [node.attr]
    current = node.value
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name) or current.id not in _ALLOWED_NAMES:
        raise PolicyExpressionError("attribute path 必須從合法名稱開始")
    parts.append(current.id)
    return ".".join(reversed(parts))


def _context_from_request(request: PolicyRequest) -> dict[str, Any]:
    return {
        "tenant_id": request.tenant_id,
        "subject_id": request.subject_id,
        "subject_type": request.subject_type,
        "department": request.department,
        "project": request.project,
        "agent_id": request.agent_id,
        "action": request.action,
        "resource_type": request.resource_type,
        "resource_id": request.resource_id,
        "sensitivity_level": request.sensitivity_level,
        "risk_category": request.risk_category,
        "trace_id": request.trace_id,
        "subject": {
            "id": request.subject_id,
            "type": request.subject_type,
            "department": request.department,
            "project": request.project,
            "agent_id": request.agent_id,
        },
        "resource": {
            "type": request.resource_type,
            "id": request.resource_id,
            "sensitivity_level": request.sensitivity_level,
            "risk_category": request.risk_category,
        },
        "atr": {
            "risk_score": request.atr_risk_score,
            "risk_category": request.atr_risk_category,
        },
    }


def _eval_node(node: ast.AST, context: dict[str, Any]) -> ExpressionValue:
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            return all(bool(_eval_node(value, context)) for value in node.values)
        return any(bool(_eval_node(value, context)) for value in node.values)
    if isinstance(node, ast.UnaryOp):
        return not bool(_eval_node(node.operand, context))
    if isinstance(node, ast.Compare):
        return _eval_compare(node, context)
    if isinstance(node, ast.Name):
        return cast("ExpressionValue", context[node.id])
    if isinstance(node, ast.Attribute):
        return _resolve_path(_attribute_path(node), context)
    if isinstance(node, ast.Constant):
        return cast("Scalar", node.value)
    if isinstance(node, ast.List | ast.Tuple):
        return tuple(cast("Scalar", element.value) for element in node.elts)  # type: ignore[attr-defined]
    raise PolicyEvaluationError(f"不支援的 expression 節點: {type(node).__name__}")


def _resolve_path(path: str, context: dict[str, Any]) -> ExpressionValue:
    current: Any = context
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise PolicyEvaluationError(f"expression 欄位不存在: {path}")
        current = current[part]
    if current is None:
        raise PolicyEvaluationError(f"expression 欄位缺值: {path}")
    if isinstance(current, list):
        return tuple(cast("Scalar", item) for item in current)
    if not isinstance(current, str | int | bool | tuple):
        raise PolicyEvaluationError(f"expression 欄位型別不支援: {path}")
    return cast("ExpressionValue", current)


def _eval_compare(node: ast.Compare, context: dict[str, Any]) -> bool:
    left = _eval_node(node.left, context)
    for operator, comparator in zip(node.ops, node.comparators, strict=True):
        right = _eval_node(comparator, context)
        if not _compare(left, operator, right):
            return False
        left = right
    return True


def _compare(left: ExpressionValue, operator: ast.cmpop, right: ExpressionValue) -> bool:
    try:
        if isinstance(operator, ast.Eq):
            return left == right
        if isinstance(operator, ast.NotEq):
            return left != right
        if isinstance(operator, ast.Lt):
            return bool(left < right)  # type: ignore[operator]
        if isinstance(operator, ast.LtE):
            return bool(left <= right)  # type: ignore[operator]
        if isinstance(operator, ast.Gt):
            return bool(left > right)  # type: ignore[operator]
        if isinstance(operator, ast.GtE):
            return bool(left >= right)  # type: ignore[operator]
        if isinstance(operator, ast.In):
            return left in cast("tuple[Scalar, ...]", right)
        if isinstance(operator, ast.NotIn):
            return left not in cast("tuple[Scalar, ...]", right)
    except TypeError as exc:
        raise PolicyEvaluationError("expression 比較型別不相容") from exc
    raise PolicyEvaluationError("不支援的比較運算")
