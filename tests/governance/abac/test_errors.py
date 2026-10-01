"""ABAC 錯誤型別測試（階層 + ApprovalRequiredError 結構化欄位）。"""

from __future__ import annotations

from src.governance.abac.errors import AbacError, ApprovalRequiredError, PolicyLoadError
from src.governance.rbac.permissions import Action, Resource


def test_policy_load_error_is_abac_and_value_error() -> None:
    err = PolicyLoadError("壞政策")
    assert isinstance(err, AbacError)
    assert isinstance(err, ValueError)


def test_approval_required_error_carries_structured_fields() -> None:
    err = ApprovalRequiredError(
        tenant_id="stanley",
        user_id="USR-001",
        resource=Resource.ORDER,
        action=Action.WRITE,
        matched_policy="approval-high-sensitivity-write",
        reason="敏感度 4 需審批",
    )
    assert isinstance(err, AbacError)
    assert err.tenant_id == "stanley"
    assert err.user_id == "USR-001"
    assert err.resource is Resource.ORDER
    assert err.action is Action.WRITE
    assert err.matched_policy == "approval-high-sensitivity-write"
    assert err.reason == "敏感度 4 需審批"
    # 訊息含關鍵欄位，S22 不需也能讀懂
    message = str(err)
    assert "order:write" in message
    assert "approval-high-sensitivity-write" in message
    assert "敏感度 4 需審批" in message


def test_approval_required_error_allows_none_policy() -> None:
    err = ApprovalRequiredError(
        tenant_id="t",
        user_id="u",
        resource=Resource.TRADE,
        action=Action.DELETE,
        matched_policy=None,
        reason="r",
    )
    assert err.matched_policy is None
