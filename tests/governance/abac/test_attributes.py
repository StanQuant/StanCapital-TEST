"""AccessRequest 建構與驗證測試。"""

from __future__ import annotations

import dataclasses

import pytest
from src.governance.abac.attributes import MAX_SENSITIVITY, MIN_SENSITIVITY
from src.governance.rbac.permissions import Action, Resource
from src.governance.rbac.roles import Role

from tests.governance.abac.conftest import make_request


def test_valid_request_holds_all_attributes() -> None:
    req = make_request()
    assert req.user_id == "USR-001"
    assert req.tenant_id == "stanley"
    assert req.role is Role.MANAGER
    assert req.department == "trading"
    assert req.region == "taiwan"
    assert req.project == "alpha"
    assert req.sensitivity_level == 2
    assert req.risk_category == "normal"
    assert req.requested_resource is Resource.ORDER
    assert req.requested_action is Action.WRITE


@pytest.mark.parametrize("level", [MIN_SENSITIVITY, MAX_SENSITIVITY])
def test_sensitivity_boundaries_are_valid(level: int) -> None:
    assert make_request(sensitivity_level=level).sensitivity_level == level


@pytest.mark.parametrize("level", [MIN_SENSITIVITY - 1, MAX_SENSITIVITY + 1, -5, 99])
def test_sensitivity_out_of_range_rejected(level: int) -> None:
    # 訊息完全相等(含內插的 level)：殺 XX 包裹變異(S05 套路)
    with pytest.raises(ValueError) as excinfo:
        make_request(sensitivity_level=level)
    assert str(excinfo.value) == f"sensitivity_level 必須在 1-5: {level}"


def test_empty_tenant_id_rejected() -> None:
    with pytest.raises(ValueError) as excinfo:
        make_request(tenant_id="")
    assert str(excinfo.value) == "tenant_id 不可為空"


def test_empty_user_id_rejected() -> None:
    with pytest.raises(ValueError) as excinfo:
        make_request(user_id="")
    assert str(excinfo.value) == "user_id 不可為空"


def test_optional_string_attributes_allow_empty() -> None:
    req = make_request(department="", region="", project="", risk_category="")
    assert req.department == ""
    assert req.region == ""
    assert req.project == ""
    assert req.risk_category == ""


def test_request_is_frozen_with_slots() -> None:
    req = make_request()
    with pytest.raises(dataclasses.FrozenInstanceError):
        req.department = "other"  # type: ignore[misc]
    assert not hasattr(req, "__dict__")  # slots=True：殺 slots 變異
