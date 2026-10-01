"""S04 · RBACChecker 警衛決策邏輯測試(假快照依賴注入)。

涵蓋：deny-by-default / 多角色聯集 / 覆寫合併公式 / fail-closed /
合併期防線(就算資料來源回傳非法覆寫也不生效) / 拒絕日誌逐字釘住。
"""

from __future__ import annotations

import dataclasses
import logging

import pytest
from sqlalchemy.exc import OperationalError
from src.governance.rbac.checker import RBACChecker, RbacDecision
from src.governance.rbac.errors import PermissionDeniedError, RBACUnavailableError
from src.governance.rbac.permissions import Action, Permission, Resource
from src.governance.rbac.roles import Role
from src.governance.rbac.types import (
    AccessSnapshot,
    OverrideEffect,
    PermissionOverride,
    User,
)

from tests.governance.conftest import make_override, make_user

# ============================================================================
# 假快照來源(依賴注入)
# ============================================================================


class FakeSnapshots:
    def __init__(self, snapshots: dict[tuple[str, str], AccessSnapshot] | None = None) -> None:
        self.snapshots = snapshots or {}

    async def load_access_snapshot(self, tenant_id: str, user_id: str) -> AccessSnapshot | None:
        return self.snapshots.get((tenant_id, user_id))


class BrokenSnapshots:
    """模擬資料來源掛掉(fail-closed 測試用)。"""

    def __init__(self, error: Exception) -> None:
        self.error = error

    async def load_access_snapshot(self, tenant_id: str, user_id: str) -> AccessSnapshot | None:
        raise self.error


def build_checker(
    *,
    roles: list[Role] | None = None,
    overrides: list[PermissionOverride] | None = None,
    user: User | None = None,
) -> RBACChecker:
    """標準場景：stanley 租戶 USR-001，可自訂角色與覆寫。"""
    snapshot = AccessSnapshot(
        user=user if user is not None else make_user(),
        roles=tuple(roles or []),
        overrides=tuple(overrides or []),
    )
    return RBACChecker(FakeSnapshots({("stanley", "USR-001"): snapshot}))


# ============================================================================
# 基本決策路徑
# ============================================================================


class TestBasicDecisions:
    async def test_allowed_by_matrix(self) -> None:
        checker = build_checker(roles=[Role.USER])
        assert await checker.check("stanley", "USR-001", Resource.ORDER, Action.WRITE) is True

    async def test_denied_by_matrix(self) -> None:
        checker = build_checker(roles=[Role.USER])
        assert await checker.check("stanley", "USR-001", Resource.USER, Action.MANAGE) is False

    async def test_unknown_user_denied(self) -> None:
        checker = build_checker(roles=[Role.OWNER])
        assert await checker.check("stanley", "ghost", Resource.ORDER, Action.READ) is False

    async def test_inactive_user_denied(self) -> None:
        checker = build_checker(roles=[Role.OWNER], user=make_user(is_active=False))
        assert await checker.check("stanley", "USR-001", Resource.ORDER, Action.READ) is False

    async def test_no_roles_denied(self) -> None:
        checker = build_checker(roles=[])
        assert await checker.check("stanley", "USR-001", Resource.ORDER, Action.READ) is False

    async def test_multi_role_union(self) -> None:
        """D2 聯集：法遵官不能下單，但兼 USER 角色就可以。"""
        compliance_only = build_checker(roles=[Role.COMPLIANCE_OFFICER])
        assert (
            await compliance_only.check("stanley", "USR-001", Resource.ORDER, Action.WRITE) is False
        )
        dual = build_checker(roles=[Role.COMPLIANCE_OFFICER, Role.USER])
        assert await dual.check("stanley", "USR-001", Resource.ORDER, Action.WRITE) is True

    async def test_agent_fence_demo_scenario(self) -> None:
        """DoD #12 Demo 場景：Agent 發訊號可以、呼叫 admin 資源被拒。"""
        checker = build_checker(roles=[Role.AGENT])
        assert await checker.check("stanley", "USR-001", Resource.STRATEGY, Action.WRITE) is True
        assert await checker.check("stanley", "USR-001", Resource.ORDER, Action.WRITE) is False
        assert await checker.check("stanley", "USR-001", Resource.USER, Action.MANAGE) is False


# ============================================================================
# require() 守門式 API
# ============================================================================


class TestRequire:
    async def test_require_passes_silently_when_allowed(self) -> None:
        checker = build_checker(roles=[Role.USER])
        await checker.require("stanley", "USR-001", Resource.ORDER, Action.WRITE)

    async def test_require_raises_with_structured_fields(self) -> None:
        checker = build_checker(roles=[Role.AGENT])
        with pytest.raises(PermissionDeniedError) as excinfo:
            await checker.require("stanley", "USR-001", Resource.USER, Action.MANAGE)
        error = excinfo.value
        assert error.tenant_id == "stanley"
        assert error.user_id == "USR-001"
        assert error.resource is Resource.USER
        assert error.action is Action.MANAGE
        assert error.roles == (Role.AGENT,)
        assert error.reason == "所有角色皆無此權限"

    @pytest.mark.parametrize(
        ("snapshot", "reason"),
        [
            (None, "使用者不存在"),
            (
                AccessSnapshot(user=make_user(is_active=False), roles=(Role.OWNER,), overrides=()),
                "使用者已停用",
            ),
            (AccessSnapshot(user=make_user(), roles=(), overrides=()), "未指派任何角色"),
        ],
    )
    async def test_require_reasons_exact(
        self, snapshot: AccessSnapshot | None, reason: str
    ) -> None:
        snapshots = FakeSnapshots({} if snapshot is None else {("stanley", "USR-001"): snapshot})
        checker = RBACChecker(snapshots)
        with pytest.raises(PermissionDeniedError) as excinfo:
            await checker.require("stanley", "USR-001", Resource.ORDER, Action.READ)
        assert excinfo.value.reason == reason
        assert excinfo.value.roles == ()


# ============================================================================
# 覆寫合併公式(D1)：(基底 ∪ 合法 grants) − revokes
# ============================================================================


class TestOverrideMerge:
    async def test_grant_extends_base(self) -> None:
        """USER 基底沒有 trade:write，LOW 風險 grant 後就有。"""
        checker = build_checker(
            roles=[Role.USER],
            overrides=[make_override(resource=Resource.TRADE, action=Action.WRITE)],
        )
        assert await checker.check("stanley", "USR-001", Resource.TRADE, Action.WRITE) is True

    async def test_revoke_removes_from_base(self) -> None:
        """USER 基底有 order:write，revoke 後沒有。"""
        checker = build_checker(
            roles=[Role.USER],
            overrides=[
                make_override(
                    resource=Resource.ORDER,
                    action=Action.WRITE,
                    effect=OverrideEffect.REVOKE,
                )
            ],
        )
        assert await checker.check("stanley", "USR-001", Resource.ORDER, Action.WRITE) is False
        # 同角色其他權限不受影響
        assert await checker.check("stanley", "USR-001", Resource.ORDER, Action.READ) is True

    async def test_revoke_is_per_role(self) -> None:
        """revoke 只削 USER 角色；兼任 MANAGER 仍可下單(逐角色語意)。"""
        checker = build_checker(
            roles=[Role.USER, Role.MANAGER],
            overrides=[
                make_override(
                    resource=Resource.ORDER,
                    action=Action.WRITE,
                    effect=OverrideEffect.REVOKE,
                )
            ],
        )
        assert await checker.check("stanley", "USR-001", Resource.ORDER, Action.WRITE) is True

    def test_effective_permissions_formula(self) -> None:
        """合併公式是純函式：(基底 ∪ grants) − revokes 逐集合驗證。"""
        checker = build_checker(roles=[Role.USER])
        grant = make_override(resource=Resource.TRADE, action=Action.WRITE)
        revoke = make_override(
            resource=Resource.ORDER,
            action=Action.WRITE,
            effect=OverrideEffect.REVOKE,
            override_id="OVR-R",
        )
        effective = checker.effective_permissions("stanley", Role.USER, [grant, revoke])
        base = checker.permissions_of(Role.USER)
        assert effective == (base | {Permission(Resource.TRADE, Action.WRITE)}) - {
            Permission(Resource.ORDER, Action.WRITE)
        }


# ============================================================================
# 合併期防線(D1 第三道)：非法覆寫不生效 + 警告
# ============================================================================


class TestMergeTimeGuards:
    async def test_high_risk_grant_ignored_with_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """惡意資料來源回傳 HIGH grant → 不生效 + 警告(繞過 frozen 驗證直造物件)。"""
        legal = make_override(resource=Resource.TRADE, action=Action.WRITE)
        illegal = dataclasses.replace(legal)
        object.__setattr__(illegal, "resource", Resource.USER)
        object.__setattr__(illegal, "action", Action.MANAGE)
        checker = build_checker(roles=[Role.USER], overrides=[illegal])
        with caplog.at_level(logging.WARNING, logger="src.governance.rbac.checker"):
            allowed = await checker.check("stanley", "USR-001", Resource.USER, Action.MANAGE)
        assert allowed is False
        guard_logs = [r for r in caplog.records if "合併期防線" in r.getMessage()]
        assert len(guard_logs) == 1
        assert guard_logs[0].getMessage() == (
            "忽略 HIGH 風險 grant 覆寫(合併期防線): tenant=stanley role=user 權限=user:manage"
        )

    async def test_owner_revoke_ignored_with_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """惡意資料來源回傳 OWNER 削權 → 不生效 + 警告，OWNER 仍全權限。"""
        legal = make_override(
            role=Role.MANAGER,
            resource=Resource.TRADE,
            action=Action.READ,
            effect=OverrideEffect.REVOKE,
        )
        illegal = dataclasses.replace(legal)
        object.__setattr__(illegal, "role", Role.OWNER)
        checker = build_checker(roles=[Role.OWNER], overrides=[illegal])
        with caplog.at_level(logging.WARNING, logger="src.governance.rbac.checker"):
            allowed = await checker.check("stanley", "USR-001", Resource.TRADE, Action.READ)
        assert allowed is True
        guard_logs = [r for r in caplog.records if "合併期防線" in r.getMessage()]
        assert len(guard_logs) == 1
        assert guard_logs[0].getMessage() == (
            "忽略 OWNER 削權覆寫(合併期防線): tenant=stanley 權限=trade:read"
        )

    async def test_illegal_grant_does_not_swallow_later_overrides(self) -> None:
        """非法 grant 被忽略後，後面的合法覆寫仍要生效(殺 continue→break 變異)。"""
        legal = make_override(resource=Resource.TRADE, action=Action.WRITE)
        illegal = dataclasses.replace(
            make_override(override_id="OVR-EVIL"),
        )
        object.__setattr__(illegal, "resource", Resource.USER)
        object.__setattr__(illegal, "action", Action.MANAGE)
        # 非法的排前面：若守門用 break，後面合法 grant 會被整批吞掉
        checker = build_checker(roles=[Role.USER], overrides=[illegal, legal])
        assert await checker.check("stanley", "USR-001", Resource.TRADE, Action.WRITE) is True

    async def test_owner_revoke_guard_processes_every_override(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """兩筆 OWNER 削權 → 兩條警告(殺 continue→break 變異：break 只會留一條)。"""
        first = make_override(
            role=Role.MANAGER,
            resource=Resource.TRADE,
            action=Action.READ,
            effect=OverrideEffect.REVOKE,
        )
        second = make_override(
            role=Role.MANAGER,
            resource=Resource.FILL,
            action=Action.READ,
            effect=OverrideEffect.REVOKE,
            override_id="OVR-2",
        )
        illegal_1 = dataclasses.replace(first)
        illegal_2 = dataclasses.replace(second)
        object.__setattr__(illegal_1, "role", Role.OWNER)
        object.__setattr__(illegal_2, "role", Role.OWNER)
        checker = build_checker(roles=[Role.OWNER], overrides=[illegal_1, illegal_2])
        with caplog.at_level(logging.WARNING, logger="src.governance.rbac.checker"):
            assert await checker.check("stanley", "USR-001", Resource.TRADE, Action.READ) is True
        guard_logs = [r for r in caplog.records if "合併期防線" in r.getMessage()]
        assert len(guard_logs) == 2


# ============================================================================
# fail-closed(D4)：資料來源掛掉 → 拋明確錯誤，絕不放行
# ============================================================================


class TestFailClosed:
    @pytest.mark.parametrize(
        "error",
        [
            OperationalError("SELECT 1", {}, OSError("connection refused")),
            OSError("network down"),
        ],
    )
    async def test_check_raises_unavailable(
        self, error: Exception, caplog: pytest.LogCaptureFixture
    ) -> None:
        checker = RBACChecker(BrokenSnapshots(error))
        with caplog.at_level(logging.ERROR, logger="src.governance.rbac.checker"):
            with pytest.raises(RBACUnavailableError) as excinfo:
                await checker.check("stanley", "USR-001", Resource.ORDER, Action.READ)
        assert str(excinfo.value) == "權限查核資料來源連不上，依 fail-closed 一律拒絕"
        assert excinfo.value.__cause__ is error
        assert len(caplog.records) == 1
        # 錯誤日誌文字也是行為(維運排障依賴，S02 教訓)，逐字釘住
        assert caplog.records[0].getMessage() == (
            f"RBAC 查核失敗(fail-closed 拒絕): tenant=stanley user=USR-001 原因={error}"
        )

    async def test_require_raises_unavailable(self) -> None:
        checker = RBACChecker(BrokenSnapshots(OSError("db is gone")))
        with pytest.raises(RBACUnavailableError):
            await checker.require("stanley", "USR-001", Resource.ORDER, Action.READ)


# ============================================================================
# 矩陣查詢 API 與 deny-by-default
# ============================================================================


class TestMatrixQueries:
    def test_permissions_of_uses_builtin_matrix(self) -> None:
        checker = build_checker(roles=[Role.AGENT])
        agent_base = checker.permissions_of(Role.AGENT)
        assert Permission(Resource.STRATEGY, Action.WRITE) in agent_base
        assert Permission(Resource.ORDER, Action.WRITE) not in agent_base

    async def test_custom_matrix_missing_role_is_deny_by_default(self) -> None:
        """注入的矩陣缺某角色 → 空集合 → 全拒絕(永遠不會「忘了設定就全開」)。"""
        custom = {Role.OWNER: frozenset({Permission(Resource.ORDER, Action.READ)})}
        snapshot = AccessSnapshot(user=make_user(), roles=(Role.AGENT,), overrides=())
        checker = RBACChecker(
            FakeSnapshots({("stanley", "USR-001"): snapshot}),
            role_permissions=custom,
        )
        assert checker.permissions_of(Role.AGENT) == frozenset()
        assert await checker.check("stanley", "USR-001", Resource.ORDER, Action.READ) is False


# ============================================================================
# 拒絕日誌(S05 稽核落地前的唯一痕跡)
# ============================================================================


class TestDenyLogging:
    async def test_deny_log_message_exact(self, caplog: pytest.LogCaptureFixture) -> None:
        checker = build_checker(roles=[Role.AGENT])
        with caplog.at_level(logging.WARNING, logger="src.governance.rbac.checker"):
            await checker.check("stanley", "USR-001", Resource.USER, Action.MANAGE)
        assert len(caplog.records) == 1
        assert caplog.records[0].getMessage() == (
            "權限拒絕: tenant=stanley user=USR-001 resource=user action=manage 原因=所有角色皆無此權限"
        )

    async def test_allow_emits_no_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        checker = build_checker(roles=[Role.USER])
        with caplog.at_level(logging.WARNING, logger="src.governance.rbac.checker"):
            await checker.check("stanley", "USR-001", Resource.ORDER, Action.WRITE)
        assert caplog.records == []


# ============================================================================
# 決策物件(白盒)：check/require 共用的 RbacDecision 也要釘住
# ============================================================================


class TestDecisionInternals:
    async def test_allow_decision_contents_exact(self) -> None:
        """允許路徑的決策內容逐欄位釘死(roles 帶齊、reason 為空字串)。"""
        checker = build_checker(roles=[Role.USER])
        decision = await checker._decide("stanley", "USR-001", Resource.ORDER, Action.WRITE)
        assert decision == RbacDecision(allowed=True, roles=(Role.USER,), reason="")

    def test_decision_frozen_with_slots(self) -> None:
        decision = RbacDecision(allowed=False, roles=(), reason="x")
        with pytest.raises(dataclasses.FrozenInstanceError):
            decision.allowed = True  # type: ignore[misc]
        assert not hasattr(decision, "__dict__")
