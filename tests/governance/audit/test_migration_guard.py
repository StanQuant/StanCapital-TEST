"""S05 Batch 6b · 稽核 migration 降級防呆測試(fail-closed)。"""

from __future__ import annotations

import pytest
from src.governance.audit.migration_guard import (
    AUDIT_DOWNGRADE_ENV,
    AuditDowngradeForbiddenError,
    require_audit_downgrade_allowed,
)

# ============================================================================
# 預設禁止(注入空 / 不被認可的開關值)
# ============================================================================


def test_blocks_when_env_absent() -> None:
    with pytest.raises(AuditDowngradeForbiddenError, match=AUDIT_DOWNGRADE_ENV):
        require_audit_downgrade_allowed(env={})


@pytest.mark.parametrize("value", ["0", "false", "no", "", "  ", "maybe"])
def test_blocks_on_unrecognized_value(value: str) -> None:
    with pytest.raises(AuditDowngradeForbiddenError):
        require_audit_downgrade_allowed(env={AUDIT_DOWNGRADE_ENV: value})


# ============================================================================
# 明確開啟才放行(不分大小寫、容忍前後空白)
# ============================================================================


@pytest.mark.parametrize("value", ["1", "true", "yes", "TRUE", "Yes", "  1  "])
def test_allows_when_explicitly_enabled(value: str) -> None:
    require_audit_downgrade_allowed(env={AUDIT_DOWNGRADE_ENV: value})  # 不拋即通過


# ============================================================================
# 預設讀 os.environ(env=None 分支)
# ============================================================================


def test_defaults_to_os_environ_and_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(AUDIT_DOWNGRADE_ENV, raising=False)
    with pytest.raises(AuditDowngradeForbiddenError):
        require_audit_downgrade_allowed()


def test_defaults_to_os_environ_and_allows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(AUDIT_DOWNGRADE_ENV, "1")
    require_audit_downgrade_allowed()  # 不拋即通過
