"""L11 Audit 錯誤型別。

fail-closed 原則(D3 裁決): 稽核寫不進去時拋 AuditUnavailableError，
業務操作一併失敗——系統裡不存在「沒有稽核的寫操作」。
"""

from __future__ import annotations


class AuditError(Exception):
    """Audit 子層所有錯誤的基底。"""


class AuditUnavailableError(AuditError):
    """稽核儲存無法寫入(D3 fail-closed: 呼叫端的業務操作必須一併失敗)。"""

    def __init__(self, tenant_id: str, action: str, reason: str) -> None:
        self.tenant_id = tenant_id
        self.action = action
        self.reason = reason
        super().__init__(
            f"稽核寫入失敗，操作已中止(fail-closed): "
            f"tenant={tenant_id} action={action} reason={reason}"
        )


class ChainCorruptionError(AuditError):
    """鏈頭狀態與記錄不一致(資料庫被繞過防線動過手腳時的內部斷言)。"""
