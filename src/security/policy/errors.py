"""L10 Policy Engine 錯誤型別。

所有政策載入與評估錯誤都要能 fail-closed：呼叫端看到錯誤時不得放行。
"""

from __future__ import annotations


class PolicyError(Exception):
    """Policy Engine 根錯誤。"""


class PolicyLoadError(PolicyError):
    """政策檔載入或 schema 驗證失敗。"""


class PolicyExpressionError(PolicyLoadError):
    """政策 expression 無法安全解析。"""


class PolicyEvaluationError(PolicyError):
    """政策評估期錯誤，必須往 deny 方向處理。"""


class PolicyVersionError(PolicyError):
    """政策版本 publish / rollback 失敗。"""


class ApprovalWorkflowError(PolicyError):
    """審批狀態機轉換失敗。"""
