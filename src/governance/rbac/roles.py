"""L11 RBAC 角色定義 · 8 個內建角色。

這份名單是「系統憲法」級宣告(Architecture §L11)：
新增 / 改名屬重大變更，必須走 ADR + Stanley 簽核，不走租戶覆寫層。
"""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    """內建角色。字串值存資料庫與日誌都用同一格式(小寫蛇形)。"""

    OWNER = "owner"
    ADMINISTRATOR = "administrator"
    SECURITY_OFFICER = "security_officer"
    COMPLIANCE_OFFICER = "compliance_officer"
    MANAGER = "manager"
    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    AGENT = "agent"
