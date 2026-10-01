"""L11 Audit · 稽核 migration 降級防呆(生產環境 fail-closed 擋下)。

為什麼存在:
  稽核三表的 downgrade 會 DROP 整張表 = 一條指令清空稽核資料,違反金融法遵的
  保存義務(S05-商業化硬化清單 §2.3 紅線)。光靠 docstring 警告不夠——一次手滑
  `alembic downgrade` 就釀災。本守門讓降級「預設禁止」,必須明確設環境變數開關才放行。

設計(fail-closed):
  預設(沒設開關)一律擋下;只有把 STANQUANT_ALLOW_AUDIT_DOWNGRADE 設成明確的
  開啟值(1 / true / yes,不分大小寫)才放行。開關刻意不寫進版本庫、不進 CI 預設,
  確保「要降級稽核」一定是人為當下的明確決定。
"""

from __future__ import annotations

import os
from collections.abc import Mapping

# 降級稽核 migration 的明確開關(預設不存在 = 禁止)
AUDIT_DOWNGRADE_ENV = "STANQUANT_ALLOW_AUDIT_DOWNGRADE"
_ALLOWED_VALUES = frozenset({"1", "true", "yes"})


class AuditDowngradeForbiddenError(RuntimeError):
    """未明確授權就試圖降級稽核 migration(預設 fail-closed 擋下)。"""


def require_audit_downgrade_allowed(env: Mapping[str, str] | None = None) -> None:
    """降級稽核 migration 前的防呆閘。未明確開啟即拋 AuditDowngradeForbiddenError。

    env 可注入(測試用);預設讀 os.environ。
    """
    source = os.environ if env is None else env
    value = source.get(AUDIT_DOWNGRADE_ENV, "").strip().lower()
    if value not in _ALLOWED_VALUES:
        raise AuditDowngradeForbiddenError(
            "稽核 migration downgrade 會刪除稽核資料、違反法遵保存義務,預設禁止。"
            f"確定是開發環境才要降級,請設環境變數 {AUDIT_DOWNGRADE_ENV}=1 後重試。"
        )
