"""L10 ATR 錯誤型別。

ATR 是安全熱路徑；設定錯誤、rulebook 壞掉、sink 失敗都不能默默放過。
核心原則是 fail-closed：寧可擋下或啟動失敗，也不要帶半套安全規則上線。
"""

from __future__ import annotations


class AtrError(Exception):
    """L10 ATR 錯誤基底。"""


class RulebookLoadError(AtrError, ValueError):
    """ATR rulebook 解析/驗證失敗。"""


class AtrSinkError(AtrError):
    """ATR sink 執行失敗。"""
