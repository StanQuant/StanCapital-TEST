"""L4 值物件不變式驗證 · fail-closed 守門（S01 規格 §8.2 落地）。

為什麼存在：型別註記（如 `quantity: Decimal`）只在「靜態檢查」時有意義，
執行期 Python 不會擋——髒資料（券商 API / JSON 反序列化 / 手動下單）仍可塞進來。
本模組提供純驗證函式，由各值物件的 `__post_init__` 呼叫，任一不變式違反一律
raise ValueError（熔斷思維：寧可在最底層當場擋下，也不讓垃圾值滲到風控與帳務）。

設計：只驗證、不改值，與 frozen dataclass 完全相容（不需 object.__setattr__）。
"""

from __future__ import annotations

import math
from datetime import datetime
from decimal import Decimal


def ensure_non_empty(name: str, value: str) -> None:
    """字串不可為空（擋空 tenant_id / symbol / id 等無主資料）。"""
    if not value:
        raise ValueError(f"{name} 不可為空字串")


def ensure_decimal(name: str, value: Decimal) -> None:
    """必須是 Decimal 且非 NaN/Infinity。

    攔截 float 冒充 Decimal：型別註記是 Decimal 但實際傳 float（如 0.1+0.2）會
    繞過 Decimal 的精度保證，在 PnL / 部位累加時悄悄引入浮點誤差——正是用 Decimal 的初衷。
    """
    if not isinstance(value, Decimal):
        raise ValueError(
            f"{name} 必須是 Decimal，不可為 {type(value).__name__}"
            "（float / int 會繞過精度保證，請用 Decimal）"
        )
    if value.is_nan() or value.is_infinite():
        raise ValueError(f"{name} 不可為 NaN / Infinity：{value}")


def ensure_finite(name: str, value: Decimal) -> None:
    """允許正 / 負 / 0，只擋型別錯誤與 NaN/Infinity（如 PnL、market_value）。"""
    ensure_decimal(name, value)


def ensure_positive(name: str, value: Decimal) -> None:
    """必須 > 0（如成交量、價格、訂單數量）。"""
    ensure_decimal(name, value)
    if value <= 0:
        raise ValueError(f"{name} 必須 > 0：{value}")


def ensure_non_negative(name: str, value: Decimal) -> None:
    """必須 >= 0（如手續費、均價——平倉時可為 0）。"""
    ensure_decimal(name, value)
    if value < 0:
        raise ValueError(f"{name} 不可為負：{value}")


def ensure_non_negative_int(name: str, value: int) -> None:
    """整數且 >= 0（如 duration_ms）。bool 不算合法整數。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} 必須是非負整數，不可為 {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} 不可為負：{value}")


def ensure_utc(name: str, value: datetime) -> None:
    """必須是「帶時區」的 datetime（拒絕 naive）。

    naive datetime（無 tzinfo）在跨時區聚合 / 排序時會錯位，也讓稽核指紋不決定性。
    本層只要求 tz-aware（最關鍵的 fail-closed）；統一轉 UTC 的正規化由序列化層負責。
    """
    if not isinstance(value, datetime):
        raise ValueError(f"{name} 必須是 datetime，不可為 {type(value).__name__}")
    if value.tzinfo is None:
        raise ValueError(f"{name} 必須是帶時區的 datetime（拒絕 naive，時間需可跨時區比對）")


def ensure_confidence(name: str, value: float) -> None:
    """信心分數必須落在 [0.0, 1.0]（且非 NaN/Infinity）。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} 必須是數值，不可為 {type(value).__name__}")
    if math.isnan(value) or math.isinf(value):
        raise ValueError(f"{name} 不可為 NaN / Infinity：{value}")
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} 必須落在 [0.0, 1.0]：{value}")
