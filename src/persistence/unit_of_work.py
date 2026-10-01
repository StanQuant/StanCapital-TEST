"""韌性交易邊界 · UnitOfWork（審查 H4：把 resilience 原語接成可安全使用的正確接縫）。

為什麼不在 Repository 個別語句包 with_retry：
    連線錯誤通常讓整個資料庫交易作廢，重試單一語句會在已 abort 的交易上再次失敗。
    正確做法是「整個工作單元」失敗時回滾、用全新 session 重跑——這正是本模組提供的邊界。

定位：
    Repository 只負責 flush（不 commit）；commit 與重試交給本邊界統一處理。
    S22 API Gateway 的 service 層所有寫交易都必須走 run_resilient（見 BACKLOG B-008），
    避免重演「resilience 寫好卻沒接上」的 dormant 問題。
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.persistence.resilience import CircuitBreaker, with_retry

logger = logging.getLogger(__name__)


async def run_resilient[T](
    session_factory: async_sessionmaker[AsyncSession],
    work: Callable[[AsyncSession], Awaitable[T]],
    *,
    attempts: int = 3,
    breaker: CircuitBreaker | None = None,
) -> T:
    """在新交易內執行 work，成功則 commit；連線類錯誤回滾並重試整個工作單元。

    - work 收到一個乾淨 session，內含的 Repository 操作只 flush；commit 由本函式負責。
    - 連線類錯誤（OperationalError / InterfaceError / OSError）→ 退避重試整個工作單元。
    - 資料類錯誤（IntegrityError 等）→ 不重試，直接拋（重試只會再失敗）。
    - 任一例外都先讓 session 的 async context 自動回滾，下次重試用全新 session。
    - 提供 breaker 時：連續失敗達門檻後快速失敗，避免對故障 DB 雪崩式重試。
    """

    async def _attempt() -> T:
        async with session_factory() as session:
            result = await work(session)
            await session.commit()
            logger.debug("工作單元提交成功")  # 最小可觀測性:寫交易成功留痕(高頻故 DEBUG)
            return result

    try:
        if breaker is not None:
            return await breaker.call(lambda: with_retry(_attempt, attempts=attempts))
        return await with_retry(_attempt, attempts=attempts)
    except Exception:
        # 重試/熔斷後仍失敗:運維需要的醒目訊號(帶 traceback)。
        logger.exception("工作單元最終失敗(重試/熔斷後仍未成功)")
        raise
