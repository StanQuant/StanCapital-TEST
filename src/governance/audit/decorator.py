"""L11 Audit 自動稽核裝飾器 · 寫操作掛上 @audited 就自動留稽核。

雙通道設計(D3 fail-closed + D4 同交易的工程落地):
- 成功路徑: 稽核走業務同一個 session(同交易提交)——「操作成功 ⟺ 稽核存在」
  原子成立；稽核寫不進去就拋 AuditUnavailableError，呼叫端必須 rollback。
- 失敗路徑: 業務拋錯時呼叫端通常會 rollback 整筆交易，FAILED 證據若寫在
  同 session 會一起蒸發——所以失敗證據走獨立 session 立即提交，
  「試圖做壞事」的痕跡不隨業務回滾消失。

服務端契約(AuditedService): 提供 audit_repo(綁業務 session)與
audit_session_factory(失敗證據的獨立交易來源)兩個屬性。
呼叫端契約: 呼叫被稽核的方法必須帶 audit_ctx 關鍵字參數；
收到 AuditUnavailableError 必須 rollback 當前交易。
"""

from __future__ import annotations

import functools
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, ParamSpec, Protocol, TypeVar, runtime_checkable

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.governance.audit.chain import hash_payload
from src.governance.audit.errors import AuditUnavailableError
from src.governance.audit.repository import AuditLogRepository
from src.governance.audit.types import AuditOutcome, AuditRecordInput
from src.governance.rbac.roles import Role

logger = logging.getLogger(__name__)

P = ParamSpec("P")
R = TypeVar("R")

# 從呼叫參數萃取資源字串 / 請求內容的函式型別
ResourceFn = Callable[..., str]
PayloadFn = Callable[..., dict[str, Any]]


@dataclass(frozen=True, slots=True)
class AuditContext:
    """呼叫端身分脈絡 · S22 gateway 落地後由中介層自動填(現在由呼叫端傳)。"""

    tenant_id: str
    user_id: str
    role: Role
    ip_address: str = "internal"
    user_agent: str = "internal"
    risk_score: int = 0


@runtime_checkable
class AuditedService(Protocol):
    """被 @audited 裝飾的方法所屬服務必須提供的兩個稽核通道。"""

    audit_repo: AuditLogRepository
    audit_session_factory: async_sessionmaker[AsyncSession]


def audited(
    action: str,
    *,
    resource: str | ResourceFn,
    payload: PayloadFn | None = None,
) -> Callable[[Callable[P, Awaitable[R]]], Callable[P, Awaitable[R]]]:
    """把服務層的寫方法包上自動稽核。

    - action: 稽核動作名(如 "order.submit"，不可含空白)
    - resource: 資源字串，或從呼叫參數算出資源字串的函式
    - payload: 從呼叫參數萃取請求內容 dict 的函式(只留 SHA256 指紋、內容不落地)；
      不提供則以空 dict 計指紋
    """

    def decorate(fn: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
        @functools.wraps(fn)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            service = _require_service(args, action)
            ctx = _require_context(kwargs, action)
            resource_str = resource(*args, **kwargs) if callable(resource) else resource
            payload_hash = hash_payload(payload(*args, **kwargs) if payload else {})

            try:
                result = await fn(*args, **kwargs)
            except AuditUnavailableError:
                raise  # 巢狀稽核已經 fail-closed，不再疊一筆失敗證據
            except Exception as business_error:
                await _record_failure(
                    service, ctx, action, resource_str, payload_hash, business_error
                )
                raise

            # 成功路徑: 與業務同 session，由呼叫端一起 commit(D4 同交易)
            try:
                await service.audit_repo.append(
                    _build_input(ctx, action, resource_str, payload_hash, AuditOutcome.SUCCESS)
                )
            except Exception as audit_error:
                raise AuditUnavailableError(
                    tenant_id=ctx.tenant_id, action=action, reason=str(audit_error)
                ) from audit_error
            # 最小可觀測性的單一觸點:所有 @audited 寫入(含全部 rbac_admin 操作)成功時
            # 都在此留一筆 DEBUG,無需在各呼叫端重複加 log(去重)。
            logger.debug(
                "稽核完成(成功) action=%s tenant=%s user=%s", action, ctx.tenant_id, ctx.user_id
            )
            return result

        return wrapper

    return decorate


def _require_service(args: tuple[Any, ...], action: str) -> AuditedService:
    if not args or not isinstance(args[0], AuditedService):
        raise TypeError(
            f"@audited 方法的所屬服務必須提供 audit_repo 與 audit_session_factory: action={action}"
        )
    return args[0]


def _require_context(kwargs: dict[str, Any], action: str) -> AuditContext:
    ctx = kwargs.get("audit_ctx")
    if not isinstance(ctx, AuditContext):
        # 沒有身分脈絡就不准執行(fail-closed: 寧可擋下也不留無主操作)
        raise AuditUnavailableError(
            tenant_id="unknown", action=action, reason="缺少 audit_ctx 關鍵字參數"
        )
    return ctx


def _build_input(
    ctx: AuditContext,
    action: str,
    resource_str: str,
    payload_hash: str,
    outcome: AuditOutcome,
) -> AuditRecordInput:
    return AuditRecordInput(
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        role=ctx.role,
        action=action,
        resource=resource_str,
        request_payload_hash=payload_hash,
        response_status=outcome,
        ip_address=ctx.ip_address,
        user_agent=ctx.user_agent,
        risk_score=ctx.risk_score,
    )


async def _record_failure(
    service: AuditedService,
    ctx: AuditContext,
    action: str,
    resource_str: str,
    payload_hash: str,
    business_error: Exception,
) -> None:
    """失敗證據走獨立交易立即提交(不隨業務 rollback 蒸發)。"""
    try:
        async with service.audit_session_factory() as session:
            # 失敗證據的獨立 repository 須沿用服務設定的 batch size,
            # 否則自訂 batch size 的部署在失敗路徑會用回預設值、封印節奏不一致
            repository = AuditLogRepository(
                session, checkpoint_batch_size=service.audit_repo.checkpoint_batch_size
            )
            await repository.append(
                _build_input(ctx, action, resource_str, payload_hash, AuditOutcome.FAILED)
            )
            await session.commit()
            # 被拒/失敗的嘗試已留下不可變證據:給維運一個即時 WARNING(有人試圖做壞事/出錯)。
            logger.warning(
                "已記錄失敗證據 action=%s tenant=%s 業務錯誤=%s",
                action,
                ctx.tenant_id,
                business_error,
            )
    except Exception as audit_error:
        logger.critical(
            "失敗證據寫入也失敗(雙重故障): tenant=%s action=%s 業務錯誤=%s 稽核錯誤=%s",
            ctx.tenant_id,
            action,
            business_error,
            audit_error,
        )
        raise AuditUnavailableError(
            tenant_id=ctx.tenant_id, action=action, reason=str(audit_error)
        ) from audit_error
