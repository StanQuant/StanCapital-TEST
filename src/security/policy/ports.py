"""S08 Policy Engine ports。

核心 evaluator 不碰 DB / audit / notification；side effects 只透過 port 進出。
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from src.security.policy.approval import ApprovalCase


class AuditMetadataSink(Protocol):
    """Policy decision audit metadata sink。"""

    def record(self, metadata: dict[str, Any]) -> None:
        """記錄 metadata。"""


class NoopAuditMetadataSink:
    """測試與未接線環境使用；不丟失 decision，僅代表尚未持久化。"""

    def record(self, metadata: dict[str, Any]) -> None:
        return None


class InMemoryAuditMetadataSink:
    """測試用 append-only sink。"""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def record(self, metadata: dict[str, Any]) -> None:
        self.records.append(metadata)


class ApprovalCaseSink(Protocol):
    """審批案件出口(port)。

    S08 把 require_approval 決策開出的 ApprovalCase 交給此 port；正式佇列 / DB / 通知
    由 S22 / S24 / S28 接線，S08 只負責不丟件。
    """

    def record(self, case: ApprovalCase) -> None:
        """記錄審批案件。"""


class NoopApprovalCaseSink:
    """未接線環境使用；代表審批案件尚未持久化，但不影響決策。"""

    def record(self, case: ApprovalCase) -> None:
        return None


class InMemoryApprovalCaseSink:
    """測試用 append-only 審批案件 sink。"""

    def __init__(self) -> None:
        self.cases: list[ApprovalCase] = []

    def record(self, case: ApprovalCase) -> None:
        self.cases.append(case)
