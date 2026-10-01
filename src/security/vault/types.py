"""S10 secret-vault 領域型別。"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from src.security.vault.errors import SecretValidationError

REDACTED_SECRET = "***REDACTED***"  # noqa: S105 - 固定遮蔽標記，不是密碼。

_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _validate_segment(field_name: str, value: str) -> None:
    if not value:
        raise SecretValidationError(f"{field_name} 不可為空")
    if not _SEGMENT_RE.fullmatch(value):
        raise SecretValidationError(
            f"{field_name} 只能使用英數、底線、點、連字號，且不可含路徑符號: {value}"
        )


class SecretProviderKind(StrEnum):
    """SecretProvider 類型。"""

    MEMORY = "memory"
    KEYCHAIN = "keychain"
    PASS = "pass"  # noqa: S105 - provider 名稱，不是密碼。
    VAULT = "vault"
    CLOUD_SECRET_MANAGER = "cloud_secret_manager"  # noqa: S105 - provider 名稱，不是密碼。  # pragma: allowlist secret


class SecretStatus(StrEnum):
    """Secret metadata 狀態。"""

    ACTIVE = "active"
    DELETED = "deleted"
    REVOKED = "revoked"


class SecretAction(StrEnum):
    """可稽核的 secret lifecycle 動作。"""

    CREATE = "create"
    READ = "read"
    ROTATE = "rotate"
    DELETE = "delete"


@dataclass(frozen=True, slots=True)
class SecretName:
    """結構化 secret 名稱。tenant_id 必填，不給預設。"""

    tenant_id: str
    service: str
    purpose: str
    environment: str

    def __post_init__(self) -> None:
        _validate_segment("tenant_id", self.tenant_id)
        _validate_segment("service", self.service)
        _validate_segment("purpose", self.purpose)
        _validate_segment("environment", self.environment)

    def path(self) -> str:
        """跨 provider 共用的安全路徑，不含 secret 原文。"""
        return (
            f"tenant/{self.tenant_id}/service/{self.service}/"
            f"purpose/{self.purpose}/env/{self.environment}"
        )

    def to_audit_dict(self) -> dict[str, str]:
        """可進 audit / log 的結構化名稱。"""
        return {
            "tenant_id": self.tenant_id,
            "service": self.service,
            "purpose": self.purpose,
            "environment": self.environment,
            "path": self.path(),
        }


@dataclass(frozen=True, slots=True, repr=False)
class SecretValue:
    """secret 原文唯一容器。repr / str 永遠遮蔽。"""

    plaintext: str = field(repr=False)

    def __post_init__(self) -> None:
        if not self.plaintext:
            raise SecretValidationError("secret value 不可為空")

    def __repr__(self) -> str:
        return "SecretValue(***REDACTED***)"

    def __str__(self) -> str:
        return REDACTED_SECRET

    def reveal(self) -> str:
        """明確取出原文；所有呼叫點都必須有理由。"""
        return self.plaintext

    def fingerprint(self, length: int = 12) -> str:
        """不可逆短指紋，用於辨識輪換，不可當 secret 使用。"""
        if not 8 <= length <= 64:
            raise SecretValidationError("fingerprint length 必須在 8-64 之間")
        return hashlib.sha256(self.plaintext.encode("utf-8")).hexdigest()[:length]


@dataclass(frozen=True, slots=True)
class SecretMetadata:
    """可稽核 metadata；不得含 secret 原文。"""

    name: SecretName
    provider: SecretProviderKind
    version: str
    fingerprint: str
    status: SecretStatus = SecretStatus.ACTIVE
    created_at: datetime = field(default_factory=_utc_now)
    updated_at: datetime = field(default_factory=_utc_now)
    rotated_at: datetime | None = None
    expires_at: datetime | None = None
    labels: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.version:
            raise SecretValidationError("version 不可為空")
        if not self.fingerprint:
            raise SecretValidationError("fingerprint 不可為空")
        for field_name in ("created_at", "updated_at"):
            timestamp = getattr(self, field_name)
            if timestamp.tzinfo is None:
                raise SecretValidationError(f"{field_name} 必須是 tz-aware 時間")
        for field_name in ("rotated_at", "expires_at"):
            timestamp = getattr(self, field_name)
            if timestamp is not None and timestamp.tzinfo is None:
                raise SecretValidationError(f"{field_name} 必須是 tz-aware 時間")
        clean_labels = dict(self.labels)
        for key, value in clean_labels.items():
            _validate_segment("label key", key)
            if not value:
                raise SecretValidationError("label value 不可為空")
        object.__setattr__(self, "labels", MappingProxyType(clean_labels))

    def with_update(
        self,
        *,
        fingerprint: str | None = None,
        version: str | None = None,
        status: SecretStatus | None = None,
        rotated_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> SecretMetadata:
        """建立更新後 metadata，保留 immutable 值物件語意。"""
        return replace(
            self,
            fingerprint=fingerprint or self.fingerprint,
            version=version or self.version,
            status=status or self.status,
            rotated_at=rotated_at if rotated_at is not None else self.rotated_at,
            updated_at=updated_at or _utc_now(),
        )

    def to_audit_metadata(self) -> dict[str, Any]:
        """轉成 audit / observability 可用 metadata；不含 secret 原文。"""
        return {
            "name": self.name.to_audit_dict(),
            "provider": self.provider.value,
            "version": self.version,
            "fingerprint": self.fingerprint,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "rotated_at": self.rotated_at.isoformat() if self.rotated_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "labels": dict(self.labels),
        }


@dataclass(frozen=True, slots=True)
class SecretRotationPolicy:
    """密鑰輪換政策。S10 只建 metadata 與範本，不做真排程。"""

    max_age_days: int = 90
    notify_before_days: int = 14

    def __post_init__(self) -> None:
        if self.max_age_days <= 0:
            raise SecretValidationError("max_age_days 必須大於 0")
        if not 0 <= self.notify_before_days < self.max_age_days:
            raise SecretValidationError("notify_before_days 必須小於 max_age_days 且不可為負")
