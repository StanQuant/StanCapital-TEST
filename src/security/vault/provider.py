"""SecretProvider Protocol。"""

from __future__ import annotations

from typing import Protocol

from src.security.vault.types import SecretMetadata, SecretName, SecretValue


class SecretProvider(Protocol):
    """所有 secret backend 的共同 contract。"""

    def set_secret(
        self,
        name: SecretName,
        value: SecretValue,
        metadata: SecretMetadata,
    ) -> SecretMetadata:
        """建立或更新 secret。"""

    def get_secret(self, name: SecretName) -> SecretValue:
        """取得 secret 原文容器。呼叫端必須有明確授權。"""

    def delete_secret(self, name: SecretName) -> SecretMetadata:
        """刪除或撤銷 secret，回傳刪除 metadata。"""

    def exists(self, name: SecretName) -> bool:
        """secret 是否存在。"""

    def list_metadata(self, tenant_id: str) -> tuple[SecretMetadata, ...]:
        """列出指定租戶的 metadata。tenant_id 必填，不給預設。"""

    def get_metadata(self, name: SecretName) -> SecretMetadata:
        """讀取 metadata，不回傳 secret 原文。"""

    def rotate_secret(
        self,
        name: SecretName,
        new_value: SecretValue,
        reason: str,
    ) -> SecretMetadata:
        """輪換 secret，記錄新版本與 fingerprint。"""
