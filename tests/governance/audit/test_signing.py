"""S05 Batch 6c · 可插拔簽章測試(信任根外移 B-006)。

涵蓋:
- 預設 sha256_sign 與純 SHA256 位元相同(向後相容紅線)
- HMAC 簽章器: 與 SHA256 不同、仍 64 hex、空金鑰拒絕
- signer_from_env: 有/無金鑰兩分支 + os.environ 預設分支
- 端到端: HMAC 寫入的鏈用同金鑰可驗、用錯金鑰(等於無金鑰攻擊者)被當篡改
"""

from __future__ import annotations

import hashlib

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from src.governance.audit.repository import AuditLogRepository
from src.governance.audit.signing import (
    AUDIT_HMAC_KEY_ENV,
    DEFAULT_SIGNER,
    make_hmac_signer,
    sha256_sign,
    signer_from_env,
)
from src.governance.audit.verifier import ChainVerifier

from tests.governance.audit.conftest import fixed_clock, make_input

# asyncio_mode = "auto"：async 測試自動偵測；本檔混合同步單元 + 非同步端到端，
# 故不在模組層標 asyncio(否則同步測試會被誤套並告警)。

TENANT = "tenant-a"


# ============================================================================
# 簽章器單元
# ============================================================================


def test_sha256_sign_is_plain_sha256() -> None:
    # 向後相容紅線: 預設簽章與歷史純 SHA256 位元相同
    assert sha256_sign("hello") == hashlib.sha256(b"hello").hexdigest()


def test_default_signer_is_sha256() -> None:
    assert DEFAULT_SIGNER is sha256_sign


def test_hmac_signer_differs_and_is_64_hex() -> None:
    signer = make_hmac_signer(b"super-secret")
    signed = signer("payload")
    assert signed != sha256_sign("payload")  # 有金鑰才算得出
    assert len(signed) == 64  # 仍 64 hex → 不需改 schema


def test_hmac_empty_key_rejected() -> None:
    with pytest.raises(ValueError, match="HMAC 金鑰不可為空"):
        make_hmac_signer(b"")


# ============================================================================
# signer_from_env
# ============================================================================


def test_signer_from_env_without_key_returns_default() -> None:
    assert signer_from_env(env={}) is DEFAULT_SIGNER


def test_signer_from_env_with_key_returns_hmac() -> None:
    signer = signer_from_env(env={AUDIT_HMAC_KEY_ENV: "k3y"})
    assert signer("x") == make_hmac_signer(b"k3y")("x")
    assert signer("x") != sha256_sign("x")


def test_signer_from_env_defaults_to_os_environ(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(AUDIT_HMAC_KEY_ENV, raising=False)
    assert signer_from_env() is DEFAULT_SIGNER  # 無金鑰 → 預設
    monkeypatch.setenv(AUDIT_HMAC_KEY_ENV, "k")
    assert signer_from_env()("x") != sha256_sign("x")  # 有金鑰 → HMAC


# ============================================================================
# 端到端: 寫入與驗證須同 signer
# ============================================================================


async def test_hmac_signed_chain_verifies_with_same_signer(session: AsyncSession) -> None:
    signer = make_hmac_signer(b"deployment-key")
    repo = AuditLogRepository(session, clock=fixed_clock, checkpoint_batch_size=3, signer=signer)
    await repo.append_many([make_input(action=f"order.submit.{i}") for i in range(6)])
    verifier = ChainVerifier(repo, signer=signer)
    assert (await verifier.verify_tenant_chain(TENANT)).is_intact  # 記錄層
    assert (await verifier.verify_checkpoint_layer(TENANT)).is_intact  # 封印層


async def test_hmac_chain_detected_as_tampered_with_wrong_signer(session: AsyncSession) -> None:
    repo = AuditLogRepository(
        session, clock=fixed_clock, checkpoint_batch_size=3, signer=make_hmac_signer(b"real-key")
    )
    await repo.append_many([make_input(action=f"order.submit.{i}") for i in range(6)])
    # 用預設 SHA256 驗證 = 沒有金鑰的攻擊者，重算指紋全對不上
    wrong = ChainVerifier(repo)  # DEFAULT_SIGNER
    report = await wrong.verify_tenant_chain(TENANT)
    assert not report.is_intact
    assert report.mismatched_sequences  # 至少一筆對不上
