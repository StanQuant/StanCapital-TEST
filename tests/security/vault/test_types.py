"""S10 值物件測試。"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest
from src.security.vault.errors import SecretValidationError
from src.security.vault.types import (
    SecretAction,
    SecretMetadata,
    SecretName,
    SecretProviderKind,
    SecretRotationPolicy,
    SecretStatus,
    SecretValue,
)


def test_secret_name_is_structured_and_audit_safe(secret_name: SecretName) -> None:
    assert secret_name.path() == "tenant/stanley/service/audit/purpose/hmac_signing/env/local"
    assert secret_name.to_audit_dict() == {
        "tenant_id": "stanley",
        "service": "audit",
        "purpose": "hmac_signing",
        "environment": "local",
        "path": "tenant/stanley/service/audit/purpose/hmac_signing/env/local",
    }
    assert not hasattr(secret_name, "__dict__")
    with pytest.raises(FrozenInstanceError):
        secret_name.tenant_id = "other"  # type: ignore[misc]


def test_public_enum_values_are_stable_contracts() -> None:
    assert {kind.value for kind in SecretProviderKind} == {
        "memory",
        "keychain",
        "pass",
        "vault",
        "cloud_secret_manager",
    }
    assert {status.value for status in SecretStatus} == {"active", "deleted", "revoked"}
    assert {action.value for action in SecretAction} == {"create", "read", "rotate", "delete"}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tenant_id", ""),
        ("tenant_id", "../evil"),
        ("service", "bad/service"),
        ("purpose", "bad purpose"),
        ("environment", "$prod"),
    ],
)
def test_secret_name_rejects_invalid_segments(field: str, value: str) -> None:
    kwargs = {
        "tenant_id": "stanley",
        "service": "audit",
        "purpose": "hmac_signing",
        "environment": "local",
    }
    kwargs[field] = value
    with pytest.raises(SecretValidationError):
        SecretName(**kwargs)


def test_secret_value_requires_explicit_reveal_and_redacts_repr() -> None:
    value = SecretValue("sq_test_secret_value_123")
    assert repr(value) == "SecretValue(***REDACTED***)"
    assert str(value) == "***REDACTED***"
    assert value.reveal() == "sq_test_secret_value_123"
    assert value.fingerprint() == "f3eade7c9bf5"  # pragma: allowlist secret
    assert value.fingerprint(16) == "f3eade7c9bf52aed"  # pragma: allowlist secret
    assert "sq_test" not in repr(value)


def test_secret_value_rejects_empty_or_bad_fingerprint_length() -> None:
    with pytest.raises(SecretValidationError, match="不可為空"):
        SecretValue("")
    value = SecretValue("abc")
    with pytest.raises(SecretValidationError, match="8-64"):
        value.fingerprint(7)
    with pytest.raises(SecretValidationError, match="8-64"):
        value.fingerprint(65)


def test_metadata_is_immutable_redacted_and_mapping_proxy(
    secret_metadata: SecretMetadata,
) -> None:
    payload = secret_metadata.to_audit_metadata()
    assert payload["name"]["tenant_id"] == "stanley"
    assert payload["name"]["service"] == "audit"
    assert payload["name"]["purpose"] == "hmac_signing"
    assert payload["name"]["environment"] == "local"
    assert payload["name"]["path"] == "tenant/stanley/service/audit/purpose/hmac_signing/env/local"
    assert payload["provider"] == "memory"
    assert payload["version"] == "v1"
    assert payload["fingerprint"] == "f3eade7c9bf5"  # pragma: allowlist secret
    assert payload["status"] == "active"
    assert payload["created_at"] == secret_metadata.created_at.isoformat()
    assert payload["updated_at"] == secret_metadata.updated_at.isoformat()
    assert payload["rotated_at"] is None
    assert payload["expires_at"] is None
    assert payload["labels"] == {"scope": "audit_hmac"}
    assert dict(secret_metadata.labels) == {"scope": "audit_hmac"}
    with pytest.raises(TypeError):
        secret_metadata.labels["new"] = "value"  # type: ignore[index]
    updated = secret_metadata.with_update(status=SecretStatus.DELETED, version="v2")
    assert updated.status is SecretStatus.DELETED
    assert updated.version == "v2"
    assert updated.created_at == secret_metadata.created_at
    assert updated.updated_at >= secret_metadata.updated_at


def test_metadata_with_update_overrides_security_fields(
    secret_metadata: SecretMetadata,
) -> None:
    rotated_at = datetime(2026, 1, 2, tzinfo=UTC)
    updated_at = datetime(2026, 1, 3, tzinfo=UTC)

    updated = secret_metadata.with_update(
        fingerprint="newfingerprint",
        version="v9",
        status=SecretStatus.REVOKED,
        rotated_at=rotated_at,
        updated_at=updated_at,
    )

    assert updated.fingerprint == "newfingerprint"
    assert updated.version == "v9"
    assert updated.status is SecretStatus.REVOKED
    assert updated.rotated_at == rotated_at
    assert updated.updated_at == updated_at
    assert updated.name == secret_metadata.name
    assert updated.provider is SecretProviderKind.MEMORY


def test_metadata_validation(secret_name: SecretName) -> None:
    with pytest.raises(SecretValidationError, match="version"):
        SecretMetadata(secret_name, SecretProviderKind.MEMORY, "", "fp")
    with pytest.raises(SecretValidationError, match="fingerprint"):
        SecretMetadata(secret_name, SecretProviderKind.MEMORY, "v1", "")
    with pytest.raises(SecretValidationError, match="tz-aware"):
        SecretMetadata(
            secret_name,
            SecretProviderKind.MEMORY,
            "v1",
            "fp",
            created_at=datetime(2026, 1, 1),
        )
    with pytest.raises(SecretValidationError, match="rotated_at"):
        SecretMetadata(
            secret_name,
            SecretProviderKind.MEMORY,
            "v1",
            "fp",
            rotated_at=datetime(2026, 1, 1),
        )
    with pytest.raises(SecretValidationError, match="label key"):
        SecretMetadata(secret_name, SecretProviderKind.MEMORY, "v1", "fp", labels={"bad/key": "x"})
    with pytest.raises(SecretValidationError, match="label value"):
        SecretMetadata(secret_name, SecretProviderKind.MEMORY, "v1", "fp", labels={"ok": ""})


def test_rotation_policy_validation() -> None:
    assert SecretRotationPolicy().max_age_days == 90
    with pytest.raises(SecretValidationError):
        SecretRotationPolicy(max_age_days=0)
    with pytest.raises(SecretValidationError):
        SecretRotationPolicy(max_age_days=90, notify_before_days=90)
