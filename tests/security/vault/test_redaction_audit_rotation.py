"""redaction / audit / rotation 測試。"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from src.observability.redaction import REDACTED
from src.security.vault.audit import SecretAuditEvent
from src.security.vault.redaction import contains_plaintext, redact_secret_payload
from src.security.vault.rotation import (
    DEFAULT_ROTATION_TEMPLATE,
    RotationTemplate,
    rotation_due,
    rotation_notice_due,
    utc_now,
)
from src.security.vault.types import (
    SecretAction,
    SecretMetadata,
    SecretRotationPolicy,
    SecretValue,
)


def test_redaction_masks_secret_value_and_sensitive_keys(secret_value: SecretValue) -> None:
    payload = {
        "safe": "ok",
        "secret_value": secret_value,
        "nested": {"authorization_header": "Bearer abc.def.ghi"},
    }
    redacted = redact_secret_payload(payload)
    assert redacted["safe"] == "ok"
    assert redacted["secret_value"] == REDACTED
    assert redacted["nested"]["authorization_header"] == REDACTED
    assert contains_plaintext(redacted, secret_value) is False
    assert redact_secret_payload(secret_value) == REDACTED
    assert contains_plaintext({"leak": secret_value.reveal()}, secret_value) is True


@pytest.mark.parametrize(
    "key",
    [
        "api_secret",
        "client_secret",
        "hmac_key",
        "secret_value",
        "vault_token",
        "authorization_header",
    ],
)
def test_redaction_masks_all_vault_sensitive_keys(key: str) -> None:
    assert redact_secret_payload({key: "sq_live_should_never_log"}) == {key: REDACTED}


def test_audit_event_contains_metadata_but_never_secret(
    secret_metadata: SecretMetadata,
    secret_value: SecretValue,
) -> None:
    event = SecretAuditEvent(
        action=SecretAction.READ,
        metadata=secret_metadata,
        actor_id="agent-1",
        trace_id="trace-1",
        result="success",
        reason="authorized read",
    )
    payload = event.to_metadata()
    assert set(payload) == {
        "event_type",
        "action",
        "actor_id",
        "trace_id",
        "result",
        "reason",
        "failure_category",
        "timestamp",
        "resource",
    }
    assert payload["event_type"] == "secret_lifecycle"
    assert payload["action"] == "read"
    assert payload["actor_id"] == "agent-1"
    assert payload["trace_id"] == "trace-1"
    assert payload["result"] == "success"
    assert payload["reason"] == "authorized read"
    assert payload["failure_category"] is None
    assert payload["timestamp"] == event.timestamp.isoformat()
    assert payload["resource"]["name"]["tenant_id"] == "stanley"
    assert payload["resource"]["fingerprint"] == secret_value.fingerprint()
    assert contains_plaintext(payload, secret_value) is False


def test_audit_event_validation(secret_metadata: SecretMetadata) -> None:
    with pytest.raises(ValueError, match="actor_id"):
        SecretAuditEvent(SecretAction.CREATE, secret_metadata, "", "trace", "success", "reason")
    with pytest.raises(ValueError, match="trace_id"):
        SecretAuditEvent(SecretAction.CREATE, secret_metadata, "actor", "", "success", "reason")
    with pytest.raises(ValueError, match="result"):
        SecretAuditEvent(SecretAction.CREATE, secret_metadata, "actor", "trace", "", "reason")
    with pytest.raises(ValueError, match="reason"):
        SecretAuditEvent(SecretAction.CREATE, secret_metadata, "actor", "trace", "success", "")
    with pytest.raises(ValueError, match="failure_category"):
        SecretAuditEvent(
            SecretAction.CREATE,
            secret_metadata,
            "actor",
            "trace",
            "failed",
            "reason",
            failure_category="",
        )
    with pytest.raises(ValueError, match="tz-aware"):
        SecretAuditEvent(
            SecretAction.CREATE,
            secret_metadata,
            "actor",
            "trace",
            "success",
            "reason",
            timestamp=datetime(2026, 1, 1),
        )


def test_rotation_due_and_template(secret_metadata: SecretMetadata) -> None:
    policy = SecretRotationPolicy(max_age_days=90, notify_before_days=14)
    before_notice = secret_metadata.updated_at + timedelta(days=75)
    notice = secret_metadata.updated_at + timedelta(days=76)
    before_due = secret_metadata.updated_at + timedelta(days=89, hours=23, minutes=59)
    due = secret_metadata.updated_at + timedelta(days=90)
    assert rotation_notice_due(secret_metadata, policy, now=before_notice) is False
    assert rotation_notice_due(secret_metadata, policy, now=notice) is True
    assert rotation_due(secret_metadata, policy, now=notice) is False
    assert rotation_due(secret_metadata, policy, now=before_due) is False
    assert rotation_due(secret_metadata, policy, now=due) is True
    assert DEFAULT_ROTATION_TEMPLATE.render().endswith("--dry-run\n")
    custom = RotationTemplate("0 1 * * *", "echo rotate")
    assert custom.render() == "0 1 * * * echo rotate\n"


def test_rotation_helpers_reject_naive_time(secret_metadata: SecretMetadata) -> None:
    policy = SecretRotationPolicy()
    with pytest.raises(ValueError, match="tz-aware"):
        rotation_due(secret_metadata, policy, now=datetime(2026, 1, 1))
    with pytest.raises(ValueError, match="tz-aware"):
        rotation_notice_due(secret_metadata, policy, now=datetime(2026, 1, 1))
    with pytest.raises(ValueError, match="schedule"):
        RotationTemplate("", "cmd")
    with pytest.raises(ValueError, match="command"):
        RotationTemplate("0 1 * * *", "")
    assert datetime.now(UTC).tzinfo is not None
    assert utc_now().tzinfo is not None
