"""L10 Secret Vault public API."""

from src.security.vault.audit import SecretAuditEvent
from src.security.vault.connector import SecretBackedConnector, require_connector_secret
from src.security.vault.errors import (
    SecretNotFoundError,
    SecretProviderError,
    SecretProviderUnavailableError,
    SecretRotationError,
    SecretValidationError,
    VaultError,
)
from src.security.vault.keychain import KeychainSecretProvider
from src.security.vault.memory import InMemorySecretProvider
from src.security.vault.pass_provider import PassSecretProvider
from src.security.vault.provider import SecretProvider
from src.security.vault.redaction import contains_plaintext, redact_secret_payload
from src.security.vault.rotation import (
    DEFAULT_ROTATION_TEMPLATE,
    RotationTemplate,
    rotation_due,
    rotation_notice_due,
)
from src.security.vault.sinks import (
    InMemorySecretAuditSink,
    NoopSecretAuditSink,
    SecretAuditProjection,
    SecretAuditSink,
    SecretObservabilitySink,
    project_secret_audit_event,
)
from src.security.vault.types import (
    SecretAction,
    SecretMetadata,
    SecretName,
    SecretProviderKind,
    SecretRotationPolicy,
    SecretStatus,
    SecretValue,
)
from src.security.vault.vault_provider import (
    CloudSecretManagerProvider,
    ManagedSecretProvider,
    SecretManagerClient,
    VaultSecretProvider,
)

__all__ = [
    "DEFAULT_ROTATION_TEMPLATE",
    "CloudSecretManagerProvider",
    "InMemorySecretAuditSink",
    "InMemorySecretProvider",
    "KeychainSecretProvider",
    "ManagedSecretProvider",
    "NoopSecretAuditSink",
    "PassSecretProvider",
    "RotationTemplate",
    "SecretAction",
    "SecretAuditEvent",
    "SecretAuditProjection",
    "SecretAuditSink",
    "SecretBackedConnector",
    "SecretManagerClient",
    "SecretMetadata",
    "SecretName",
    "SecretNotFoundError",
    "SecretObservabilitySink",
    "SecretProvider",
    "SecretProviderError",
    "SecretProviderKind",
    "SecretProviderUnavailableError",
    "SecretRotationError",
    "SecretRotationPolicy",
    "SecretStatus",
    "SecretValidationError",
    "SecretValue",
    "VaultError",
    "VaultSecretProvider",
    "contains_plaintext",
    "project_secret_audit_event",
    "redact_secret_payload",
    "require_connector_secret",
    "rotation_due",
    "rotation_notice_due",
]
