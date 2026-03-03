"""Encryption helpers for CA private keys stored in the database.

CA private keys are encrypted at rest using Fernet (AES-128-CBC + HMAC-SHA256)
from the ``cryptography`` package.  The encryption key is derived from the
``CA_ENCRYPTION_KEY`` environment variable (or ``Flask.config["CA_ENCRYPTION_KEY"]``).

Key derivation
--------------
Fernet requires a URL-safe base64-encoded 32-byte key.  We accept any string
from the env and derive the actual Fernet key using SHA-256 so that operators
can supply human-readable secrets without having to pre-encode them.

Envelope format
---------------
Encrypted values are stored as the string::

    $fernet$<fernet_token>

The ``$fernet$`` prefix lets the code distinguish already-encrypted values from
legacy plaintext PEM keys so that the migration path is safe and idempotent.

Usage
-----
Encrypt before storing::

    from gatehouse_app.utils.ca_key_encryption import encrypt_ca_key
    ca.private_key = encrypt_ca_key(private_key_pem)

Decrypt before use::

    from gatehouse_app.utils.ca_key_encryption import decrypt_ca_key
    plaintext_pem = decrypt_ca_key(ca.private_key)
"""
import base64
import hashlib
import logging
import os

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

# Prefix that marks a stored value as Fernet-encrypted
_FERNET_PREFIX = "$fernet$"


class CAKeyEncryptionError(Exception):
    """Raised when CA key encryption or decryption fails."""


def _get_fernet() -> Fernet:
    """Build a Fernet instance from the configured encryption key.

    Looks up ``CA_ENCRYPTION_KEY`` in the environment first, then falls back to
    the Flask app config (if a request context is active).

    Raises:
        CAKeyEncryptionError: if no key is configured or it is the insecure
            placeholder value in a production-like environment.
    """
    raw_key = os.environ.get("CA_ENCRYPTION_KEY")

    if not raw_key:
        # Try Flask config if we're inside an app context
        try:
            from flask import current_app
            raw_key = current_app.config.get("CA_ENCRYPTION_KEY")
        except RuntimeError:
            pass  # No app context

    if not raw_key:
        raise CAKeyEncryptionError(
            "CA_ENCRYPTION_KEY is not set. "
            "Set this environment variable before starting the application."
        )

    # Warn loudly when running with the placeholder in a non-test environment
    env_name = os.environ.get("FLASK_ENV", "").lower()
    if raw_key.startswith("dev-") and env_name not in ("development", "testing", "test"):
        logger.warning(
            "CA_ENCRYPTION_KEY appears to be a development placeholder. "
            "Set a strong random key for production environments."
        )

    # Derive a 32-byte key from the raw secret via SHA-256, then URL-safe base64
    key_bytes = hashlib.sha256(raw_key.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key_bytes)
    return Fernet(fernet_key)


def encrypt_ca_key(plaintext_pem: str) -> str:
    """Encrypt a CA private key PEM string.

    Idempotent: already-encrypted values are returned unchanged.

    Args:
        plaintext_pem: CA private key in OpenSSH/PEM format.

    Returns:
        Encrypted string with ``$fernet$`` prefix, safe for database storage.

    Raises:
        CAKeyEncryptionError: if the key cannot be encrypted.
    """
    if not plaintext_pem:
        raise CAKeyEncryptionError("Cannot encrypt an empty key")

    # Already encrypted — do not double-encrypt
    if plaintext_pem.startswith(_FERNET_PREFIX):
        return plaintext_pem

    try:
        fernet = _get_fernet()
        token = fernet.encrypt(plaintext_pem.encode()).decode()
        return f"{_FERNET_PREFIX}{token}"
    except CAKeyEncryptionError:
        raise
    except Exception as exc:
        raise CAKeyEncryptionError(f"Failed to encrypt CA key: {exc}") from exc


def decrypt_ca_key(stored_value: str) -> str:
    """Decrypt a CA private key retrieved from the database.

    Idempotent: plaintext (legacy) values are returned unchanged so that the
    system continues to work while a migration encrypts existing rows.

    Args:
        stored_value: Value from ``CA.private_key`` column.

    Returns:
        Plaintext PEM string ready for use with ``sshkey_tools``.

    Raises:
        CAKeyEncryptionError: if decryption fails (wrong key, corrupted data).
    """
    if not stored_value:
        raise CAKeyEncryptionError("Cannot decrypt an empty value")

    # Legacy plaintext key — return as-is
    if not stored_value.startswith(_FERNET_PREFIX):
        logger.warning(
            "CA private key appears to be stored as plaintext. "
            "Run the migration to encrypt existing keys."
        )
        return stored_value

    token = stored_value[len(_FERNET_PREFIX):]
    try:
        fernet = _get_fernet()
        return fernet.decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise CAKeyEncryptionError(
            "CA key decryption failed — the CA_ENCRYPTION_KEY may be incorrect "
            "or the stored key is corrupted."
        ) from exc
    except CAKeyEncryptionError:
        raise
    except Exception as exc:
        raise CAKeyEncryptionError(f"Unexpected decryption error: {exc}") from exc


def is_encrypted(stored_value: str) -> bool:
    """Return True if the stored value has the ``$fernet$`` envelope.

    Args:
        stored_value: Value from ``CA.private_key`` column.
    """
    return bool(stored_value and stored_value.startswith(_FERNET_PREFIX))


def reencrypt_ca_key(stored_value: str, old_raw_key: str, new_raw_key: str) -> str:
    """Re-encrypt a CA key with a new encryption key (for key rotation).

    Args:
        stored_value: Current value from ``CA.private_key`` (may or may not be encrypted).
        old_raw_key: The current ``CA_ENCRYPTION_KEY`` value (raw secret string).
        new_raw_key: The new ``CA_ENCRYPTION_KEY`` value to encrypt with.

    Returns:
        New encrypted envelope string.

    Raises:
        CAKeyEncryptionError: if decryption or re-encryption fails.
    """
    # Decrypt with old key
    if stored_value.startswith(_FERNET_PREFIX):
        token = stored_value[len(_FERNET_PREFIX):]
        old_key_bytes = base64.urlsafe_b64encode(hashlib.sha256(old_raw_key.encode()).digest())
        try:
            plaintext = Fernet(old_key_bytes).decrypt(token.encode()).decode()
        except InvalidToken as exc:
            raise CAKeyEncryptionError(
                "Re-encryption failed: could not decrypt with the old key."
            ) from exc
    else:
        # Plaintext
        plaintext = stored_value

    # Re-encrypt with new key
    new_key_bytes = base64.urlsafe_b64encode(hashlib.sha256(new_raw_key.encode()).digest())
    try:
        token = Fernet(new_key_bytes).encrypt(plaintext.encode()).decode()
        return f"{_FERNET_PREFIX}{token}"
    except Exception as exc:
        raise CAKeyEncryptionError(f"Re-encryption with new key failed: {exc}") from exc
