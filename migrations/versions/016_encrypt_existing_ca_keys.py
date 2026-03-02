"""Encrypt existing plaintext CA private keys at rest.

Revision ID: 016_encrypt_existing_ca_keys
Revises: 015_add_user_suspend_audit_actions
Create Date: 2026-03-02

All CA private keys created before this migration were stored as plaintext PEM
strings in the ``cas.private_key`` column.  This migration detects those rows
(by checking for the absence of the ``$fernet$`` prefix that encrypted values
carry) and re-encrypts them with the key derived from ``CA_ENCRYPTION_KEY``.

The migration is safe to re-run: already-encrypted rows are left untouched.

Prerequisites
-------------
``CA_ENCRYPTION_KEY`` must be set in the environment before running this
migration.  The same value must be configured for the running application.

To roll back to plaintext (downgrade):
The ``downgrade()`` function decrypts all rows back to plaintext PEM.  This is
provided only for emergency rollback and should not be used in production once
the system has been running with encrypted keys.
"""
import os
import base64
import hashlib
import logging

from alembic import op
import sqlalchemy as sa
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Alembic revision identifiers
revision = "016_encrypt_ca_keys"
down_revision = "015_user_suspend_audit"
branch_labels = None
depends_on = None

_FERNET_PREFIX = "$fernet$"


def _get_fernet():
    """Build a Fernet instance from CA_ENCRYPTION_KEY env var."""
    from cryptography.fernet import Fernet

    raw_key = os.environ.get("CA_ENCRYPTION_KEY")
    if not raw_key:
        raise RuntimeError(
            "CA_ENCRYPTION_KEY environment variable is not set. "
            "Set it before running this migration."
        )
    key_bytes = base64.urlsafe_b64encode(hashlib.sha256(raw_key.encode()).digest())
    return Fernet(key_bytes)


def upgrade():
    """Encrypt plaintext CA private keys."""
    bind = op.get_bind()
    session = Session(bind=bind)

    try:
        fernet = _get_fernet()
    except RuntimeError as exc:
        raise RuntimeError(str(exc)) from exc

    # Fetch all non-deleted CA rows
    rows = session.execute(
        sa.text("SELECT id, private_key FROM cas WHERE deleted_at IS NULL")
    ).fetchall()

    encrypted_count = 0
    skipped_count = 0

    for row in rows:
        ca_id, private_key = row[0], row[1]

        if not private_key:
            logger.warning(f"CA {ca_id} has empty private_key — skipping")
            skipped_count += 1
            continue

        if private_key.startswith(_FERNET_PREFIX):
            # Already encrypted
            skipped_count += 1
            continue

        # Encrypt
        try:
            token = fernet.encrypt(private_key.encode()).decode()
            encrypted_value = f"{_FERNET_PREFIX}{token}"
            session.execute(
                sa.text("UPDATE cas SET private_key = :pk WHERE id = :id"),
                {"pk": encrypted_value, "id": ca_id},
            )
            encrypted_count += 1
            logger.info(f"Encrypted private key for CA {ca_id}")
        except Exception as exc:
            session.rollback()
            raise RuntimeError(
                f"Failed to encrypt private key for CA {ca_id}: {exc}"
            ) from exc

    session.commit()
    logger.info(
        f"CA key encryption migration complete: "
        f"{encrypted_count} encrypted, {skipped_count} skipped"
    )
    print(
        f"  [016_encrypt_ca_keys] {encrypted_count} CA private key(s) encrypted, "
        f"{skipped_count} already encrypted or empty."
    )


def downgrade():
    """Decrypt CA private keys back to plaintext (emergency rollback only)."""
    bind = op.get_bind()
    session = Session(bind=bind)

    try:
        fernet = _get_fernet()
    except RuntimeError as exc:
        raise RuntimeError(str(exc)) from exc

    rows = session.execute(
        sa.text("SELECT id, private_key FROM cas WHERE deleted_at IS NULL")
    ).fetchall()

    decrypted_count = 0
    skipped_count = 0

    for row in rows:
        ca_id, private_key = row[0], row[1]

        if not private_key or not private_key.startswith(_FERNET_PREFIX):
            skipped_count += 1
            continue

        token = private_key[len(_FERNET_PREFIX):]
        try:
            from cryptography.fernet import InvalidToken
            try:
                plaintext = fernet.decrypt(token.encode()).decode()
            except InvalidToken as exc:
                raise RuntimeError(
                    f"Downgrade failed: cannot decrypt CA {ca_id} — wrong key or corrupted data."
                ) from exc

            session.execute(
                sa.text("UPDATE cas SET private_key = :pk WHERE id = :id"),
                {"pk": plaintext, "id": ca_id},
            )
            decrypted_count += 1
            logger.warning(f"Decrypted (plaintext restore) private key for CA {ca_id}")
        except RuntimeError:
            session.rollback()
            raise

    session.commit()
    logger.warning(
        f"CA key decryption (downgrade) complete: "
        f"{decrypted_count} decrypted, {skipped_count} skipped"
    )
    print(
        f"  [016_encrypt_ca_keys] DOWNGRADE: {decrypted_count} CA private key(s) "
        f"decrypted to plaintext. WARNING: keys are now unencrypted at rest."
    )
