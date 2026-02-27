"""Sync auditaction enum with all AuditAction Python enum values.

Revision ID: 009
Revises: 008
Create Date: 2026-02-27 15:20:00.000000

The auditaction DB enum was only created with the initial 17 values from 001_base.py.
All TOTP, WebAuthn, OAuth, SSH, CA, Principal, and Department audit actions were added
to the Python enum but never synced to the DB type.
"""
from alembic import op


revision = '009'
down_revision = '008'
branch_labels = None
depends_on = None

MISSING_VALUES = [
    'TOTP_ENROLL_INITIATED', 'TOTP_ENROLL_COMPLETED', 'TOTP_VERIFY_SUCCESS',
    'TOTP_VERIFY_FAILED', 'TOTP_DISABLED', 'TOTP_BACKUP_CODE_USED',
    'TOTP_BACKUP_CODES_REGENERATED', 'WEBAUTHN_REGISTER_INITIATED',
    'WEBAUTHN_REGISTER_COMPLETED', 'WEBAUTHN_REGISTER_FAILED',
    'WEBAUTHN_LOGIN_INITIATED', 'WEBAUTHN_LOGIN_SUCCESS', 'WEBAUTHN_LOGIN_FAILED',
    'WEBAUTHN_CREDENTIAL_DELETED', 'WEBAUTHN_CREDENTIAL_RENAMED',
    'ORG_SECURITY_POLICY_UPDATE', 'USER_SECURITY_POLICY_OVERRIDE_UPDATE',
    'MFA_POLICY_USER_SUSPENDED', 'MFA_POLICY_USER_COMPLIANT',
    'EXTERNAL_AUTH_LINK_INITIATED', 'EXTERNAL_AUTH_LINK_COMPLETED',
    'EXTERNAL_AUTH_LINK_FAILED', 'EXTERNAL_AUTH_UNLINK', 'EXTERNAL_AUTH_LOGIN',
    'EXTERNAL_AUTH_LOGIN_FAILED', 'EXTERNAL_AUTH_TOKEN_REFRESH',
    'EXTERNAL_AUTH_CONFIG_CREATE', 'EXTERNAL_AUTH_CONFIG_UPDATE',
    'EXTERNAL_AUTH_CONFIG_DELETE', 'SSH_KEY_ADDED', 'SSH_KEY_VERIFIED',
    'SSH_KEY_DELETED', 'SSH_KEY_VALIDATION_FAILED', 'SSH_CERT_REQUESTED',
    'SSH_CERT_ISSUED', 'SSH_CERT_FAILED', 'SSH_CERT_REVOKED', 'SSH_CERT_EXPIRED',
    'CA_CREATED', 'CA_UPDATED', 'CA_DELETED', 'CA_KEY_ROTATED',
    'PRINCIPAL_CREATED', 'PRINCIPAL_UPDATED', 'PRINCIPAL_DELETED',
    'PRINCIPAL_MEMBER_ADDED', 'PRINCIPAL_MEMBER_REMOVED',
    'DEPARTMENT_CREATED', 'DEPARTMENT_UPDATED', 'DEPARTMENT_DELETED',
    'DEPARTMENT_MEMBER_ADDED', 'DEPARTMENT_MEMBER_REMOVED',
]


def upgrade():
    for val in MISSING_VALUES:
        op.execute(f"""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_enum
                    WHERE enumlabel = '{val}'
                    AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'auditaction')
                ) THEN
                    ALTER TYPE auditaction ADD VALUE '{val}';
                END IF;
            END$$;
        """)


def downgrade():
    # PostgreSQL does not support removing enum values; downgrade is a no-op.
    pass
