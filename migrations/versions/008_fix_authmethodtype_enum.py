"""Add TOTP and WEBAUTHN to authmethodtype enum.

Revision ID: 008
Revises: 007
Create Date: 2026-02-27 15:00:00.000000

The original migration (001_base) created authmethodtype with only:
  PASSWORD, GOOGLE, GITHUB, MICROSOFT, SAML, OIDC

This migration adds the missing TOTP and WEBAUTHN values so
has_totp_enabled() and has_webauthn_enabled() queries work correctly.
"""
from alembic import op
import sqlalchemy as sa


revision = '008'
down_revision = '007'
branch_labels = None
depends_on = None


def upgrade():
    # Add TOTP to the enum (idempotent approach using DO block)
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_enum
                WHERE enumlabel = 'TOTP'
                AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'authmethodtype')
            ) THEN
                ALTER TYPE authmethodtype ADD VALUE 'TOTP';
            END IF;
        END$$;
    """)
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_enum
                WHERE enumlabel = 'WEBAUTHN'
                AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'authmethodtype')
            ) THEN
                ALTER TYPE authmethodtype ADD VALUE 'WEBAUTHN';
            END IF;
        END$$;
    """)


def downgrade():
    # PostgreSQL does not support removing enum values; downgrade is a no-op.
    pass
