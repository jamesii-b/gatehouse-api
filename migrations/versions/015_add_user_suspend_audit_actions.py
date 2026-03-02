"""Add USER_SUSPEND and USER_UNSUSPEND to auditaction enum.

Revision ID: 015_add_user_suspend_audit_actions
Revises: 014_add_dept_cert_policy
Create Date: 2026-03-02

USER_SUSPEND and USER_UNSUSPEND were added to the Python AuditAction enum
but were never synced to the PostgreSQL auditaction type, causing a
DataError (invalid enum value) whenever an admin suspends or unsuspends a user.
"""
from alembic import op

revision = "015_user_suspend_audit"
down_revision = "014_add_dept_cert_policy"
branch_labels = None
depends_on = None


def upgrade():
    for val in ("USER_SUSPEND", "USER_UNSUSPEND"):
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
