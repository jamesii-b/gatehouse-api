"""Add ORG_OWNERSHIP_TRANSFERRED and USER_HARD_DELETE to auditaction enum.

Revision ID: 018_audit_enum_values
Revises: 017_add_ca_serial_counter
Create Date: 2026-03-02

ORG_OWNERSHIP_TRANSFERRED and USER_HARD_DELETE were added to the Python
AuditAction enum but were never synced to the PostgreSQL auditaction type,
causing a DataError (invalid enum value) when transferring org ownership
or hard-deleting a user.
"""
from alembic import op

revision = "018_audit_enum_values"
down_revision = "017_add_ca_serial_counter"
branch_labels = None
depends_on = None


def upgrade():
    # ALTER TYPE ... ADD VALUE cannot run inside a transaction block in PostgreSQL.
    # Alembic has already opened a transaction on the connection by the time our
    # upgrade() runs, so we must:
    #   1. Roll back that open transaction on the raw psycopg2 connection.
    #   2. Switch to autocommit so the ALTER TYPE runs outside any transaction.
    #   3. Restore the previous state afterwards.
    conn = op.get_bind()
    # SQLAlchemy 2.x: conn.connection is a _ConnectionFairy; .driver_connection is psycopg2
    fairy = conn.connection
    raw = getattr(fairy, "driver_connection", None) or getattr(fairy, "dbapi_connection", fairy)
    # Roll back the open transaction so psycopg2 allows us to change autocommit.
    raw.rollback()
    old_autocommit = raw.autocommit
    raw.autocommit = True
    try:
        with raw.cursor() as cur:
            for val in ("ORG_OWNERSHIP_TRANSFERRED", "USER_HARD_DELETE"):
                cur.execute(
                    "SELECT 1 FROM pg_enum "
                    "WHERE enumlabel = %s "
                    "AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'auditaction')",
                    (val,),
                )
                if not cur.fetchone():
                    cur.execute(f"ALTER TYPE auditaction ADD VALUE '{val}'")
    finally:
        raw.autocommit = old_autocommit


def downgrade():
    # PostgreSQL does not support removing enum values; downgrade is a no-op.
    pass
