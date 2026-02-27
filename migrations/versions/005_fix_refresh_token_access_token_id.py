"""Fix oidc_refresh_tokens.access_token_id — widen column and drop wrong FK

The access_token_id column was VARCHAR(36) with a foreign key to sessions.id.
In practice the code stores JWT JTI strings (43+ chars) in this column, not
session UUIDs, so the FK constraint was wrong and the column was too narrow.

This migration:
  1. Drops the foreign key constraint to sessions.id (IF EXISTS — may have been
     applied manually already via raw SQL)
  2. Widens the column to VARCHAR(255)

Revision ID: 005
Revises: d2fd4f159054
Create Date: 2026-02-25
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector


# revision identifiers, used by Alembic.
revision = '005'
down_revision = 'd2fd4f159054'
branch_labels = None
depends_on = None


def _fk_exists(conn, table_name, constraint_name):
    """Check whether a named FK constraint exists on a table."""
    insp = Inspector.from_engine(conn)
    fks = insp.get_foreign_keys(table_name)
    return any(fk.get('name') == constraint_name for fk in fks)


def upgrade():
    conn = op.get_bind()

    # Drop the incorrect FK to sessions.id only if it still exists
    # (may have been removed manually before this migration was written)
    if _fk_exists(conn, 'oidc_refresh_tokens', 'oidc_refresh_tokens_access_token_id_fkey'):
        op.drop_constraint(
            'oidc_refresh_tokens_access_token_id_fkey',
            'oidc_refresh_tokens',
            type_='foreignkey'
        )

    # Widen the column to hold JWT JTI strings (43+ chars)
    op.alter_column(
        'oidc_refresh_tokens',
        'access_token_id',
        existing_type=sa.String(length=36),
        type_=sa.String(length=255),
        existing_nullable=True
    )


def downgrade():
    op.alter_column(
        'oidc_refresh_tokens',
        'access_token_id',
        existing_type=sa.String(length=255),
        type_=sa.String(length=36),
        existing_nullable=True
    )
    # Re-add the FK constraint to sessions.id
    op.create_foreign_key(
        'oidc_refresh_tokens_access_token_id_fkey',
        'oidc_refresh_tokens',
        'sessions',
        ['access_token_id'],
        ['id']
    )
