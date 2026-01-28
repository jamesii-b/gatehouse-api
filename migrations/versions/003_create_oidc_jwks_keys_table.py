"""Database migration: Create oidc_jwks_keys table.

Revision ID: 002
Revises: 001
Create Date: 2024-01-01 00:00:00

This migration creates the oidc_jwks_keys table for persisting OIDC signing keys.
"""

from alembic import op
import sqlalchemy as sa

# Revision identifiers
revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade():
    """Create oidc_jwks_keys table."""
    
    op.create_table(
        'oidc_jwks_keys',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
        sa.Column('expires_at', sa.DateTime, nullable=True),
        sa.Column('deleted_at', sa.DateTime, nullable=True),
        sa.Column('kid', sa.String(255), nullable=False),
        sa.Column('key_type', sa.String(50), nullable=False),
        sa.Column('private_key', sa.Text, nullable=False),
        sa.Column('public_key', sa.Text, nullable=False),
        sa.Column('algorithm', sa.String(50), nullable=False),
        sa.Column('is_active', sa.Boolean, default=True, nullable=False),
        sa.Column('is_primary', sa.Boolean, default=False, nullable=False),
    )
    
    # Create unique index on kid
    op.create_index('ix_oidc_jwks_keys_kid', 'oidc_jwks_keys', ['kid'], unique=True)
    
    # Create index on is_active for filtering active keys
    op.create_index('ix_oidc_jwks_keys_is_active', 'oidc_jwks_keys', ['is_active'])


def downgrade():
    """Drop oidc_jwks_keys table."""
    op.drop_index('ix_oidc_jwks_keys_is_active', table_name='oidc_jwks_keys')
    op.drop_index('ix_oidc_jwks_keys_kid', table_name='oidc_jwks_keys')
    op.drop_table('oidc_jwks_keys')