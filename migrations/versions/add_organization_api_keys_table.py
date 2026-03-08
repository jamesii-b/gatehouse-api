"""Add organization_api_keys table for API key management.

Revision ID: 001_add_org_api_keys
Revises: 3de11c5dc2d5
Create Date: 2026-03-07 23:40:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '001_add_org_api_keys'
down_revision = '3de11c5dc2d5'
branch_labels = None
depends_on = None


def upgrade():
    # Create organization_api_keys table
    op.create_table(
        'organization_api_keys',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('organization_id', sa.String(36), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('key_hash', sa.String(255), nullable=False),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_revoked', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoke_reason', sa.String(255), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('key_hash'),
    )
    
    # Create indexes for performance
    op.create_index('idx_org_api_key_org_active', 'organization_api_keys',
                    ['organization_id', 'is_revoked'])
    op.create_index('idx_api_key_last_used', 'organization_api_keys',
                    ['last_used_at'])
    op.create_index('idx_org_api_key_org_id', 'organization_api_keys',
                    ['organization_id'])


def downgrade():
    # Drop indexes
    op.drop_index('idx_org_api_key_org_id', table_name='organization_api_keys')
    op.drop_index('idx_api_key_last_used', table_name='organization_api_keys')
    op.drop_index('idx_org_api_key_org_active', table_name='organization_api_keys')
    
    # Drop table
    op.drop_table('organization_api_keys')
