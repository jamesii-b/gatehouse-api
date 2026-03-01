"""add org_invite_tokens table

Revision ID: 011_org_invite_tokens
Revises: 010_password_reset_email_verify
Create Date: 2025-01-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = '011_org_invite_tokens'
down_revision = '010_password_reset_email_verify'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'org_invite_tokens',
        sa.Column('id', sa.String(36), primary_key=True, nullable=False),
        sa.Column('organization_id', sa.String(36), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('invited_by_id', sa.String(36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('role', sa.String(64), nullable=False, server_default='member'),
        sa.Column('token', sa.String(128), nullable=False, unique=True),
        sa.Column('expires_at', sa.DateTime, nullable=False),
        sa.Column('accepted_at', sa.DateTime, nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
        sa.Column('deleted_at', sa.DateTime, nullable=True),
    )
    op.create_index('ix_org_invite_tokens_organization_id', 'org_invite_tokens', ['organization_id'])
    op.create_index('ix_org_invite_tokens_email', 'org_invite_tokens', ['email'])
    op.create_index('ix_org_invite_tokens_token', 'org_invite_tokens', ['token'])


def downgrade():
    op.drop_table('org_invite_tokens')
