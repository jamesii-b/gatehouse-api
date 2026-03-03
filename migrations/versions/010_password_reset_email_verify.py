"""add password reset and email verification token tables

Revision ID: 010_password_reset_email_verify
Revises: 009_sync_auditaction_enum
Create Date: 2025-01-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '010_password_reset_email_verify'
down_revision = '009'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'password_reset_tokens',
        sa.Column('id', sa.String(36), primary_key=True, nullable=False),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('token', sa.String(128), nullable=False, unique=True),
        sa.Column('expires_at', sa.DateTime, nullable=False),
        sa.Column('used_at', sa.DateTime, nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
        sa.Column('deleted_at', sa.DateTime, nullable=True),
    )
    op.create_index('ix_password_reset_tokens_user_id', 'password_reset_tokens', ['user_id'])
    op.create_index('ix_password_reset_tokens_token', 'password_reset_tokens', ['token'])

    op.create_table(
        'email_verification_tokens',
        sa.Column('id', sa.String(36), primary_key=True, nullable=False),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('token', sa.String(128), nullable=False, unique=True),
        sa.Column('expires_at', sa.DateTime, nullable=False),
        sa.Column('used_at', sa.DateTime, nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
        sa.Column('deleted_at', sa.DateTime, nullable=True),
    )
    op.create_index('ix_email_verification_tokens_user_id', 'email_verification_tokens', ['user_id'])
    op.create_index('ix_email_verification_tokens_token', 'email_verification_tokens', ['token'])


def downgrade():
    op.drop_table('email_verification_tokens')
    op.drop_table('password_reset_tokens')
