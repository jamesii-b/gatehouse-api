"""Make CA.organization_id nullable (system CA) and add cert_id to sign response

Revision ID: 012_ca_nullable_org_and_cert_serial
Revises: 011_org_invite_tokens
Create Date: 2025-01-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = '012_ca_nullable_org'
down_revision = '011_org_invite_tokens'
branch_labels = None
depends_on = None


def upgrade():
    # Allow CA records without an org (e.g. the global system-config CA)
    with op.batch_alter_table('cas', schema=None) as batch_op:
        batch_op.alter_column(
            'organization_id',
            existing_type=sa.String(36),
            nullable=True,
        )


def downgrade():
    with op.batch_alter_table('cas', schema=None) as batch_op:
        batch_op.alter_column(
            'organization_id',
            existing_type=sa.String(36),
            nullable=False,
        )
