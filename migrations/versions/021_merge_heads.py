"""Merge 020_ca_serial_timestamp_start and 002_add_can_sudo_to_departments into a single head.

Revision ID: 021_merge_heads
Revises: 020_ca_serial_timestamp_start, 002_add_can_sudo_to_departments
Create Date: 2026-03-09

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = '021_merge_heads'
down_revision = ('020_ca_serial_timestamp_start', '002_add_can_sudo_to_departments')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
