"""Add can_sudo column to departments table.

Revision ID: 002_add_can_sudo_to_departments
Revises: 001_add_org_api_keys
Create Date: 2026-03-07 23:40:30.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '002_add_can_sudo_to_departments'
down_revision = '001_add_org_api_keys'
branch_labels = None
depends_on = None


def upgrade():
    # Add can_sudo column to departments table
    op.add_column('departments',
                  sa.Column('can_sudo', sa.Boolean(), nullable=False, server_default='false'))
    
    # Create index for performance
    op.create_index('idx_dept_can_sudo', 'departments',
                    ['organization_id', 'can_sudo'])


def downgrade():
    # Drop index
    op.drop_index('idx_dept_can_sudo', table_name='departments')
    
    # Drop column
    op.drop_column('departments', 'can_sudo')
