"""add_activation_fields_and_ca_permissions

Revision ID: d34bfb72844e
Revises: 012_ca_nullable_org
Create Date: 2026-02-28 18:06:47.328552

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'd34bfb72844e'
down_revision = '012_ca_nullable_org'
branch_labels = None
depends_on = None


def upgrade():
    # Create ca_permissions table
    op.create_table(
        'ca_permissions',
        sa.Column('ca_id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('permission', sa.String(length=50), nullable=False),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['ca_id'], ['cas.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('ca_id', 'user_id', name='uix_ca_permission'),
    )
    op.create_index('ix_ca_permissions_ca_id', 'ca_permissions', ['ca_id'], unique=False)
    op.create_index('ix_ca_permissions_user_id', 'ca_permissions', ['user_id'], unique=False)

    # Add activation columns to users
    op.add_column('users', sa.Column('activated', sa.Boolean(), nullable=False,
                                     server_default=sa.text('true')))
    op.add_column('users', sa.Column('activation_key', sa.String(length=128), nullable=True))
    op.create_index('ix_users_activation_key', 'users', ['activation_key'], unique=True)


def downgrade():
    op.drop_index('ix_users_activation_key', table_name='users')
    op.drop_column('users', 'activation_key')
    op.drop_column('users', 'activated')
    op.drop_index('ix_ca_permissions_user_id', table_name='ca_permissions')
    op.drop_index('ix_ca_permissions_ca_id', table_name='ca_permissions')
    op.drop_table('ca_permissions')
