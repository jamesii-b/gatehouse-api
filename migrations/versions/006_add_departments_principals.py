"""Add Department and Principal models for SSH CA management.

Revision ID: 006
Revises: 005
Create Date: 2026-02-27 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '006'
down_revision = '005'
branch_labels = None
depends_on = None


def upgrade():
    # ### Department table ###
    op.create_table('departments',
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('id'),
        sa.UniqueConstraint('organization_id', 'name', name='uix_org_dept_name')
    )
    op.create_index(op.f('ix_departments_organization_id'), 'departments', ['organization_id'], unique=False)
    op.create_index(op.f('ix_departments_name'), 'departments', ['name'], unique=False)

    # ### DepartmentMembership table ###
    op.create_table('department_memberships',
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('department_id', sa.String(length=36), nullable=False),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['department_id'], ['departments.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('id'),
        sa.UniqueConstraint('user_id', 'department_id', name='uix_user_dept')
    )
    op.create_index(op.f('ix_department_memberships_user_id'), 'department_memberships', ['user_id'], unique=False)
    op.create_index(op.f('ix_department_memberships_department_id'), 'department_memberships', ['department_id'], unique=False)

    # ### Principal table ###
    op.create_table('principals',
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('id'),
        sa.UniqueConstraint('organization_id', 'name', name='uix_org_principal_name')
    )
    op.create_index(op.f('ix_principals_organization_id'), 'principals', ['organization_id'], unique=False)
    op.create_index(op.f('ix_principals_name'), 'principals', ['name'], unique=False)

    # ### PrincipalMembership table ###
    op.create_table('principal_memberships',
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('principal_id', sa.String(length=36), nullable=False),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['principal_id'], ['principals.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('id'),
        sa.UniqueConstraint('user_id', 'principal_id', name='uix_user_principal')
    )
    op.create_index(op.f('ix_principal_memberships_user_id'), 'principal_memberships', ['user_id'], unique=False)
    op.create_index(op.f('ix_principal_memberships_principal_id'), 'principal_memberships', ['principal_id'], unique=False)

    # ### DepartmentPrincipal table ###
    op.create_table('department_principals',
        sa.Column('department_id', sa.String(length=36), nullable=False),
        sa.Column('principal_id', sa.String(length=36), nullable=False),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['department_id'], ['departments.id'], ),
        sa.ForeignKeyConstraint(['principal_id'], ['principals.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('id'),
        sa.UniqueConstraint('department_id', 'principal_id', name='uix_dept_principal')
    )
    op.create_index(op.f('ix_department_principals_department_id'), 'department_principals', ['department_id'], unique=False)
    op.create_index(op.f('ix_department_principals_principal_id'), 'department_principals', ['principal_id'], unique=False)


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_department_principals_principal_id'), table_name='department_principals')
    op.drop_index(op.f('ix_department_principals_department_id'), table_name='department_principals')
    op.drop_table('department_principals')
    
    op.drop_index(op.f('ix_principal_memberships_principal_id'), table_name='principal_memberships')
    op.drop_index(op.f('ix_principal_memberships_user_id'), table_name='principal_memberships')
    op.drop_table('principal_memberships')
    
    op.drop_index(op.f('ix_principals_name'), table_name='principals')
    op.drop_index(op.f('ix_principals_organization_id'), table_name='principals')
    op.drop_table('principals')
    
    op.drop_index(op.f('ix_department_memberships_department_id'), table_name='department_memberships')
    op.drop_index(op.f('ix_department_memberships_user_id'), table_name='department_memberships')
    op.drop_table('department_memberships')
    
    op.drop_index(op.f('ix_departments_name'), table_name='departments')
    op.drop_index(op.f('ix_departments_organization_id'), table_name='departments')
    op.drop_table('departments')
    # ### end Alembic commands ###
