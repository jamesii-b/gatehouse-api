"""Add ca_type column to cas table (user/host).

Revision ID: 013
Revises: d34bfb72844e
Create Date: 2026-02-28 23:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '013'
down_revision = 'd34bfb72844e'
branch_labels = None
depends_on = None


def upgrade():
    # Create the enum type first (PostgreSQL requires this)
    ca_type_enum = sa.Enum('user', 'host', name='ca_type_enum')
    ca_type_enum.create(op.get_bind(), checkfirst=True)

    # Add ca_type column with a default of 'user' so existing CAs stay valid
    op.add_column(
        'cas',
        sa.Column(
            'ca_type',
            ca_type_enum,
            nullable=False,
            server_default='user',
        ),
    )


def downgrade():
    op.drop_column('cas', 'ca_type')
    # Drop the enum type (PostgreSQL only; SQLite ignores)
    try:
        op.execute("DROP TYPE IF EXISTS ca_type_enum")
    except Exception:
        pass
