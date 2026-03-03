"""allow_null_ssh_key_id_for_host_certs

Make ssh_certificates.ssh_key_id nullable so that host certificates issued
against a raw server host public key (i.e. not a pre-registered SSHKey record)
can be persisted in the database.

Revision ID: db15faee1fb8
Revises: 018_audit_enum_values
Create Date: 2026-03-03 16:55:54.030674

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'db15faee1fb8'
down_revision = '018_audit_enum_values'
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column(
        'ssh_certificates',
        'ssh_key_id',
        existing_type=sa.VARCHAR(length=36),
        nullable=True,
    )


def downgrade():
    # Null out any rows introduced by host-cert issuance before restoring NOT NULL
    op.execute(
        "UPDATE ssh_certificates SET ssh_key_id = '00000000-0000-0000-0000-000000000000' "
        "WHERE ssh_key_id IS NULL"
    )
    op.alter_column(
        'ssh_certificates',
        'ssh_key_id',
        existing_type=sa.VARCHAR(length=36),
        nullable=False,
    )
