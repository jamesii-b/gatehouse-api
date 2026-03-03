"""Add monotonic serial counter to CAs table.

Each CA now owns a `next_serial_number` (BigInteger) that is atomically
incremented every time a certificate is signed.  This guarantees:
  - Serials are unique per CA
  - Serials are monotonically increasing (auditable, no gaps by accident)
  - The value embedded in the OpenSSH certificate matches what is stored
    in the `ssh_certificates.serial` column

Revision ID: 017_add_ca_serial_counter
Revises: 016_encrypt_ca_keys
Create Date: 2026-03-02
"""
from alembic import op
import sqlalchemy as sa

revision = "017_add_ca_serial_counter"
down_revision = "016_encrypt_ca_keys"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("cas", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "next_serial_number",
                sa.BigInteger(),
                nullable=False,
                server_default="1",
            )
        )


def downgrade():
    with op.batch_alter_table("cas", schema=None) as batch_op:
        batch_op.drop_column("next_serial_number")
