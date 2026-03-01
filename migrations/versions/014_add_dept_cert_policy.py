"""add_department_cert_policies

Adds the department_cert_policies table which stores per-department
SSH certificate issuance rules:
  - whether users may choose their own expiry
  - default and maximum expiry durations
  - allowed SSH certificate extensions
"""

from alembic import op
import sqlalchemy as sa

revision = "014_add_dept_cert_policy"
down_revision = "013"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "department_cert_policies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("department_id", sa.String(36), sa.ForeignKey("departments.id"), nullable=False, unique=True),
        # Whether users are allowed to specify their own expiry (up to max)
        sa.Column("allow_user_expiry", sa.Boolean(), nullable=False, server_default="0"),
        # Default validity in hours (used when user doesn't specify, or not allowed to)
        sa.Column("default_expiry_hours", sa.Integer(), nullable=False, server_default="1"),
        # Hard cap on validity; admin cannot be exceeded
        sa.Column("max_expiry_hours", sa.Integer(), nullable=False, server_default="24"),
        # JSON list of extension names that are enabled for this department
        # e.g. ["permit-pty", "permit-agent-forwarding"]
        sa.Column("allowed_extensions", sa.JSON(), nullable=False, server_default='["permit-pty","permit-agent-forwarding","permit-X11-forwarding","permit-port-forwarding","permit-user-rc"]'),
        # Admin-defined custom extension names beyond the standard five
        sa.Column("custom_extensions", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("deleted_at", sa.DateTime(), nullable=True),
    )
    op.create_index("idx_dept_cert_policy_dept", "department_cert_policies", ["department_id"])


def downgrade():
    op.drop_index("idx_dept_cert_policy_dept", "department_cert_policies")
    op.drop_table("department_cert_policies")
