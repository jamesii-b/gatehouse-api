"""Database migration: Add TOTP support to authentication_methods table.

Revision ID: 002
Revises: 0abed208e728
Create Date: 2026-01-11 00:00:00

This migration adds TOTP (Time-based One-Time Password) support to the
authentication_methods table by adding three new columns:
- totp_secret: Stores the TOTP secret key
- totp_backup_codes: Stores backup codes for account recovery
- totp_verified_at: Tracks when TOTP was verified
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers
revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade():
    """Add TOTP columns to authentication_methods table."""
    
    # Add TOTP secret column
    op.add_column(
        'authentication_methods',
        sa.Column('totp_secret', sa.String(32), nullable=True)
    )
    
    # Add TOTP backup codes column (JSON type for PostgreSQL)
    op.add_column(
        'authentication_methods',
        sa.Column('totp_backup_codes', postgresql.JSON, nullable=True)
    )
    
    # Add TOTP verified at column
    op.add_column(
        'authentication_methods',
        sa.Column('totp_verified_at', sa.DateTime, nullable=True)
    )


def downgrade():
    """Remove TOTP columns from authentication_methods table."""
    
    # Remove TOTP columns in reverse order of addition
    op.drop_column('authentication_methods', 'totp_verified_at')
    op.drop_column('authentication_methods', 'totp_backup_codes')
    op.drop_column('authentication_methods', 'totp_secret')
