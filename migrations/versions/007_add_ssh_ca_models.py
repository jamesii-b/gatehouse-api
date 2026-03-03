"""Add SSH CA models: SSHKey, SSHCertificate, CA, CertificateAuditLog.

Revision ID: 007
Revises: 006
Create Date: 2026-02-27 11:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '007'
down_revision = '006'
branch_labels = None
depends_on = None


def upgrade():
    # ### CA table ###
    op.create_table('cas',
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('key_type', sa.Enum('ed25519', 'rsa', 'ecdsa', name='ca_key_type_enum'), nullable=False),
        sa.Column('private_key', sa.Text(), nullable=False),
        sa.Column('public_key', sa.Text(), nullable=False),
        sa.Column('fingerprint', sa.String(length=255), nullable=False),
        sa.Column('crl_enabled', sa.Boolean(), nullable=False),
        sa.Column('crl_endpoint', sa.String(length=512), nullable=True),
        sa.Column('default_cert_validity_hours', sa.Integer(), nullable=False),
        sa.Column('max_cert_validity_hours', sa.Integer(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('rotated_at', sa.DateTime(), nullable=True),
        sa.Column('rotation_reason', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('id'),
        sa.UniqueConstraint('fingerprint'),
        sa.UniqueConstraint('organization_id', 'name', name='uix_org_ca_name')
    )
    op.create_index(op.f('ix_cas_organization_id'), 'cas', ['organization_id'], unique=False)
    op.create_index('idx_ca_org_active', 'cas', ['organization_id', 'is_active'], unique=False)

    # ### SSHKey table ###
    op.create_table('ssh_keys',
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('payload', sa.Text(), nullable=False),
        sa.Column('fingerprint', sa.String(length=255), nullable=False),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('verified', sa.Boolean(), nullable=False),
        sa.Column('verified_at', sa.DateTime(), nullable=True),
        sa.Column('verify_text', sa.String(length=255), nullable=True),
        sa.Column('verify_text_created_at', sa.DateTime(), nullable=True),
        sa.Column('key_type', sa.String(length=50), nullable=True),
        sa.Column('key_bits', sa.Integer(), nullable=True),
        sa.Column('key_comment', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('id'),
        sa.UniqueConstraint('payload'),
        sa.UniqueConstraint('fingerprint')
    )
    op.create_index(op.f('ix_ssh_keys_user_id'), 'ssh_keys', ['user_id'], unique=False)
    op.create_index(op.f('ix_ssh_keys_fingerprint'), 'ssh_keys', ['fingerprint'], unique=False)
    op.create_index(op.f('ix_ssh_keys_verified'), 'ssh_keys', ['verified'], unique=False)
    op.create_index('idx_ssh_key_user_verified', 'ssh_keys', ['user_id', 'verified'], unique=False)

    # ### SSHCertificate table ###
    op.create_table('ssh_certificates',
        sa.Column('ca_id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('ssh_key_id', sa.String(length=36), nullable=False),
        sa.Column('certificate', sa.Text(), nullable=False),
        sa.Column('serial', sa.String(length=255), nullable=False),
        sa.Column('key_id', sa.String(length=255), nullable=False),
        sa.Column('cert_type', sa.Enum('user', 'host', name='ssh_cert_type_enum'), nullable=False),
        sa.Column('principals', sa.JSON(), nullable=False),
        sa.Column('valid_after', sa.DateTime(), nullable=False),
        sa.Column('valid_before', sa.DateTime(), nullable=False),
        sa.Column('revoked', sa.Boolean(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('revoke_reason', sa.String(length=255), nullable=True),
        sa.Column('status', sa.Enum('requested', 'issued', 'revoked', 'expired', 'superseded', name='ssh_cert_status_enum'), nullable=False),
        sa.Column('request_ip', sa.String(length=45), nullable=True),
        sa.Column('request_user_agent', sa.String(length=512), nullable=True),
        sa.Column('critical_options', sa.JSON(), nullable=True),
        sa.Column('extensions', sa.JSON(), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['ca_id'], ['cas.id'], ),
        sa.ForeignKeyConstraint(['ssh_key_id'], ['ssh_keys.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('id'),
        sa.UniqueConstraint('serial')
    )
    op.create_index(op.f('ix_ssh_certificates_ca_id'), 'ssh_certificates', ['ca_id'], unique=False)
    op.create_index(op.f('ix_ssh_certificates_user_id'), 'ssh_certificates', ['user_id'], unique=False)
    op.create_index(op.f('ix_ssh_certificates_ssh_key_id'), 'ssh_certificates', ['ssh_key_id'], unique=False)
    op.create_index(op.f('ix_ssh_certificates_serial'), 'ssh_certificates', ['serial'], unique=False)
    op.create_index(op.f('ix_ssh_certificates_revoked'), 'ssh_certificates', ['revoked'], unique=False)
    op.create_index(op.f('ix_ssh_certificates_status'), 'ssh_certificates', ['status'], unique=False)
    op.create_index('idx_cert_user_status', 'ssh_certificates', ['user_id', 'status'], unique=False)
    op.create_index('idx_cert_validity', 'ssh_certificates', ['valid_after', 'valid_before'], unique=False)
    op.create_index('idx_cert_revoked', 'ssh_certificates', ['revoked', 'revoked_at'], unique=False)

    # ### CertificateAuditLog table ###
    op.create_table('certificate_audit_logs',
        sa.Column('certificate_id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=True),
        sa.Column('action', sa.String(length=50), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.String(length=512), nullable=True),
        sa.Column('request_id', sa.String(length=36), nullable=True),
        sa.Column('message', sa.Text(), nullable=True),
        sa.Column('extra_data', sa.JSON(), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['certificate_id'], ['ssh_certificates.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('id')
    )
    op.create_index(op.f('ix_certificate_audit_logs_certificate_id'), 'certificate_audit_logs', ['certificate_id'], unique=False)
    op.create_index(op.f('ix_certificate_audit_logs_user_id'), 'certificate_audit_logs', ['user_id'], unique=False)
    op.create_index(op.f('ix_certificate_audit_logs_action'), 'certificate_audit_logs', ['action'], unique=False)
    op.create_index('idx_cert_audit_cert_action', 'certificate_audit_logs', ['certificate_id', 'action'], unique=False)
    op.create_index('idx_cert_audit_user', 'certificate_audit_logs', ['user_id', 'created_at'], unique=False)


def downgrade():
    op.drop_index('idx_cert_audit_user', table_name='certificate_audit_logs')
    op.drop_index('idx_cert_audit_cert_action', table_name='certificate_audit_logs')
    op.drop_index(op.f('ix_certificate_audit_logs_action'), table_name='certificate_audit_logs')
    op.drop_index(op.f('ix_certificate_audit_logs_user_id'), table_name='certificate_audit_logs')
    op.drop_index(op.f('ix_certificate_audit_logs_certificate_id'), table_name='certificate_audit_logs')
    op.drop_table('certificate_audit_logs')
    
    op.drop_index('idx_cert_revoked', table_name='ssh_certificates')
    op.drop_index('idx_cert_validity', table_name='ssh_certificates')
    op.drop_index('idx_cert_user_status', table_name='ssh_certificates')
    op.drop_index(op.f('ix_ssh_certificates_status'), table_name='ssh_certificates')
    op.drop_index(op.f('ix_ssh_certificates_revoked'), table_name='ssh_certificates')
    op.drop_index(op.f('ix_ssh_certificates_serial'), table_name='ssh_certificates')
    op.drop_index(op.f('ix_ssh_certificates_ssh_key_id'), table_name='ssh_certificates')
    op.drop_index(op.f('ix_ssh_certificates_user_id'), table_name='ssh_certificates')
    op.drop_index(op.f('ix_ssh_certificates_ca_id'), table_name='ssh_certificates')
    op.drop_table('ssh_certificates')
    
    op.drop_index('idx_ssh_key_user_verified', table_name='ssh_keys')
    op.drop_index(op.f('ix_ssh_keys_verified'), table_name='ssh_keys')
    op.drop_index(op.f('ix_ssh_keys_fingerprint'), table_name='ssh_keys')
    op.drop_index(op.f('ix_ssh_keys_user_id'), table_name='ssh_keys')
    op.drop_table('ssh_keys')
    
    op.drop_index('idx_ca_org_active', table_name='cas')
    op.drop_index(op.f('ix_cas_organization_id'), table_name='cas')
    op.drop_table('cas')
