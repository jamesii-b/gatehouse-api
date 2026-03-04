"""Convert audit_logs.action from auditaction enum to VARCHAR(100).

Revision ID: 019_audit_varchar
Revises: 018_audit_enum_values, db15faee1fb8
Create Date: 2026-03-04

WHY
---
The PostgreSQL `auditaction` ENUM type must be explicitly altered every time a
new AuditAction is added to the Python enum, otherwise the INSERT fails with:

    psycopg2.errors.InvalidTextRepresentation:
    invalid input value for enum auditaction: "admin.mfa.remove"

The Python enum was refactored from UPPER_SNAKE_CASE to lower.dot.case string
values, but only the UPPER_SNAKE_CASE values exist in the DB type.  Rather
than add every new value forever, we convert the column to VARCHAR(100) which
accepts any string — the Python layer already validates the value via the Enum.

DATA MIGRATION
--------------
All existing rows store UPPER_SNAKE_CASE values.  We map each one to the
corresponding new lower.dot.case string so historical audit logs remain
queryable with the current enum.
"""
from alembic import op
import sqlalchemy as sa

revision = "019_audit_varchar"
down_revision = ("018_audit_enum_values", "db15faee1fb8")
branch_labels = None
depends_on = None

# Map every UPPER_SNAKE_CASE DB value → its new lower.dot.case Python value.
VALUE_MAP = {
    "USER_LOGIN":                          "user.login",
    "USER_LOGOUT":                         "user.logout",
    "USER_REGISTER":                       "user.register",
    "USER_UPDATE":                         "user.update",
    "USER_DELETE":                         "user.delete",
    "USER_HARD_DELETE":                    "user.hard_delete",
    "USER_SUSPEND":                        "user.suspend",
    "USER_UNSUSPEND":                      "user.unsuspend",
    "PASSWORD_CHANGE":                     "user.password_change",
    "PASSWORD_RESET":                      "user.password_reset",
    "ORG_CREATE":                          "org.create",
    "ORG_UPDATE":                          "org.update",
    "ORG_DELETE":                          "org.delete",
    "ORG_MEMBER_ADD":                      "org.member.add",
    "ORG_MEMBER_REMOVE":                   "org.member.remove",
    "ORG_MEMBER_ROLE_CHANGE":              "org.member.role_change",
    "ORG_OWNERSHIP_TRANSFERRED":           "org.ownership.transferred",
    "SESSION_CREATE":                      "session.create",
    "SESSION_REVOKE":                      "session.revoke",
    "AUTH_METHOD_ADD":                     "auth.method.add",
    "AUTH_METHOD_REMOVE":                  "auth.method.remove",
    "TOTP_ENROLL_INITIATED":               "totp.enroll.initiated",
    "TOTP_ENROLL_COMPLETED":               "totp.enroll.completed",
    "TOTP_VERIFY_SUCCESS":                 "totp.verify.success",
    "TOTP_VERIFY_FAILED":                  "totp.verify.failed",
    "TOTP_DISABLED":                       "totp.disabled",
    "TOTP_BACKUP_CODE_USED":               "totp.backup_code.used",
    "TOTP_BACKUP_CODES_REGENERATED":       "totp.backup_codes.regenerated",
    "WEBAUTHN_REGISTER_INITIATED":         "webauthn.register.initiated",
    "WEBAUTHN_REGISTER_COMPLETED":         "webauthn.register.completed",
    "WEBAUTHN_REGISTER_FAILED":            "webauthn.register.failed",
    "WEBAUTHN_LOGIN_INITIATED":            "webauthn.login.initiated",
    "WEBAUTHN_LOGIN_SUCCESS":              "webauthn.login.success",
    "WEBAUTHN_LOGIN_FAILED":               "webauthn.login.failed",
    "WEBAUTHN_CREDENTIAL_DELETED":         "webauthn.credential.deleted",
    "WEBAUTHN_CREDENTIAL_RENAMED":         "webauthn.credential.renamed",
    "ORG_SECURITY_POLICY_UPDATE":          "org.security_policy.update",
    "USER_SECURITY_POLICY_OVERRIDE_UPDATE":"user.security_policy.override_update",
    "MFA_POLICY_USER_SUSPENDED":           "mfa.policy.user_suspended",
    "MFA_POLICY_USER_COMPLIANT":           "mfa.policy.user_compliant",
    "EXTERNAL_AUTH_LINK_INITIATED":        "external_auth.link.initiated",
    "EXTERNAL_AUTH_LINK_COMPLETED":        "external_auth.link.completed",
    "EXTERNAL_AUTH_LINK_FAILED":           "external_auth.link.failed",
    "EXTERNAL_AUTH_UNLINK":                "external_auth.unlink",
    "EXTERNAL_AUTH_LOGIN":                 "external_auth.login",
    "EXTERNAL_AUTH_LOGIN_FAILED":          "external_auth.login.failed",
    "EXTERNAL_AUTH_TOKEN_REFRESH":         "external_auth.token_refresh",
    "EXTERNAL_AUTH_CONFIG_CREATE":         "external_auth.config.create",
    "EXTERNAL_AUTH_CONFIG_UPDATE":         "external_auth.config.update",
    "EXTERNAL_AUTH_CONFIG_DELETE":         "external_auth.config.delete",
    "SSH_KEY_ADDED":                       "ssh.key.added",
    "SSH_KEY_VERIFIED":                    "ssh.key.verified",
    "SSH_KEY_DELETED":                     "ssh.key.deleted",
    "SSH_KEY_VALIDATION_FAILED":           "ssh.key.validation.failed",
    "SSH_CERT_REQUESTED":                  "ssh.cert.requested",
    "SSH_CERT_ISSUED":                     "ssh.cert.issued",
    "SSH_CERT_FAILED":                     "ssh.cert.failed",
    "SSH_CERT_REVOKED":                    "ssh.cert.revoked",
    "SSH_CERT_EXPIRED":                    "ssh.cert.expired",
    "CA_CREATED":                          "ca.created",
    "CA_UPDATED":                          "ca.updated",
    "CA_DELETED":                          "ca.deleted",
    "CA_KEY_ROTATED":                      "ca.key.rotated",
    "PRINCIPAL_CREATED":                   "principal.created",
    "PRINCIPAL_UPDATED":                   "principal.updated",
    "PRINCIPAL_DELETED":                   "principal.deleted",
    "PRINCIPAL_MEMBER_ADDED":              "principal.member.added",
    "PRINCIPAL_MEMBER_REMOVED":            "principal.member.removed",
    "DEPARTMENT_CREATED":                  "department.created",
    "DEPARTMENT_UPDATED":                  "department.updated",
    "DEPARTMENT_DELETED":                  "department.deleted",
    "DEPARTMENT_MEMBER_ADDED":             "department.member.added",
    "DEPARTMENT_MEMBER_REMOVED":           "department.member.removed",
}


def upgrade():
    conn = op.get_bind()

    # 1. Add a temporary VARCHAR column
    op.add_column("audit_logs", sa.Column("action_new", sa.String(100), nullable=True))

    # 2. Populate it: map old UPPER_SNAKE_CASE to new lower.dot.case
    for old_val, new_val in VALUE_MAP.items():
        conn.execute(
            sa.text("UPDATE audit_logs SET action_new = :new WHERE action::text = :old"),
            {"new": new_val, "old": old_val},
        )

    # 3. Any unmapped rows (shouldn't exist, but be safe): copy as-is
    conn.execute(sa.text("UPDATE audit_logs SET action_new = action::text WHERE action_new IS NULL"))

    # 4. Drop the old enum column, rename the new one
    op.drop_column("audit_logs", "action")
    op.alter_column("audit_logs", "action_new", new_column_name="action", nullable=False)

    # 5. Recreate the index (was on the old column)
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("idx_audit_user_action", "audit_logs", ["user_id", "action"])

    # 6. Drop the now-unused auditaction enum type
    op.execute("DROP TYPE IF EXISTS auditaction")


def downgrade():
    # Converting VARCHAR back to a custom enum is complex and lossy for new
    # values — provide a no-op downgrade.  Run a previous backup to revert.
    pass
