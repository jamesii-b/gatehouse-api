"""Application constants and enums."""
from enum import Enum


class UserStatus(str, Enum):
    """User account status."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"
    COMPLIANCE_SUSPENDED = "compliance_suspended"


class Role(str, Enum):
    """Generic role definitions (hierarchy: Admin > Manager > Member > Viewer > Guest)."""

    ADMIN = "admin"
    MANAGER = "manager"
    MEMBER = "member"
    VIEWER = "viewer"
    GUEST = "guest"


class OrganizationRole(str, Enum):
    """Organization member roles."""

    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    GUEST = "guest"


class AuthMethodType(str, Enum):
    """Authentication method types."""

    PASSWORD = "password"
    TOTP = "totp"
    GOOGLE = "google"
    GITHUB = "github"
    MICROSOFT = "microsoft"
    SAML = "saml"
    OIDC = "oidc"
    WEBAUTHN = "webauthn"


class SessionStatus(str, Enum):
    """Session status."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class AuditAction(str, Enum):
    """Audit log action types."""

    # User actions
    USER_LOGIN = "user.login"
    USER_LOGOUT = "user.logout"
    USER_REGISTER = "user.register"
    USER_UPDATE = "user.update"
    USER_DELETE = "user.delete"
    PASSWORD_CHANGE = "user.password_change"
    PASSWORD_RESET = "user.password_reset"

    # Organization actions
    ORG_CREATE = "org.create"
    ORG_UPDATE = "org.update"
    ORG_DELETE = "org.delete"
    ORG_MEMBER_ADD = "org.member.add"
    ORG_MEMBER_REMOVE = "org.member.remove"
    ORG_MEMBER_ROLE_CHANGE = "org.member.role_change"

    # Session actions
    SESSION_CREATE = "session.create"
    SESSION_REVOKE = "session.revoke"

    # Auth method actions
    AUTH_METHOD_ADD = "auth.method.add"
    AUTH_METHOD_REMOVE = "auth.method.remove"
    TOTP_ENROLL_INITIATED = "totp.enroll.initiated"
    TOTP_ENROLL_COMPLETED = "totp.enroll.completed"
    TOTP_VERIFY_SUCCESS = "totp.verify.success"
    TOTP_VERIFY_FAILED = "totp.verify.failed"
    TOTP_DISABLED = "totp.disabled"
    TOTP_BACKUP_CODE_USED = "totp.backup_code.used"
    TOTP_BACKUP_CODES_REGENERATED = "totp.backup_codes.regenerated"

    # WebAuthn actions
    WEBAUTHN_REGISTER_INITIATED = "webauthn.register.initiated"
    WEBAUTHN_REGISTER_COMPLETED = "webauthn.register.completed"
    WEBAUTHN_REGISTER_FAILED = "webauthn.register.failed"
    WEBAUTHN_LOGIN_INITIATED = "webauthn.login.initiated"
    WEBAUTHN_LOGIN_SUCCESS = "webauthn.login.success"
    WEBAUTHN_LOGIN_FAILED = "webauthn.login.failed"
    WEBAUTHN_CREDENTIAL_DELETED = "webauthn.credential.deleted"
    WEBAUTHN_CREDENTIAL_RENAMED = "webauthn.credential.renamed"

    # Security policy actions
    ORG_SECURITY_POLICY_UPDATE = "org.security_policy.update"
    USER_SECURITY_POLICY_OVERRIDE_UPDATE = "user.security_policy.override_update"
    MFA_POLICY_USER_SUSPENDED = "mfa.policy.user_suspended"
    MFA_POLICY_USER_COMPLIANT = "mfa.policy.user_compliant"

    # External authentication provider actions
    EXTERNAL_AUTH_LINK_INITIATED = "external_auth.link.initiated"
    EXTERNAL_AUTH_LINK_COMPLETED = "external_auth.link.completed"
    EXTERNAL_AUTH_LINK_FAILED = "external_auth.link.failed"
    EXTERNAL_AUTH_UNLINK = "external_auth.unlink"
    EXTERNAL_AUTH_LOGIN = "external_auth.login"
    EXTERNAL_AUTH_LOGIN_FAILED = "external_auth.login.failed"
    EXTERNAL_AUTH_TOKEN_REFRESH = "external_auth.token_refresh"
    EXTERNAL_AUTH_CONFIG_CREATE = "external_auth.config.create"
    EXTERNAL_AUTH_CONFIG_UPDATE = "external_auth.config.update"
    EXTERNAL_AUTH_CONFIG_DELETE = "external_auth.config.delete"

    # SSH Key and Certificate actions
    SSH_KEY_ADDED = "ssh.key.added"
    SSH_KEY_VERIFIED = "ssh.key.verified"
    SSH_KEY_DELETED = "ssh.key.deleted"
    SSH_KEY_VALIDATION_FAILED = "ssh.key.validation.failed"
    SSH_CERT_REQUESTED = "ssh.cert.requested"
    SSH_CERT_ISSUED = "ssh.cert.issued"
    SSH_CERT_FAILED = "ssh.cert.failed"
    SSH_CERT_REVOKED = "ssh.cert.revoked"
    SSH_CERT_EXPIRED = "ssh.cert.expired"

    # CA actions
    CA_CREATED = "ca.created"
    CA_UPDATED = "ca.updated"
    CA_DELETED = "ca.deleted"
    CA_KEY_ROTATED = "ca.key.rotated"

    # Principal actions
    PRINCIPAL_CREATED = "principal.created"
    PRINCIPAL_UPDATED = "principal.updated"
    PRINCIPAL_DELETED = "principal.deleted"
    PRINCIPAL_MEMBER_ADDED = "principal.member.added"
    PRINCIPAL_MEMBER_REMOVED = "principal.member.removed"

    # Department actions
    DEPARTMENT_CREATED = "department.created"
    DEPARTMENT_UPDATED = "department.updated"
    DEPARTMENT_DELETED = "department.deleted"
    DEPARTMENT_MEMBER_ADDED = "department.member.added"
    DEPARTMENT_MEMBER_REMOVED = "department.member.removed"


class OIDCGrantType(str, Enum):
    """OIDC grant types."""

    AUTHORIZATION_CODE = "authorization_code"
    IMPLICIT = "implicit"
    REFRESH_TOKEN = "refresh_token"
    CLIENT_CREDENTIALS = "client_credentials"


class OIDCResponseType(str, Enum):
    """OIDC response types."""

    CODE = "code"
    TOKEN = "token"
    ID_TOKEN = "id_token"


# Error type constants
class ErrorType:
    """Error type constants for API responses."""

    VALIDATION_ERROR = "VALIDATION_ERROR"
    AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR"
    AUTHORIZATION_ERROR = "AUTHORIZATION_ERROR"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    BAD_REQUEST = "BAD_REQUEST"


class MfaPolicyMode(str, Enum):
    """MFA policy mode for organizations."""

    DISABLED = "disabled"
    OPTIONAL = "optional"
    REQUIRE_TOTP = "require_totp"
    REQUIRE_WEBAUTHN = "require_webauthn"
    REQUIRE_TOTP_OR_WEBAUTHN = "require_totp_or_webauthn"


class MfaComplianceStatus(str, Enum):
    """MFA compliance status for users per organization."""

    NOT_APPLICABLE = "not_applicable"
    PENDING = "pending"
    IN_GRACE = "in_grace"
    COMPLIANT = "compliant"
    PAST_DUE = "past_due"
    SUSPENDED = "suspended"


class MfaRequirementOverride(str, Enum):
    """User override for organization MFA requirements."""

    INHERIT = "inherit"
    REQUIRED = "required"
    EXEMPT = "exempt"
