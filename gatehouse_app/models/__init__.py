"""Models package.

Sub-packages
------------
models.user         — User, Session
models.organization — Organization, OrganizationMember, Department,
                      DepartmentMembership, DepartmentPrincipal,
                      DepartmentCertPolicy, Principal, PrincipalMembership,
                      OrgInviteToken
models.auth         — AuthenticationMethod, ApplicationProviderConfig,
                      OrganizationProviderOverride, OAuthState,
                      AuditLog, PasswordResetToken, EmailVerificationToken
models.oidc         — OIDCClient, OIDCAuthCode, OIDCRefreshToken, OIDCSession,
                      OIDCTokenMetadata, OIDCAuditLog, OidcJwksKey
models.ssh_ca       — CA, KeyType, CertType, CaType, CAPermission,
                      SSHKey, SSHCertificate, CertificateStatus,
                      CertificateAuditLog
models.security     — OrganizationSecurityPolicy, UserSecurityPolicy,
                      MfaPolicyCompliance

All names are re-exported here so that existing code using the flat import
style (``from gatehouse_app.models import X``) or the old per-file style
(``from gatehouse_app.models.user import User``) continue to work unchanged.
"""

# ── Base ──────────────────────────────────────────────────────────────────────
from gatehouse_app.models.base import BaseModel  # noqa: F401

# ── User ──────────────────────────────────────────────────────────────────────
from gatehouse_app.models.user.user import User  # noqa: F401
from gatehouse_app.models.user.session import Session  # noqa: F401

# ── Organization ──────────────────────────────────────────────────────────────
from gatehouse_app.models.organization.organization import Organization  # noqa: F401
from gatehouse_app.models.organization.organization_member import (  # noqa: F401
    OrganizationMember,
)
from gatehouse_app.models.organization.department import (  # noqa: F401
    Department,
    DepartmentMembership,
    DepartmentPrincipal,
)
from gatehouse_app.models.organization.department_cert_policy import (  # noqa: F401
    DepartmentCertPolicy,
    STANDARD_EXTENSIONS,
)
from gatehouse_app.models.organization.principal import (  # noqa: F401
    Principal,
    PrincipalMembership,
)
from gatehouse_app.models.organization.org_invite_token import OrgInviteToken  # noqa: F401

# ── Auth ──────────────────────────────────────────────────────────────────────
from gatehouse_app.models.auth.authentication_method import (  # noqa: F401
    AuthenticationMethod,
    ApplicationProviderConfig,
    OrganizationProviderOverride,
    OAuthState,
)
from gatehouse_app.models.auth.audit_log import AuditLog  # noqa: F401
from gatehouse_app.models.auth.password_reset_token import PasswordResetToken  # noqa: F401
from gatehouse_app.models.auth.email_verification_token import (  # noqa: F401
    EmailVerificationToken,
)

# ── OIDC ──────────────────────────────────────────────────────────────────────
from gatehouse_app.models.oidc.oidc_client import OIDCClient  # noqa: F401
from gatehouse_app.models.oidc.oidc_authorization_code import OIDCAuthCode  # noqa: F401
from gatehouse_app.models.oidc.oidc_refresh_token import OIDCRefreshToken  # noqa: F401
from gatehouse_app.models.oidc.oidc_session import OIDCSession  # noqa: F401
from gatehouse_app.models.oidc.oidc_token_metadata import OIDCTokenMetadata  # noqa: F401
from gatehouse_app.models.oidc.oidc_audit_log import OIDCAuditLog  # noqa: F401
from gatehouse_app.models.oidc.oidc_jwks_key import OidcJwksKey  # noqa: F401

# ── SSH / CA ──────────────────────────────────────────────────────────────────
from gatehouse_app.models.ssh_ca.ca import (  # noqa: F401
    CA,
    KeyType,
    CertType,
    CaType,
    CAPermission,
)
from gatehouse_app.models.ssh_ca.ssh_key import SSHKey  # noqa: F401
from gatehouse_app.models.ssh_ca.ssh_certificate import (  # noqa: F401
    SSHCertificate,
    CertificateStatus,
)
from gatehouse_app.models.ssh_ca.certificate_audit_log import (  # noqa: F401
    CertificateAuditLog,
)

# ── Security ──────────────────────────────────────────────────────────────────
from gatehouse_app.models.security.organization_security_policy import (  # noqa: F401
    OrganizationSecurityPolicy,
)
from gatehouse_app.models.security.user_security_policy import (  # noqa: F401
    UserSecurityPolicy,
)
from gatehouse_app.models.security.mfa_policy_compliance import (  # noqa: F401
    MfaPolicyCompliance,
)

__all__ = [
    # Base
    "BaseModel",
    # User
    "User",
    "Session",
    # Organization
    "Organization",
    "OrganizationMember",
    "Department",
    "DepartmentMembership",
    "DepartmentPrincipal",
    "DepartmentCertPolicy",
    "STANDARD_EXTENSIONS",
    "Principal",
    "PrincipalMembership",
    "OrgInviteToken",
    # Auth
    "AuthenticationMethod",
    "ApplicationProviderConfig",
    "OrganizationProviderOverride",
    "OAuthState",
    "AuditLog",
    "PasswordResetToken",
    "EmailVerificationToken",
    # OIDC
    "OIDCClient",
    "OIDCAuthCode",
    "OIDCRefreshToken",
    "OIDCSession",
    "OIDCTokenMetadata",
    "OIDCAuditLog",
    "OidcJwksKey",
    # SSH / CA
    "CA",
    "KeyType",
    "CertType",
    "CaType",
    "CAPermission",
    "SSHKey",
    "SSHCertificate",
    "CertificateStatus",
    "CertificateAuditLog",
    # Security
    "OrganizationSecurityPolicy",
    "UserSecurityPolicy",
    "MfaPolicyCompliance",
]
