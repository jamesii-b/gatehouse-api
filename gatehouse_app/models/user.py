"""User model."""
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel
from gatehouse_app.utils.constants import UserStatus


class User(BaseModel):
    """User model representing a user account."""

    __tablename__ = "users"

    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    full_name = db.Column(db.String(255), nullable=True)
    avatar_url = db.Column(db.String(512), nullable=True)
    status = db.Column(
        db.Enum(UserStatus), default=UserStatus.ACTIVE, nullable=False, index=True
    )
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(45), nullable=True)

    # Relationships
    authentication_methods = db.relationship(
        "AuthenticationMethod", back_populates="user", cascade="all, delete-orphan"
    )
    sessions = db.relationship("Session", back_populates="user", cascade="all, delete-orphan")
    organization_memberships = db.relationship(
        "OrganizationMember",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="OrganizationMember.user_id",
    )
    audit_logs = db.relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    security_policies = db.relationship(
        "UserSecurityPolicy",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="UserSecurityPolicy.user_id",
    )
    mfa_compliance = db.relationship(
        "MfaPolicyCompliance",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="MfaPolicyCompliance.user_id",
    )
    department_memberships = db.relationship(
        "DepartmentMembership",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="DepartmentMembership.user_id",
    )
    principal_memberships = db.relationship(
        "PrincipalMembership",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="PrincipalMembership.user_id",
    )
    ssh_keys = db.relationship(
        "SSHKey",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="SSHKey.user_id",
    )
    ssh_certificates = db.relationship(
        "SSHCertificate",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="SSHCertificate.user_id",
    )

    def __repr__(self):
        """String representation of User."""
        return f"<User {self.email}>"

    def to_dict(self, exclude=None):
        """Convert user to dictionary, excluding sensitive fields by default."""
        exclude = exclude or []
        # Always exclude password-related fields
        default_exclude = []
        all_exclude = list(set(default_exclude + exclude))
        return super().to_dict(exclude=all_exclude)

    def has_password_auth(self):
        """Check if user has password authentication enabled."""
        from gatehouse_app.models.authentication_method import AuthenticationMethod
        from gatehouse_app.utils.constants import AuthMethodType

        return (
            AuthenticationMethod.query.filter_by(
                user_id=self.id, method_type=AuthMethodType.PASSWORD, deleted_at=None
            ).first()
            is not None
        )

    def get_organizations(self):
        """Get all organizations the user is a member of."""
        return [membership.organization for membership in self.organization_memberships]

    def has_totp_enabled(self) -> bool:
        """Check if user has TOTP enabled and verified.

        Returns:
            True if user has a verified TOTP authentication method, False otherwise.
        """
        from gatehouse_app.models.authentication_method import AuthenticationMethod
        from gatehouse_app.utils.constants import AuthMethodType

        return (
            AuthenticationMethod.query.filter_by(
                user_id=self.id,
                method_type=AuthMethodType.TOTP,
                verified=True,
                deleted_at=None,
            ).first()
            is not None
        )

    def get_totp_method(self):
        """Get user's TOTP authentication method.

        Returns:
            The AuthenticationMethod instance for TOTP or None if not found.
            
        Note:
            Returns the most recently created TOTP method to handle cases where
            multiple enrollment attempts may exist.
        """
        from gatehouse_app.models.authentication_method import AuthenticationMethod
        from gatehouse_app.utils.constants import AuthMethodType

        return AuthenticationMethod.query.filter_by(
            user_id=self.id, method_type=AuthMethodType.TOTP, deleted_at=None
        ).order_by(AuthenticationMethod.created_at.desc()).first()

    def has_webauthn_enabled(self) -> bool:
        """Check if user has any WebAuthn passkey credentials.

        Returns:
            True if user has at least one WebAuthn credential, False otherwise.
        """
        from gatehouse_app.models.authentication_method import AuthenticationMethod
        from gatehouse_app.utils.constants import AuthMethodType

        return (
            AuthenticationMethod.query.filter_by(
                user_id=self.id,
                method_type=AuthMethodType.WEBAUTHN,
                deleted_at=None,
            ).first()
            is not None
        )

    def get_webauthn_credentials(self):
        """Get all WebAuthn credentials for the user.

        Returns:
            List of AuthenticationMethod instances for WebAuthn, ordered by creation date.
        """
        from gatehouse_app.models.authentication_method import AuthenticationMethod
        from gatehouse_app.utils.constants import AuthMethodType

        return AuthenticationMethod.query.filter_by(
            user_id=self.id, method_type=AuthMethodType.WEBAUTHN, deleted_at=None
        ).order_by(AuthenticationMethod.created_at.desc()).all()

    def get_webauthn_credential_count(self) -> int:
        """Get the count of WebAuthn credentials for the user.

        Returns:
            Number of WebAuthn credentials.
        """
        from gatehouse_app.models.authentication_method import AuthenticationMethod
        from gatehouse_app.utils.constants import AuthMethodType

        return AuthenticationMethod.query.filter_by(
            user_id=self.id, method_type=AuthMethodType.WEBAUTHN, deleted_at=None
        ).count()
