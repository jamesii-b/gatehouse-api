"""Authentication method model — user credentials and OAuth provider config."""
from datetime import datetime, timedelta, timezone
import secrets
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel
from gatehouse_app.utils.constants import AuthMethodType
from gatehouse_app.utils.encryption import encrypt, decrypt


class AuthenticationMethod(BaseModel):
    """Authentication method model storing user authentication credentials."""

    __tablename__ = "authentication_methods"

    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    method_type = db.Column(db.Enum(AuthMethodType), nullable=False, index=True)

    # For password authentication
    password_hash = db.Column(db.String(255), nullable=True)

    # For OAuth/OIDC providers
    provider_user_id = db.Column(db.String(255), nullable=True)
    provider_data = db.Column(db.JSON, nullable=True)

    # For TOTP authentication
    totp_secret = db.Column(db.String(32), nullable=True)
    totp_backup_codes = db.Column(db.JSON, nullable=True)
    totp_verified_at = db.Column(db.DateTime, nullable=True)

    # Metadata
    is_primary = db.Column(db.Boolean, default=False, nullable=False)
    verified = db.Column(db.Boolean, default=False, nullable=False)
    last_used_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    user = db.relationship("User", back_populates="authentication_methods")

    __table_args__ = (
        db.Index("idx_user_method", "user_id", "method_type"),
        db.UniqueConstraint(
            "user_id", "method_type", "provider_user_id", name="uix_user_method_provider"
        ),
    )

    def __repr__(self):
        """String representation of AuthenticationMethod."""
        return (
            f"<AuthenticationMethod user_id={self.user_id} type={self.method_type}>"
        )

    def is_password(self) -> bool:
        """Check if this is a password authentication method."""
        return self.method_type == AuthMethodType.PASSWORD

    def is_oauth(self) -> bool:
        """Check if this is an OAuth authentication method."""
        return self.method_type in [
            AuthMethodType.GOOGLE,
            AuthMethodType.GITHUB,
            AuthMethodType.MICROSOFT,
        ]

    def is_totp(self) -> bool:
        """Check if this is a TOTP authentication method."""
        return self.method_type == AuthMethodType.TOTP

    def is_webauthn(self) -> bool:
        """Check if this is a WebAuthn authentication method."""
        return self.method_type == AuthMethodType.WEBAUTHN

    def to_dict(self, exclude=None):
        """Convert to dictionary, excluding sensitive fields."""
        exclude = exclude or []
        # Always exclude credential material
        for field in ("password_hash", "totp_secret", "totp_backup_codes"):
            if field not in exclude:
                exclude.append(field)
        return super().to_dict(exclude=exclude)

    def to_webauthn_dict(self):
        """Convert WebAuthn credential to public dictionary.

        Returns:
            Dictionary with safe-to-expose credential information, or None.
        """
        if not self.is_webauthn() or not self.provider_data:
            return None

        data = self.provider_data
        return {
            "id": data.get("credential_id"),
            "name": data.get("name"),
            "transports": data.get("transports", []),
            "created_at": data.get("created_at"),
            "last_used_at": data.get("last_used_at"),
            "sign_count": data.get("sign_count", 0),
        }


class ApplicationProviderConfig(BaseModel):
    """Application-wide OAuth provider configuration.

    Stores OAuth provider credentials at the application level, allowing users
    to authenticate without needing to specify an organization first.
    """

    __tablename__ = "application_provider_configs"

    # Provider identification
    provider_type = db.Column(db.String(50), nullable=False, unique=True, index=True)

    # OAuth credentials (client_secret encrypted at rest)
    client_id = db.Column(db.String(255), nullable=False)
    client_secret_encrypted = db.Column(db.String(512), nullable=True)

    # Provider status
    is_enabled = db.Column(db.Boolean, default=True, nullable=False)

    # Default redirect URL
    default_redirect_url = db.Column(db.String(2048), nullable=True)

    # Provider-specific settings (JSON)
    additional_config = db.Column(db.JSON, nullable=True)

    # Relationships
    organization_overrides = db.relationship(
        "OrganizationProviderOverride",
        back_populates="application_config",
        foreign_keys="OrganizationProviderOverride.provider_type",
        primaryjoin=(
            "ApplicationProviderConfig.provider_type"
            "==OrganizationProviderOverride.provider_type"
        ),
        cascade="all, delete-orphan",
    )

    def __repr__(self):
        """String representation of ApplicationProviderConfig."""
        return (
            f"<ApplicationProviderConfig provider={self.provider_type} "
            f"enabled={self.is_enabled}>"
        )

    def set_client_secret(self, plaintext_secret: str) -> None:
        """Encrypt and store client secret.

        Args:
            plaintext_secret: The plaintext OAuth client secret
        """
        if plaintext_secret:
            self.client_secret_encrypted = encrypt(plaintext_secret)

    def get_client_secret(self) -> str | None:
        """Decrypt and return client secret.

        Returns:
            The plaintext OAuth client secret, or None if not set.
        """
        if self.client_secret_encrypted:
            return decrypt(self.client_secret_encrypted)
        return None

    def to_dict(self, exclude=None):
        """Convert to dictionary, excluding sensitive fields."""
        exclude = exclude or []
        if "client_secret_encrypted" not in exclude:
            exclude.append("client_secret_encrypted")
        return super().to_dict(exclude=exclude)


class OrganizationProviderOverride(BaseModel):
    """Organization-specific OAuth configuration overrides.

    Allows organizations to override application-level OAuth settings for
    enterprise SSO scenarios or custom provider configurations.
    """

    __tablename__ = "organization_provider_overrides"

    organization_id = db.Column(
        db.String(36),
        db.ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )
    provider_type = db.Column(db.String(50), nullable=False, index=True)

    # Override OAuth credentials (encrypted, nullable — only set when overriding)
    client_id = db.Column(db.String(255), nullable=True)
    client_secret_encrypted = db.Column(db.String(512), nullable=True)

    # Provider status
    is_enabled = db.Column(db.Boolean, default=True, nullable=False)

    # Redirect URL override
    redirect_url_override = db.Column(db.String(2048), nullable=True)

    # Provider-specific settings override (JSON)
    additional_config = db.Column(db.JSON, nullable=True)

    # Relationships
    organization = db.relationship("Organization", backref="provider_overrides")
    application_config = db.relationship(
        "ApplicationProviderConfig",
        back_populates="organization_overrides",
        foreign_keys=[provider_type],
        primaryjoin=(
            "ApplicationProviderConfig.provider_type"
            "==OrganizationProviderOverride.provider_type"
        ),
        viewonly=True,
    )

    __table_args__ = (
        db.UniqueConstraint(
            "organization_id", "provider_type", name="uix_org_provider_type"
        ),
    )

    def __repr__(self):
        """String representation of OrganizationProviderOverride."""
        return (
            f"<OrganizationProviderOverride org={self.organization_id} "
            f"provider={self.provider_type}>"
        )

    def set_client_secret(self, plaintext_secret: str) -> None:
        """Encrypt and store client secret override."""
        if plaintext_secret:
            self.client_secret_encrypted = encrypt(plaintext_secret)

    def get_client_secret(self) -> str | None:
        """Decrypt and return client secret override."""
        if self.client_secret_encrypted:
            return decrypt(self.client_secret_encrypted)
        return None

    def to_dict(self, exclude=None):
        """Convert to dictionary, excluding sensitive fields."""
        exclude = exclude or []
        if "client_secret_encrypted" not in exclude:
            exclude.append("client_secret_encrypted")
        return super().to_dict(exclude=exclude)


class OAuthState(BaseModel):
    """OAuth flow state tracking.

    Tracks OAuth authentication flow state, including PKCE parameters and
    organization context (which is optional to support login flows where the
    organization isn't known until after authentication).
    """

    __tablename__ = "oauth_states"

    # OAuth state parameter (unique, used for CSRF protection)
    state = db.Column(db.String(64), unique=True, nullable=False, index=True)

    # Flow type: "login", "register", "link"
    flow_type = db.Column(db.String(50), nullable=False)

    # Provider type
    provider_type = db.Column(db.String(50), nullable=False)

    # User context (optional — not set for login/register flows)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)

    # Organization context (optional — for SSO discovery or post-auth)
    organization_id = db.Column(
        db.String(36), db.ForeignKey("organizations.id"), nullable=True, index=True
    )

    # PKCE parameters
    nonce = db.Column(db.String(128), nullable=True)
    code_verifier = db.Column(db.String(128), nullable=True)
    code_challenge = db.Column(db.String(128), nullable=True)

    # OAuth parameters
    redirect_uri = db.Column(db.String(2048), nullable=True)

    # Post-auth redirect (for frontend routing)
    return_url = db.Column(db.String(2048), nullable=True)

    # Additional state data
    extra_data = db.Column(db.JSON, nullable=True)

    # Expiration and usage tracking
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    used = db.Column(db.Boolean, default=False, nullable=False)

    # Relationships
    user = db.relationship("User", backref="oauth_states")
    organization = db.relationship("Organization", backref="oauth_states")

    def __repr__(self):
        """String representation of OAuthState."""
        return (
            f"<OAuthState state={self.state[:8]}... "
            f"flow={self.flow_type} provider={self.provider_type}>"
        )

    @classmethod
    def create_state(
        cls,
        flow_type: str,
        provider_type: str,
        user_id: str = None,
        organization_id: str = None,
        redirect_uri: str = None,
        return_url: str = None,
        code_verifier: str = None,
        code_challenge: str = None,
        nonce: str = None,
        extra_data: dict = None,
        lifetime_seconds: int = 600,
    ) -> "OAuthState":
        """Create a new OAuth state with an auto-generated state parameter.

        Args:
            flow_type: Type of flow ("login", "register", "link")
            provider_type: OAuth provider type
            user_id: Optional user ID for authenticated flows
            organization_id: Optional organization ID
            redirect_uri: OAuth callback URI
            return_url: Post-auth redirect destination
            code_verifier: PKCE code verifier
            code_challenge: PKCE code challenge
            nonce: OpenID Connect nonce
            extra_data: Additional state data
            lifetime_seconds: How long the state is valid (default 10 minutes)

        Returns:
            New OAuthState instance
        """
        state = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=lifetime_seconds)

        oauth_state = cls(
            state=state,
            flow_type=flow_type,
            provider_type=provider_type,
            user_id=user_id,
            organization_id=organization_id,
            redirect_uri=redirect_uri,
            return_url=return_url,
            code_verifier=code_verifier,
            code_challenge=code_challenge,
            nonce=nonce,
            extra_data=extra_data,
            expires_at=expires_at,
            used=False,
        )
        oauth_state.save()
        return oauth_state

    def is_valid(self) -> bool:
        """Check if the OAuth state is still valid.

        Returns:
            True if state hasn't expired and hasn't been used.
        """
        now = datetime.now(timezone.utc)
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return not self.used and expires_at > now

    def mark_used(self) -> None:
        """Mark the state as used to prevent replay attacks."""
        self.used = True
        self.save()

    @classmethod
    def cleanup_expired(cls) -> None:
        """Remove expired OAuth states."""
        now = datetime.now(timezone.utc)
        cls.query.filter(cls.expires_at < now).delete()
        db.session.commit()

    def to_dict(self, exclude=None):
        """Convert to dictionary, excluding sensitive fields."""
        exclude = exclude or []
        # code_verifier must never be exposed
        if "code_verifier" not in exclude:
            exclude.append("code_verifier")
        return super().to_dict(exclude=exclude)
