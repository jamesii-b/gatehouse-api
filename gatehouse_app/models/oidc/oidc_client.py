"""OIDC Client model."""
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel
from gatehouse_app.utils.constants import OIDCGrantType, OIDCResponseType


class OIDCClient(BaseModel):
    """OIDC client model for OAuth2/OIDC integrations."""

    __tablename__ = "oidc_clients"

    organization_id = db.Column(
        db.String(36), db.ForeignKey("organizations.id"), nullable=False, index=True
    )
    name = db.Column(db.String(255), nullable=False)
    client_id = db.Column(db.String(255), unique=True, nullable=False, index=True)
    client_secret_hash = db.Column(db.String(255), nullable=False)

    # OAuth/OIDC configuration
    redirect_uris = db.Column(db.JSON, nullable=False)       # Allowed redirect URIs
    grant_types = db.Column(db.JSON, nullable=False)         # Allowed grant types
    response_types = db.Column(db.JSON, nullable=False)      # Allowed response types
    scopes = db.Column(db.JSON, nullable=False)              # Allowed scopes

    # Client metadata
    logo_uri = db.Column(db.String(512), nullable=True)
    client_uri = db.Column(db.String(512), nullable=True)
    policy_uri = db.Column(db.String(512), nullable=True)
    tos_uri = db.Column(db.String(512), nullable=True)

    # Settings
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_confidential = db.Column(db.Boolean, default=True, nullable=False)
    require_pkce = db.Column(db.Boolean, default=True, nullable=False)

    # Token lifetimes (in seconds)
    access_token_lifetime = db.Column(db.Integer, default=3600, nullable=False)
    refresh_token_lifetime = db.Column(db.Integer, default=2592000, nullable=False)
    id_token_lifetime = db.Column(db.Integer, default=3600, nullable=False)

    # Relationships
    organization = db.relationship("Organization", back_populates="oidc_clients")

    # OIDC sub-resource relationships (declared here, not monkey-patched elsewhere)
    authorization_codes = db.relationship(
        "OIDCAuthCode", back_populates="client", cascade="all, delete-orphan"
    )
    refresh_tokens = db.relationship(
        "OIDCRefreshToken", back_populates="client", cascade="all, delete-orphan"
    )
    oidc_sessions = db.relationship(
        "OIDCSession", back_populates="client", cascade="all, delete-orphan"
    )
    token_metadata = db.relationship(
        "OIDCTokenMetadata", back_populates="client", cascade="all, delete-orphan"
    )
    audit_logs = db.relationship(
        "OIDCAuditLog", back_populates="client", cascade="all, delete-orphan"
    )

    def __repr__(self):
        """String representation of OIDCClient."""
        return f"<OIDCClient {self.name} client_id={self.client_id}>"

    def to_dict(self, exclude=None):
        """Convert to dictionary, excluding sensitive fields."""
        exclude = exclude or []
        if "client_secret_hash" not in exclude:
            exclude.append("client_secret_hash")
        return super().to_dict(exclude=exclude)

    def has_grant_type(self, grant_type) -> bool:
        """Check if client supports a specific grant type."""
        return grant_type in self.grant_types

    def has_response_type(self, response_type) -> bool:
        """Check if client supports a specific response type."""
        return response_type in self.response_types

    def is_redirect_uri_allowed(self, redirect_uri: str) -> bool:
        """Check if a redirect URI is allowed for this client."""
        return redirect_uri in self.redirect_uris

    def has_scope(self, scope: str) -> bool:
        """Check if client is allowed to request a specific scope."""
        return scope in self.scopes
