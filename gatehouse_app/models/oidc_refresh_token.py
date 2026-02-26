"""OIDC Refresh Token model for token rotation."""
from datetime import datetime, timezone
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel


class OIDCRefreshToken(BaseModel):
    """OIDC Refresh Token model for token refresh and rotation.

    Refresh tokens are long-lived credentials used to obtain new access tokens.
    They support token rotation for enhanced security.
    """

    __tablename__ = "oidc_refresh_tokens"

    # Client and User references
    client_id = db.Column(
        db.String(255), db.ForeignKey("oidc_clients.id"), nullable=False, index=True
    )
    user_id = db.Column(
        db.String(36), db.ForeignKey("users.id"), nullable=False, index=True
    )

    # Token (hashed for security)
    token_hash = db.Column(db.String(255), nullable=False, unique=True, index=True)

    # Associated access token ID (stores JWT JTI string — no FK to sessions)
    access_token_id = db.Column(
        db.String(255), nullable=True, index=True
    )

    # Token scope
    scope = db.Column(db.JSON, nullable=True)  # Granted scopes

    # Timing
    expires_at = db.Column(db.DateTime, nullable=False, index=True)

    # Revocation tracking
    revoked_at = db.Column(db.DateTime, nullable=True)
    revoked_reason = db.Column(db.String(255), nullable=True)

    # Token rotation metadata
    previous_token_hash = db.Column(db.String(255), nullable=True)  # For rotation
    rotation_count = db.Column(db.Integer, default=0, nullable=False)

    # Request metadata
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)

    # Relationships
    client = db.relationship("OIDCClient", back_populates="refresh_tokens")
    user = db.relationship("User", back_populates="oidc_refresh_tokens")

    def __repr__(self):
        """String representation of OIDCRefreshToken."""
        return f"<OIDCRefreshToken client_id={self.client_id} user_id={self.user_id} revoked={self.is_revoked()}>"

    def is_expired(self):
        """Check if the refresh token has expired."""
        # Handle both timezone-aware and timezone-naive expires_at values
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > expires_at

    def is_revoked(self):
        """Check if the refresh token has been revoked."""
        return self.revoked_at is not None

    def is_valid(self):
        """Check if the refresh token is valid for use."""
        return not self.is_revoked() and not self.is_expired() and self.deleted_at is None

    def revoke(self, reason=None):
        """Revoke the refresh token.

        Args:
            reason: Optional reason for revocation
        """
        self.revoked_at = datetime.now(timezone.utc)
        self.revoked_reason = reason
        db.session.commit()

    def rotate(self, new_token_hash):
        """Rotate the refresh token (invalidate old, create new).

        Args:
            new_token_hash: Hash of the new refresh token

        Returns:
            self for chaining
        """
        # Store reference to old token
        self.previous_token_hash = self.token_hash
        self.token_hash = new_token_hash
        self.rotation_count += 1
        # Extend expiration on rotation
        from datetime import timedelta
        self.expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        db.session.commit()
        return self

    @classmethod
    def create_token(cls, client_id, user_id, token_hash, scope=None,
                     access_token_id=None, ip_address=None, user_agent=None,
                     lifetime_seconds=2592000):
        """Create a new refresh token.

        Args:
            client_id: The OIDC client ID
            user_id: The user ID
            token_hash: Hashed refresh token
            scope: Granted scopes
            access_token_id: Associated access token ID
            ip_address: Client IP address
            user_agent: Client user agent
            lifetime_seconds: Token lifetime in seconds (default 30 days)

        Returns:
            OIDCRefreshToken instance
        """
        from datetime import timedelta
        token = cls(
            client_id=client_id,
            user_id=user_id,
            token_hash=token_hash,
            scope=scope,
            access_token_id=access_token_id,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=lifetime_seconds),
            ip_address=ip_address,
            user_agent=user_agent,
        )
        db.session.add(token)
        db.session.commit()
        return token

    def to_dict(self, exclude=None):
        """Convert to dictionary, excluding sensitive fields."""
        exclude = exclude or []
        # Always exclude token hashes
        exclude.append("token_hash")
        exclude.append("previous_token_hash")
        return super().to_dict(exclude=exclude)


# Add relationship back to User model
from gatehouse_app.models.user import User
User.oidc_refresh_tokens = db.relationship(
    "OIDCRefreshToken", back_populates="user", cascade="all, delete-orphan"
)

# Add relationship back to OIDCClient model
from gatehouse_app.models.oidc_client import OIDCClient
OIDCClient.refresh_tokens = db.relationship(
    "OIDCRefreshToken", back_populates="client", cascade="all, delete-orphan"
)
