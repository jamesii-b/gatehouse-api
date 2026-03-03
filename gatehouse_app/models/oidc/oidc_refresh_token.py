"""OIDC Refresh Token model for token rotation."""
from datetime import datetime, timedelta, timezone
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel


class OIDCRefreshToken(BaseModel):
    """OIDC Refresh Token model for token refresh and rotation.

    Refresh tokens are long-lived credentials used to obtain new access tokens.
    They support token rotation for enhanced security — each use invalidates
    the old token and issues a new one.
    """

    __tablename__ = "oidc_refresh_tokens"

    # Client and User references
    client_id = db.Column(
        db.String(255), db.ForeignKey("oidc_clients.id"), nullable=False, index=True
    )
    user_id = db.Column(
        db.String(36), db.ForeignKey("users.id"), nullable=False, index=True
    )

    # Token (hashed for security — never store plaintext refresh tokens)
    token_hash = db.Column(db.String(255), nullable=False, unique=True, index=True)

    # Associated access token JTI (no FK — stored as string for lightweight lookup)
    access_token_id = db.Column(db.String(255), nullable=True, index=True)

    # Token scope
    scope = db.Column(db.JSON, nullable=True)

    # Timing
    expires_at = db.Column(db.DateTime, nullable=False, index=True)

    # Revocation tracking
    revoked_at = db.Column(db.DateTime, nullable=True)
    revoked_reason = db.Column(db.String(255), nullable=True)

    # Token rotation metadata
    previous_token_hash = db.Column(db.String(255), nullable=True)
    rotation_count = db.Column(db.Integer, default=0, nullable=False)

    # Request metadata
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)

    # Relationships
    client = db.relationship("OIDCClient", back_populates="refresh_tokens")
    user = db.relationship("User", back_populates="oidc_refresh_tokens")

    def __repr__(self):
        """String representation of OIDCRefreshToken."""
        return (
            f"<OIDCRefreshToken client_id={self.client_id} "
            f"user_id={self.user_id} revoked={self.is_revoked()}>"
        )

    def is_expired(self) -> bool:
        """Check if the refresh token has expired."""
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > expires_at

    def is_revoked(self) -> bool:
        """Check if the refresh token has been revoked."""
        return self.revoked_at is not None

    def is_valid(self) -> bool:
        """Check if the refresh token is valid for use."""
        return not self.is_revoked() and not self.is_expired() and self.deleted_at is None

    def revoke(self, reason: str = None) -> None:
        """Revoke the refresh token.

        Args:
            reason: Optional reason for revocation
        """
        self.revoked_at = datetime.now(timezone.utc)
        self.revoked_reason = reason
        db.session.commit()

    def rotate(self, new_token_hash: str) -> "OIDCRefreshToken":
        """Rotate the refresh token — invalidate the old hash, store the new one.

        Args:
            new_token_hash: Hash of the new refresh token

        Returns:
            self for chaining
        """
        self.previous_token_hash = self.token_hash
        self.token_hash = new_token_hash
        self.rotation_count += 1
        self.expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        db.session.commit()
        return self

    @classmethod
    def create_token(
        cls,
        client_id: str,
        user_id: str,
        token_hash: str,
        scope=None,
        access_token_id: str = None,
        ip_address: str = None,
        user_agent: str = None,
        lifetime_seconds: int = 2592000,
    ) -> "OIDCRefreshToken":
        """Create a new refresh token.

        Args:
            client_id: The OIDC client ID
            user_id: The user ID
            token_hash: Hashed refresh token
            scope: Granted scopes
            access_token_id: Associated access token JTI
            ip_address: Client IP address
            user_agent: Client user agent
            lifetime_seconds: Token lifetime in seconds (default 30 days)

        Returns:
            OIDCRefreshToken instance
        """
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
        for field in ("token_hash", "previous_token_hash"):
            if field not in exclude:
                exclude.append(field)
        return super().to_dict(exclude=exclude)
