"""OIDC Authorization Code model for the authorization code grant flow."""
from datetime import datetime, timedelta, timezone
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel


class OIDCAuthCode(BaseModel):
    """OIDC Authorization Code model for the authorization code grant flow.

    Authorization codes are single-use, short-lived codes. The code itself is
    hashed before storage so that a database breach cannot replay codes.
    """

    __tablename__ = "oidc_authorization_codes"

    # Client and User references
    client_id = db.Column(
        db.String(255), db.ForeignKey("oidc_clients.id"), nullable=False, index=True
    )
    user_id = db.Column(
        db.String(36), db.ForeignKey("users.id"), nullable=False, index=True
    )

    # Authorization code (hashed for security)
    code_hash = db.Column(db.String(255), nullable=False)

    # Request parameters
    redirect_uri = db.Column(db.String(512), nullable=False)
    scope = db.Column(db.JSON, nullable=True)
    nonce = db.Column(db.String(255), nullable=True)
    code_verifier = db.Column(db.String(255), nullable=True)

    # Status tracking
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    used_at = db.Column(db.DateTime, nullable=True)
    is_used = db.Column(db.Boolean, default=False, nullable=False)

    # Request metadata
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)

    # Relationships — back_populates declared on User and OIDCClient
    client = db.relationship("OIDCClient", back_populates="authorization_codes")
    user = db.relationship("User", back_populates="oidc_auth_codes")

    def __repr__(self):
        """String representation of OIDCAuthCode."""
        return (
            f"<OIDCAuthCode client_id={self.client_id} "
            f"user_id={self.user_id} used={self.is_used}>"
        )

    def is_expired(self) -> bool:
        """Check if the authorization code has expired."""
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > expires_at

    def is_valid(self) -> bool:
        """Check if the authorization code is valid for use."""
        return not self.is_used and not self.is_expired() and self.deleted_at is None

    def mark_as_used(self) -> None:
        """Mark the authorization code as used."""
        self.is_used = True
        self.used_at = datetime.now(timezone.utc)
        db.session.commit()

    @classmethod
    def create_code(
        cls,
        client_id: str,
        user_id: str,
        code_hash: str,
        redirect_uri: str,
        scope=None,
        nonce: str = None,
        code_verifier: str = None,
        ip_address: str = None,
        user_agent: str = None,
        lifetime_seconds: int = 600,
    ) -> "OIDCAuthCode":
        """Create a new authorization code.

        Args:
            client_id: The OIDC client ID
            user_id: The user ID
            code_hash: Hashed authorization code
            redirect_uri: The redirect URI
            scope: Requested scopes
            nonce: OIDC nonce
            code_verifier: PKCE code verifier (stored hashed server-side)
            ip_address: Client IP address
            user_agent: Client user agent
            lifetime_seconds: Code lifetime in seconds (default 10 minutes)

        Returns:
            OIDCAuthCode instance
        """
        code = cls(
            client_id=client_id,
            user_id=user_id,
            code_hash=code_hash,
            redirect_uri=redirect_uri,
            scope=scope,
            nonce=nonce,
            code_verifier=code_verifier,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=lifetime_seconds),
            ip_address=ip_address,
            user_agent=user_agent,
        )
        db.session.add(code)
        db.session.commit()
        return code

    def to_dict(self, exclude=None):
        """Convert to dictionary, excluding sensitive fields."""
        exclude = exclude or []
        for field in ("code_hash", "code_verifier"):
            if field not in exclude:
                exclude.append(field)
        return super().to_dict(exclude=exclude)
