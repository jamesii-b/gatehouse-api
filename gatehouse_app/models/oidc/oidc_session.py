"""OIDC Session model for OIDC session tracking."""
import hashlib
import base64
from datetime import datetime, timedelta, timezone
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel


class OIDCSession(BaseModel):
    """OIDC Session model for tracking OIDC authentication sessions.

    Tracks the state during the OIDC authorization flow, including PKCE
    parameters and nonce validation.
    """

    __tablename__ = "oidc_sessions"

    # User reference
    user_id = db.Column(
        db.String(36), db.ForeignKey("users.id"), nullable=False, index=True
    )

    # Client reference
    client_id = db.Column(
        db.String(255), db.ForeignKey("oidc_clients.id"), nullable=False, index=True
    )

    # State management
    state = db.Column(db.String(255), nullable=False, index=True)
    nonce = db.Column(db.String(255), nullable=True)

    # Authorization request parameters
    redirect_uri = db.Column(db.String(512), nullable=False)
    scope = db.Column(db.JSON, nullable=True)

    # PKCE parameters
    code_challenge = db.Column(db.String(255), nullable=True)
    code_challenge_method = db.Column(db.String(10), nullable=True)  # "S256" or "plain"

    # Timing
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    authenticated_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    user = db.relationship("User", back_populates="oidc_sessions")
    client = db.relationship("OIDCClient", back_populates="oidc_sessions")

    def __repr__(self):
        """String representation of OIDCSession."""
        return (
            f"<OIDCSession user_id={self.user_id} "
            f"client_id={self.client_id} state={self.state[:8]}...>"
        )

    def is_expired(self) -> bool:
        """Check if the OIDC session has expired."""
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > expires_at

    def is_authenticated(self) -> bool:
        """Check if the user has been authenticated in this session."""
        return self.authenticated_at is not None

    def mark_authenticated(self) -> None:
        """Mark the session as authenticated."""
        self.authenticated_at = datetime.now(timezone.utc)
        db.session.commit()

    def validate_nonce(self, expected_nonce: str) -> bool:
        """Validate the nonce matches the expected value.

        Args:
            expected_nonce: The expected nonce value

        Returns:
            True if nonce matches
        """
        return self.nonce == expected_nonce

    def validate_code_challenge(self, code_verifier: str) -> bool:
        """Validate the code verifier against the stored code challenge.

        Args:
            code_verifier: The PKCE code verifier

        Returns:
            True if the challenge is satisfied
        """
        if not self.code_challenge:
            return False

        if self.code_challenge_method == "S256":
            digest = hashlib.sha256(code_verifier.encode()).digest()
            expected = base64.urlsafe_b64encode(digest).decode().rstrip("=")
            return self.code_challenge == expected
        elif self.code_challenge_method == "plain":
            return self.code_challenge == code_verifier

        return False

    @classmethod
    def create_session(
        cls,
        user_id: str,
        client_id: str,
        state: str,
        redirect_uri: str,
        scope=None,
        nonce: str = None,
        code_challenge: str = None,
        code_challenge_method: str = None,
        lifetime_seconds: int = 600,
    ) -> "OIDCSession":
        """Create a new OIDC session.

        Args:
            user_id: The user ID
            client_id: The OIDC client ID
            state: The state parameter
            redirect_uri: The redirect URI
            scope: Requested scopes
            nonce: OIDC nonce
            code_challenge: PKCE code challenge
            code_challenge_method: PKCE method ("S256" or "plain")
            lifetime_seconds: Session lifetime in seconds

        Returns:
            OIDCSession instance
        """
        session = cls(
            user_id=user_id,
            client_id=client_id,
            state=state,
            redirect_uri=redirect_uri,
            scope=scope,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=lifetime_seconds),
        )
        db.session.add(session)
        db.session.commit()
        return session

    @classmethod
    def get_by_state(cls, state: str) -> "OIDCSession | None":
        """Get a session by state parameter.

        Args:
            state: The state parameter

        Returns:
            OIDCSession instance or None
        """
        return cls.query.filter_by(state=state, deleted_at=None).first()

    def to_dict(self, exclude=None):
        """Convert to dictionary."""
        return super().to_dict(exclude=exclude)
