"""OIDC JWKS Key model for persisting signing keys."""
from datetime import datetime, timezone
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel


class OidcJwksKey(BaseModel):
    """OIDC JWKS Key model for persisting JSON Web Key Set signing keys.

    Stores RSA/ECDSA key pairs used for signing OIDC tokens. Multiple keys can
    be stored to support key rotation scenarios.

    Attributes:
        kid: Unique key ID used in JWT ``kid`` header
        key_type: Type of key (e.g., "RSA", "EC")
        private_key: PEM-encoded private key (never exposed in API responses)
        public_key: PEM-encoded public key
        algorithm: Signing algorithm (e.g., "RS256", "ES256")
        is_active: Whether this key is currently used for signing/verification
        is_primary: Whether this is the primary signing key
        expires_at: Optional expiry for key rotation enforcement
    """

    __tablename__ = "oidc_jwks_keys"

    # Override the default UUID id with integer primary key for JWKS key sets
    id = db.Column(db.Integer, primary_key=True)

    expires_at = db.Column(db.DateTime, nullable=True)

    # Key identification and type
    kid = db.Column(db.String(255), unique=True, nullable=False, index=True)
    key_type = db.Column(db.String(50), nullable=False)      # e.g., "RSA", "EC"
    algorithm = db.Column(db.String(50), nullable=False)     # e.g., "RS256", "ES256"

    # Key material (PEM-encoded) — private_key must never be returned by API
    private_key = db.Column(db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=False)

    # Key status
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_primary = db.Column(db.Boolean, default=False, nullable=False)

    def __repr__(self):
        """String representation of OidcJwksKey."""
        return (
            f"<OidcJwksKey kid={self.kid} "
            f"key_type={self.key_type} algorithm={self.algorithm}>"
        )

    def to_dict(self, exclude_private_key: bool = True):
        """Convert model to dictionary.

        Args:
            exclude_private_key: If True (default), excludes the private key.

        Returns:
            Dictionary representation of the model
        """
        exclude = ["private_key"] if exclude_private_key else []
        return super().to_dict(exclude=exclude)

    @classmethod
    def get_active_keys(cls) -> list:
        """Get all active keys for signing operations."""
        return cls.query.filter_by(is_active=True).all()

    @classmethod
    def get_primary_key(cls) -> "OidcJwksKey | None":
        """Get the primary signing key."""
        return cls.query.filter_by(is_primary=True).first()

    @classmethod
    def get_key_by_kid(cls, kid: str) -> "OidcJwksKey | None":
        """Get an active key by its key ID."""
        return cls.query.filter_by(kid=kid, is_active=True).first()
