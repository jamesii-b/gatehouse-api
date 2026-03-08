"""Organization API Key model — API keys for organizations for external integrations."""
import secrets
from datetime import datetime, timezone
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel


class OrganizationApiKey(BaseModel):
    """API Key model representing an API key for an organization.

    API keys are used to authenticate external integrations or services
    that need programmatic access to the organization's resources.
    Each key is tied to an organization and can be revoked/deleted as needed.
    """

    __tablename__ = "organization_api_keys"

    organization_id = db.Column(
        db.String(36),
        db.ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )
    
    # Human-readable name for the API key
    name = db.Column(db.String(255), nullable=False)
    
    # Hashed key value (never store plain text)
    key_hash = db.Column(db.String(255), nullable=False, unique=True, index=True)
    
    # Last used timestamp for tracking activity
    last_used_at = db.Column(db.DateTime, nullable=True)
    
    # Revocation status
    is_revoked = db.Column(db.Boolean, default=False, nullable=False, index=True)
    revoked_at = db.Column(db.DateTime, nullable=True)
    revoke_reason = db.Column(db.String(255), nullable=True)

    # Description/purpose of the key
    description = db.Column(db.Text, nullable=True)

    # Relationships
    organization = db.relationship("Organization", back_populates="api_keys")

    __table_args__ = (
        db.Index("idx_org_api_key_org_active", "organization_id", "is_revoked"),
        db.Index("idx_api_key_last_used", "last_used_at"),
    )

    def __repr__(self):
        """String representation of OrganizationApiKey."""
        return f"<OrganizationApiKey name={self.name} org_id={self.organization_id}>"

    @staticmethod
    def generate_key() -> str:
        """Generate a random API key.
        
        Returns:
            A random 32-byte hex string suitable for use as an API key
        """
        return secrets.token_hex(32)

    @classmethod
    def create_key(
        cls,
        organization_id: str,
        name: str,
        description: str = None,
    ) -> tuple:
        """Create and store a new API key for an organization.

        Args:
            organization_id: ID of the organization
            name: Human-readable name for the key
            description: Optional description/purpose of the key

        Returns:
            Tuple of (OrganizationApiKey instance, plain_text_key_string)
            The plain text key is only returned on creation and should be
            stored securely by the user. It cannot be retrieved later.
        """
        # Generate a plain text key
        plain_key = cls.generate_key()
        
        # Hash it using the key_hash method
        key_hash = cls.hash_key(plain_key)
        
        # Create the database record
        api_key = cls(
            organization_id=organization_id,
            name=name,
            key_hash=key_hash,
            description=description,
        )
        api_key.save()
        
        return api_key, plain_key

    @staticmethod
    def hash_key(plain_key: str) -> str:
        """Hash an API key for storage.

        Args:
            plain_key: The plain text API key

        Returns:
            Hashed version of the key
        """
        import hashlib
        return hashlib.sha256(plain_key.encode()).hexdigest()

    @classmethod
    def verify_key(cls, organization_id: str, plain_key: str) -> "OrganizationApiKey":
        """Verify an API key for an organization.

        Args:
            organization_id: ID of the organization
            plain_key: The plain text API key to verify

        Returns:
            OrganizationApiKey instance if valid and active, None otherwise
        """
        key_hash = cls.hash_key(plain_key)
        
        api_key = cls.query.filter_by(
            organization_id=organization_id,
            key_hash=key_hash,
            is_revoked=False,
            deleted_at=None,
        ).first()
        
        if api_key:
            # Update last used timestamp
            api_key.last_used_at = datetime.now(timezone.utc)
            api_key.save()
        
        return api_key

    def revoke(self, reason: str = None) -> None:
        """Revoke this API key.

        Args:
            reason: Optional reason for revocation
        """
        self.is_revoked = True
        self.revoked_at = datetime.now(timezone.utc)
        self.revoke_reason = reason
        self.save()

    def to_dict(self, exclude=None):
        """Convert API key to dictionary.

        The key_hash is excluded by default for security.
        """
        exclude = exclude or []
        if "key_hash" not in exclude:
            exclude.append("key_hash")
        return super().to_dict(exclude=exclude)
