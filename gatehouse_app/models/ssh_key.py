"""SSH Key model."""
from datetime import datetime
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel


class SSHKey(BaseModel):
    """SSH Key model representing a user's SSH public key.
    
    This model stores SSH public keys that users register for certificate signing.
    Users must verify ownership of the key before it can be used for signing certificates.
    """

    __tablename__ = "ssh_keys"

    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id"),
        nullable=False,
        index=True,
    )
    
    # SSH key payload in OpenSSH format (e.g., "ssh-rsa AAAAB3Nz...")
    payload = db.Column(db.Text, nullable=False, unique=True)
    
    # SHA256 fingerprint for quick comparison
    fingerprint = db.Column(db.String(255), nullable=False, unique=True, index=True)
    
    # Optional description for the key (e.g., "My laptop key")
    description = db.Column(db.String(255), nullable=True)
    
    # Verification status
    verified = db.Column(db.Boolean, default=False, nullable=False, index=True)
    verified_at = db.Column(db.DateTime, nullable=True)
    
    # Verification challenge
    verify_text = db.Column(db.String(255), nullable=True)
    verify_text_created_at = db.Column(db.DateTime, nullable=True)
    
    # Key type extracted from the key (ssh-rsa, ssh-ed25519, etc.)
    key_type = db.Column(db.String(50), nullable=True)
    
    # Key bits/length
    key_bits = db.Column(db.Integer, nullable=True)
    
    # Comment from the key (usually email or key name)
    key_comment = db.Column(db.String(255), nullable=True)
    
    # Relationships
    user = db.relationship("User", back_populates="ssh_keys")
    certificates = db.relationship(
        "SSHCertificate",
        back_populates="ssh_key",
        cascade="all, delete-orphan",
        foreign_keys="SSHCertificate.ssh_key_id",
    )

    __table_args__ = (
        db.Index("idx_ssh_key_user_verified", "user_id", "verified"),
    )

    def __repr__(self):
        """String representation of SSHKey."""
        return f"<SSHKey {self.fingerprint[:16]}... user_id={self.user_id}>"

    def to_dict(self, exclude=None):
        """Convert SSH key to dictionary."""
        exclude = exclude or []
        exclude.extend(["payload", "verify_text"])  # Never expose these in API
        data = super().to_dict(exclude=exclude)
        
        # Add computed fields
        data["cert_count"] = len([c for c in self.certificates if c.deleted_at is None])
        
        return data

    def mark_verified(self):
        """Mark this SSH key as verified."""
        self.verified = True
        self.verified_at = datetime.utcnow()
        self.save()

    def needs_verification_refresh(self, max_age_hours=24):
        """Check if verification challenge needs to be refreshed.
        
        Args:
            max_age_hours: Maximum age of verification challenge in hours
            
        Returns:
            True if verification challenge is stale
        """
        if not self.verify_text_created_at:
            return True
        
        age = datetime.utcnow() - self.verify_text_created_at
        return age.total_seconds() > (max_age_hours * 3600)
