"""SSH Key model — user SSH public keys registered for certificate signing."""
from datetime import datetime, timezone
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel


class SSHKey(BaseModel):
    """SSH Key model representing a user's SSH public key.

    Users register SSH public keys for certificate signing. Keys must be
    verified (owner proved possession) before they can be used.
    """

    __tablename__ = "ssh_keys"

    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    # SSH key payload in OpenSSH format (e.g., "ssh-ed25519 AAAAB3Nz...")
    payload = db.Column(db.Text, nullable=False, unique=True)

    # SHA256 fingerprint for quick comparison and deduplication
    fingerprint = db.Column(db.String(255), nullable=False, unique=True, index=True)

    # Optional human-readable description (e.g., "My laptop key")
    description = db.Column(db.String(255), nullable=True)

    # Verification status
    verified = db.Column(db.Boolean, default=False, nullable=False, index=True)
    verified_at = db.Column(db.DateTime, nullable=True)

    # Verification challenge — shown to user once, cleared after verification
    verify_text = db.Column(db.String(255), nullable=True)
    verify_text_created_at = db.Column(db.DateTime, nullable=True)

    # Key metadata extracted from the key
    key_type = db.Column(db.String(50), nullable=True)    # ssh-rsa, ssh-ed25519, etc.
    key_bits = db.Column(db.Integer, nullable=True)       # key length
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
        """Convert SSH key to dictionary.

        ``payload`` and ``verify_text`` are never exposed through the API.
        """
        exclude = exclude or []
        for field in ("payload", "verify_text"):
            if field not in exclude:
                exclude.append(field)
        data = super().to_dict(exclude=exclude)
        data["cert_count"] = len([c for c in self.certificates if c.deleted_at is None])
        return data

    def mark_verified(self) -> None:
        """Mark this SSH key as verified and clear the challenge."""
        self.verified = True
        self.verified_at = datetime.now(timezone.utc)    # Bug fix: was datetime.utcnow()
        self.verify_text = None
        self.save()

    def needs_verification_refresh(self, max_age_hours: int = 24) -> bool:
        """Check if verification challenge needs to be refreshed.

        Args:
            max_age_hours: Maximum age of verification challenge in hours

        Returns:
            True if verification challenge is stale or missing
        """
        if not self.verify_text_created_at:
            return True
        age = datetime.now(timezone.utc) - self.verify_text_created_at.replace(
            tzinfo=timezone.utc
        ) if self.verify_text_created_at.tzinfo is None else (
            datetime.now(timezone.utc) - self.verify_text_created_at
        )
        return age.total_seconds() > (max_age_hours * 3600)
