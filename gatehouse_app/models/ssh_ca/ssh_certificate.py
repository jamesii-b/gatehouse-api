"""SSH Certificate model — signed SSH user/host certificates."""
from enum import Enum
from datetime import datetime, timezone
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel
from gatehouse_app.models.ssh_ca.ca import CertType


class CertificateStatus(str, Enum):
    """SSH certificate lifecycle status."""

    REQUESTED = "requested"    # Waiting for signing
    ISSUED = "issued"          # Signed and valid
    REVOKED = "revoked"        # Manually revoked
    EXPIRED = "expired"        # Validity period ended
    SUPERSEDED = "superseded"  # Replaced by newer certificate


class SSHCertificate(BaseModel):
    """SSH Certificate model representing a signed SSH user/host certificate.

    Certificates are issued by a CA and associated with an SSH public key.
    They include principals (access levels), validity periods, and standard
    OpenSSH certificate metadata.
    """

    __tablename__ = "ssh_certificates"

    # Certificate relationships
    ca_id = db.Column(
        db.String(36),
        db.ForeignKey("cas.id"),
        nullable=False,
        index=True,
    )
    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id"),
        nullable=False,
        index=True,
    )
    ssh_key_id = db.Column(
        db.String(36),
        db.ForeignKey("ssh_keys.id"),
        nullable=True,   # Nullable: host certs may be issued against a raw public key
        index=True,
    )

    # Certificate content — full signed certificate in OpenSSH format
    certificate = db.Column(db.Text, nullable=False)

    # Certificate metadata
    serial = db.Column(db.String(255), nullable=False, unique=True, index=True)
    key_id = db.Column(db.String(255), nullable=False)  # Usually user email
    cert_type = db.Column(
        db.Enum(CertType, values_callable=lambda x: [e.value for e in x]),
        default=CertType.USER,
        nullable=False,
    )

    # Principals — JSON list, e.g., ["prod-servers", "dev-servers"]
    principals = db.Column(db.JSON, nullable=False, default=list)

    # Validity period
    valid_after = db.Column(db.DateTime, nullable=False)
    valid_before = db.Column(db.DateTime, nullable=False)

    # Revocation status
    revoked = db.Column(db.Boolean, default=False, nullable=False, index=True)
    revoked_at = db.Column(db.DateTime, nullable=True)
    revoke_reason = db.Column(db.String(255), nullable=True)

    # Status tracking
    status = db.Column(
        db.Enum(CertificateStatus, values_callable=lambda x: [e.value for e in x]),
        default=CertificateStatus.ISSUED,
        nullable=False,
        index=True,
    )

    # Request metadata
    request_ip = db.Column(db.String(45), nullable=True)
    request_user_agent = db.Column(db.String(512), nullable=True)

    # Critical options — OpenSSH critical options (JSON)
    critical_options = db.Column(db.JSON, nullable=True, default=dict)

    # Extensions — OpenSSH extensions (JSON)
    extensions = db.Column(db.JSON, nullable=True, default=dict)

    # Relationships
    ca = db.relationship("CA", back_populates="certificates")
    user = db.relationship("User", back_populates="ssh_certificates")
    ssh_key = db.relationship(
        "SSHKey",
        back_populates="certificates",
        foreign_keys="SSHCertificate.ssh_key_id",
    )
    audit_logs = db.relationship(
        "CertificateAuditLog",
        back_populates="certificate",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        db.Index("idx_cert_user_status", "user_id", "status"),
        db.Index("idx_cert_validity", "valid_after", "valid_before"),
        db.Index("idx_cert_revoked", "revoked", "revoked_at"),
    )

    def __repr__(self):
        """String representation of SSHCertificate."""
        return f"<SSHCertificate serial={self.serial[:16]}... user_id={self.user_id}>"

    def to_dict(self, exclude=None):
        """Convert certificate to dictionary.

        The raw ``certificate`` blob is excluded by default (it is large and
        callers can request it explicitly by removing it from the exclude list).
        """
        exclude = exclude or []
        if "certificate" not in exclude:
            exclude.append("certificate")
        data = super().to_dict(exclude=exclude)
        data["is_valid"] = self.is_valid()
        data["days_until_expiry"] = self.days_until_expiry()
        return data

    def _aware(self, dt: datetime) -> datetime:
        """Return a timezone-aware UTC datetime."""
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt

    def is_valid(self) -> bool:
        """Check if certificate is currently valid.

        Returns:
            True if certificate is issued, not revoked, and within validity period
        """
        if self.revoked or self.status == CertificateStatus.REVOKED:
            return False
        now = datetime.now(timezone.utc)
        return self._aware(self.valid_after) <= now <= self._aware(self.valid_before)

    def is_expired(self) -> bool:
        """Check if certificate has expired.

        Returns:
            True if current time is past valid_before
        """
        return datetime.now(timezone.utc) > self._aware(self.valid_before)

    def days_until_expiry(self) -> int:
        """Get number of days until certificate expires.

        Returns:
            Number of days remaining (negative if already expired)
        """
        delta = self._aware(self.valid_before) - datetime.now(timezone.utc)
        return delta.days + (1 if delta.seconds > 0 else 0)

    def revoke(self, reason: str = None) -> None:
        """Revoke this certificate.

        Args:
            reason: Optional reason for revocation
        """
        self.revoked = True
        self.revoked_at = datetime.now(timezone.utc)    # Bug fix: was datetime.utcnow()
        self.revoke_reason = reason
        self.status = CertificateStatus.REVOKED
        self.save()

    def mark_expired(self) -> None:
        """Mark certificate as expired when validity period ends."""
        self.status = CertificateStatus.EXPIRED
        self.save()
