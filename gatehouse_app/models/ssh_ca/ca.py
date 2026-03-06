"""Certificate Authority (CA) model."""
import time
from enum import Enum
from datetime import datetime, timezone
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel


def _serial_start() -> int:
    return int(time.time() * 1000)


class KeyType(str, Enum):
    """SSH CA key types."""

    ED25519 = "ed25519"
    RSA = "rsa"
    ECDSA = "ecdsa"


class CertType(str, Enum):
    """SSH certificate types."""

    USER = "user"
    HOST = "host"


class CaType(str, Enum):
    """CA signing type — whether this CA signs user or host certificates."""

    USER = "user"
    HOST = "host"


class CA(BaseModel):
    """Certificate Authority (CA) model for SSH certificate signing.

    Each organization can have multiple CAs for different purposes
    (e.g., production vs. staging). Private keys are encrypted at rest
    and should be protected with KMS.
    """

    __tablename__ = "cas"

    organization_id = db.Column(
        db.String(36),
        db.ForeignKey("organizations.id"),
        nullable=True,   # NULL for the global system-config CA
        index=True,
    )

    # CA identity
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)

    # CA signing type: 'user' signs user certificates, 'host' signs host certs
    ca_type = db.Column(
        db.Enum(CaType, values_callable=lambda x: [e.value for e in x]),
        default=CaType.USER,
        nullable=False,
    )

    # Key type (ED25519, RSA, ECDSA)
    key_type = db.Column(
        db.Enum(KeyType, values_callable=lambda x: [e.value for e in x]),
        default=KeyType.ED25519,
        nullable=False,
    )

    # Private key — PEM-encoded, encrypted at rest by database/KMS
    private_key = db.Column(db.Text, nullable=False)

    # Public key — PEM format
    public_key = db.Column(db.Text, nullable=False)

    # SHA256 fingerprint of the public key
    fingerprint = db.Column(db.String(255), nullable=False, unique=True)

    # CRL (Certificate Revocation List) configuration
    crl_enabled = db.Column(db.Boolean, default=True, nullable=False)
    crl_endpoint = db.Column(db.String(512), nullable=True)

    # Default certificate validity in hours (overridable per request)
    default_cert_validity_hours = db.Column(db.Integer, default=1, nullable=False)

    # Maximum validity duration allowed
    max_cert_validity_hours = db.Column(db.Integer, default=24, nullable=False)

    # CA status
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)

    # Key rotation tracking
    rotated_at = db.Column(db.DateTime, nullable=True)
    rotation_reason = db.Column(db.String(255), nullable=True)

    # Monotonically-increasing serial counter.  Every cert this CA issues
    # gets the next value so serials are unique, ordered, and auditable.
    # Protected by a row-level SELECT … FOR UPDATE in get_next_serial().
    # Initialised to the current Unix timestamp in milliseconds so serials
    # are globally unique across CAs from the moment of creation.
    next_serial_number = db.Column(db.BigInteger, default=_serial_start, nullable=False)

    # Relationships
    organization = db.relationship("Organization", back_populates="cas")
    certificates = db.relationship(
        "SSHCertificate",
        back_populates="ca",
        cascade="all, delete-orphan",
    )
    permissions = db.relationship(
        "CAPermission",
        back_populates="ca",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        db.UniqueConstraint("organization_id", "name", name="uix_org_ca_name"),
        db.Index("idx_ca_org_active", "organization_id", "is_active"),
    )

    def __repr__(self):
        """String representation of CA."""
        return (
            f"<CA {self.name} "
            f"(org_id={self.organization_id}, type={self.key_type})>"
        )

    def to_dict(self, exclude=None):
        """Convert CA to dictionary, never exposing the private key."""
        exclude = exclude or []
        if "private_key" not in exclude:
            exclude.append("private_key")
        data = super().to_dict(exclude=exclude)

        # Add computed fields
        data["total_certs"] = len([c for c in self.certificates if c.deleted_at is None])
        data["active_certs"] = len(
            [c for c in self.certificates if c.deleted_at is None and not c.revoked]
        )
        data["revoked_certs"] = len(
            [c for c in self.certificates if c.deleted_at is None and c.revoked]
        )
        return data

    def get_active_certificates(self) -> list:
        """Get all active (non-revoked) certificates issued by this CA."""
        return [
            c for c in self.certificates if c.deleted_at is None and not c.revoked
        ]

    def rotate_key(
        self,
        new_private_key: str,
        new_public_key: str,
        new_fingerprint: str,
        reason: str = None,
    ) -> None:
        """Rotate the CA's key pair.

        This should only be done in carefully controlled circumstances.
        All existing certificates remain valid but no new certificates can be
        signed with the old key after rotation.

        Args:
            new_private_key: New PEM-encoded private key
            new_public_key: New PEM-encoded public key
            new_fingerprint: SHA256 fingerprint of new public key
            reason: Optional reason for rotation
        """
        self.private_key = new_private_key
        self.public_key = new_public_key
        self.fingerprint = new_fingerprint
        self.rotated_at = datetime.now(timezone.utc)   # Bug fix: was datetime.utcnow()
        self.rotation_reason = reason
        self.save()

    def get_next_serial(self) -> int:
        """Atomically increment and return the next certificate serial number.

        Uses a SELECT … FOR UPDATE row lock so concurrent requests never
        receive the same serial.  Must be called inside an active DB
        transaction (i.e. before the final session.commit()).

        Returns:
            int: The serial number to embed in the next certificate.
        """
        # Re-fetch this CA row with an exclusive row lock
        locked = (
            db.session.query(CA)
            .with_for_update()
            .filter_by(id=self.id)
            .one()
        )
        serial = locked.next_serial_number
        locked.next_serial_number = serial + 1
        db.session.flush()   # write increment; commit happens in the caller
        return serial


class CAPermission(BaseModel):
    """Per-user CA permission model.

    Controls which users are allowed to sign certificates against a specific CA.
    When a CA has any permission rows, the signing endpoint enforces the list;
    CAs with no rows are open to all org members (backwards-compatible default).

    Permission values:
        sign  – user may request certificate signing
        admin – user may sign AND manage the CA (rotate keys, delete, etc.)
    """

    __tablename__ = "ca_permissions"

    ca_id = db.Column(
        db.String(36),
        db.ForeignKey("cas.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    permission = db.Column(db.String(50), nullable=False, default="sign")

    # Relationships
    ca = db.relationship("CA", back_populates="permissions")
    user = db.relationship("User", back_populates="ca_permissions")

    __table_args__ = (
        db.UniqueConstraint("ca_id", "user_id", name="uix_ca_permission"),
    )

    def __repr__(self):
        return (
            f"<CAPermission ca_id={self.ca_id} "
            f"user_id={self.user_id} permission={self.permission}>"
        )

    def to_dict(self, exclude=None):
        data = super().to_dict(exclude=exclude or [])
        data["permission"] = self.permission
        return data
