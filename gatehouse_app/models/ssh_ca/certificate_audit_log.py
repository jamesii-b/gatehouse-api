"""Certificate audit log model — tracks SSH certificate lifecycle events."""
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel


class CertificateAuditLog(BaseModel):
    """Audit log for SSH certificate lifecycle events.

    Tracks all operations on SSH certificates: signing, revocation, validation,
    etc. Kept separate from the general AuditLog to provide detailed certificate
    operation tracking without polluting the main audit stream.
    """

    __tablename__ = "certificate_audit_logs"

    # Reference to the certificate
    certificate_id = db.Column(
        db.String(36),
        db.ForeignKey("ssh_certificates.id"),
        nullable=False,
        index=True,
    )

    # The user who performed the action (null for system actions)
    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id"),
        nullable=True,
        index=True,
    )

    # Action type (e.g., "signed", "revoked", "validated", "requested")
    action = db.Column(db.String(50), nullable=False, index=True)

    # Request details
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(512), nullable=True)
    request_id = db.Column(db.String(36), nullable=True)

    # Detailed message
    message = db.Column(db.Text, nullable=True)

    # Additional context
    extra_data = db.Column(db.JSON, nullable=True)

    # Outcome
    success = db.Column(db.Boolean, default=True, nullable=False)
    error_message = db.Column(db.Text, nullable=True)

    # Relationships
    certificate = db.relationship("SSHCertificate", back_populates="audit_logs")
    user = db.relationship("User")

    __table_args__ = (
        db.Index("idx_cert_audit_cert_action", "certificate_id", "action"),
        db.Index("idx_cert_audit_user", "user_id", "created_at"),
    )

    def __repr__(self):
        """String representation of CertificateAuditLog."""
        return (
            f"<CertificateAuditLog cert_id={self.certificate_id} action={self.action}>"
        )

    @classmethod
    def log(
        cls,
        certificate_id: str,
        action: str,
        user_id: str = None,
        **kwargs,
    ) -> "CertificateAuditLog":
        """Create a certificate audit log entry.

        Args:
            certificate_id: ID of the certificate
            action: Action type (e.g., "signed", "revoked")
            user_id: ID of the user performing the action (optional)
            **kwargs: Additional fields (ip_address, user_agent, message, etc.)

        Returns:
            CertificateAuditLog instance
        """
        log_entry = cls(
            certificate_id=certificate_id,
            action=action,
            user_id=user_id,
            **kwargs,
        )
        log_entry.save()
        return log_entry
