"""Audit log model."""
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel
from gatehouse_app.utils.constants import AuditAction


class AuditLog(BaseModel):
    """Audit log model for tracking user and system actions."""

    __tablename__ = "audit_logs"

    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True, index=True)
    action = db.Column(db.Enum(AuditAction), nullable=False, index=True)

    # Context
    resource_type = db.Column(db.String(50), nullable=True, index=True)
    resource_id = db.Column(db.String(36), nullable=True, index=True)
    organization_id = db.Column(db.String(36), nullable=True, index=True)

    # Request details
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    request_id = db.Column(db.String(36), nullable=True, index=True)

    # Additional data
    extra_data = db.Column(db.JSON, nullable=True)
    description = db.Column(db.Text, nullable=True)

    # Outcome
    success = db.Column(db.Boolean, default=True, nullable=False)
    error_message = db.Column(db.Text, nullable=True)

    # Relationships
    user = db.relationship("User", back_populates="audit_logs")

    __table_args__ = (
        db.Index("idx_audit_user_action", "user_id", "action"),
        db.Index("idx_audit_resource", "resource_type", "resource_id"),
        db.Index("idx_audit_org", "organization_id", "created_at"),
    )

    def __repr__(self):
        """String representation of AuditLog."""
        return f"<AuditLog action={self.action} user_id={self.user_id}>"

    @classmethod
    def log(cls, action, user_id=None, **kwargs) -> "AuditLog":
        """Create an audit log entry.

        Args:
            action: AuditAction enum value
            user_id: ID of the user performing the action
            **kwargs: Additional audit log fields

        Returns:
            AuditLog instance
        """
        log_entry = cls(action=action, user_id=user_id, **kwargs)
        log_entry.save()
        return log_entry
