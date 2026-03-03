"""Session model."""
from datetime import datetime, timedelta, timezone
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel
from gatehouse_app.utils.constants import SessionStatus


class Session(BaseModel):
    """Session model for tracking user sessions."""

    __tablename__ = "sessions"

    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    status = db.Column(db.Enum(SessionStatus), default=SessionStatus.ACTIVE, nullable=False)

    # Session metadata
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    device_info = db.Column(db.JSON, nullable=True)

    # Timing
    expires_at = db.Column(db.DateTime, nullable=False)
    last_activity_at = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    revoked_at = db.Column(db.DateTime, nullable=True)
    revoked_reason = db.Column(db.String(255), nullable=True)

    # Compliance session flag
    is_compliance_only = db.Column(db.Boolean, nullable=False, default=False)

    # Relationships
    user = db.relationship("User", back_populates="sessions")

    def __repr__(self):
        """String representation of Session."""
        return f"<Session user_id={self.user_id} status={self.status}>"

    def is_active(self):
        """Check if session is currently active."""
        now = datetime.now(timezone.utc)
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return (
            self.status == SessionStatus.ACTIVE
            and expires_at > now
            and self.deleted_at is None
        )

    def is_expired(self):
        """Check if session has expired."""
        now = datetime.now(timezone.utc)
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return now > expires_at

    def refresh(self, duration_seconds: int = 86400):
        """Refresh session expiration.

        Args:
            duration_seconds: New session duration in seconds
        """
        self.expires_at = datetime.now(timezone.utc) + timedelta(seconds=duration_seconds)
        self.last_activity_at = datetime.now(timezone.utc)
        db.session.commit()

    def revoke(self, reason: str = None):
        """Revoke the session.

        Args:
            reason: Optional reason for revocation
        """
        self.status = SessionStatus.REVOKED
        self.revoked_at = datetime.now(timezone.utc)
        if reason:
            self.revoked_reason = reason
        db.session.commit()

    def to_dict(self, exclude=None):
        """Convert to dictionary, excluding sensitive fields."""
        exclude = exclude or []
        exclude.append("token")
        return super().to_dict(exclude=exclude)
