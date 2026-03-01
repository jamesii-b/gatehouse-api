"""MfaPolicyCompliance model — per-user per-organization MFA compliance tracking."""
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel
from gatehouse_app.utils.constants import MfaComplianceStatus


class MfaPolicyCompliance(BaseModel):
    """MFA policy compliance tracking per user per organization.

    Tracks each user's MFA compliance state separately for each organization
    membership. One row per (user, org) pair.
    """

    __tablename__ = "mfa_policy_compliance"

    user_id = db.Column(
        db.String(36), db.ForeignKey("users.id"), nullable=False, index=True
    )
    organization_id = db.Column(
        db.String(36), db.ForeignKey("organizations.id"), nullable=False, index=True
    )

    status = db.Column(
        db.Enum(MfaComplianceStatus),
        nullable=False,
        default=MfaComplianceStatus.NOT_APPLICABLE,
    )

    # Snapshot of org policy version when this record became active
    policy_version = db.Column(db.Integer, nullable=False)

    # When policy started applying to this user
    applied_at = db.Column(db.DateTime, nullable=True)

    # Final deadline for this user to comply
    deadline_at = db.Column(db.DateTime, nullable=True)

    # When they became compliant under this policy_version
    compliant_at = db.Column(db.DateTime, nullable=True)

    # When suspended enforcement started for this user
    suspended_at = db.Column(db.DateTime, nullable=True)

    # Notification tracking
    last_notified_at = db.Column(db.DateTime, nullable=True)
    notification_count = db.Column(db.Integer, nullable=False, default=0)

    __table_args__ = (
        db.UniqueConstraint("user_id", "organization_id", name="uix_user_org_compliance"),
    )

    # Relationships
    user = db.relationship(
        "User", back_populates="mfa_compliance", foreign_keys=[user_id]
    )
    organization = db.relationship("Organization", foreign_keys=[organization_id])

    def __repr__(self):
        """String representation of MfaPolicyCompliance."""
        return (
            f"<MfaPolicyCompliance user={self.user_id} "
            f"org={self.organization_id} status={self.status}>"
        )

    def to_dict(self, exclude=None):
        """Convert to dictionary."""
        return super().to_dict(exclude=exclude or [])
