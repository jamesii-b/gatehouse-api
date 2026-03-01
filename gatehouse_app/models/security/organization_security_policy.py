"""OrganizationSecurityPolicy model."""
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel
from gatehouse_app.utils.constants import MfaPolicyMode


class OrganizationSecurityPolicy(BaseModel):
    """Organization security policy model for MFA configuration.

    One row per organization capturing its current security requirements.
    """

    __tablename__ = "organization_security_policies"

    organization_id = db.Column(
        db.String(36),
        db.ForeignKey("organizations.id"),
        nullable=False,
        index=True,
        unique=True,
    )

    # MFA policy configuration
    mfa_policy_mode = db.Column(
        db.Enum(MfaPolicyMode), nullable=False, default=MfaPolicyMode.OPTIONAL
    )

    # Grace period for members in days
    mfa_grace_period_days = db.Column(db.Integer, nullable=False, default=14)

    # Notification settings (in days before individual user deadline)
    notify_days_before = db.Column(db.Integer, nullable=False, default=7)

    # Versioning for compatibility tracking
    policy_version = db.Column(db.Integer, nullable=False, default=1)

    # Audit metadata
    updated_by_user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)

    # Relationships
    organization = db.relationship(
        "Organization",
        back_populates="security_policy",
        foreign_keys=[organization_id],
    )
    updated_by_user = db.relationship("User", foreign_keys=[updated_by_user_id])

    def __repr__(self):
        """String representation of OrganizationSecurityPolicy."""
        return (
            f"<OrganizationSecurityPolicy "
            f"org={self.organization_id} mode={self.mfa_policy_mode}>"
        )

    def to_dict(self, exclude=None):
        """Convert to dictionary."""
        return super().to_dict(exclude=exclude or [])
