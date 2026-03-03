"""UserSecurityPolicy model — per-user MFA overrides."""
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel
from gatehouse_app.utils.constants import MfaRequirementOverride


class UserSecurityPolicy(BaseModel):
    """User security policy model for per-user MFA overrides.

    Stores per-user overrides of organization-level MFA requirements.
    """

    __tablename__ = "user_security_policies"

    user_id = db.Column(
        db.String(36), db.ForeignKey("users.id"), nullable=False, index=True
    )
    organization_id = db.Column(
        db.String(36), db.ForeignKey("organizations.id"), nullable=False, index=True
    )

    mfa_override_mode = db.Column(
        db.Enum(MfaRequirementOverride),
        nullable=False,
        default=MfaRequirementOverride.INHERIT,
    )

    # If override is REQUIRED, optionally force a specific factor set
    force_totp = db.Column(db.Boolean, nullable=False, default=False)
    force_webauthn = db.Column(db.Boolean, nullable=False, default=False)

    __table_args__ = (
        db.UniqueConstraint("user_id", "organization_id", name="uix_user_org_policy"),
    )

    # Relationships
    user = db.relationship(
        "User", back_populates="security_policies", foreign_keys=[user_id]
    )
    organization = db.relationship("Organization", foreign_keys=[organization_id])

    def __repr__(self):
        """String representation of UserSecurityPolicy."""
        return (
            f"<UserSecurityPolicy user={self.user_id} "
            f"org={self.organization_id} mode={self.mfa_override_mode}>"
        )

    def to_dict(self, exclude=None):
        """Convert to dictionary."""
        return super().to_dict(exclude=exclude or [])
