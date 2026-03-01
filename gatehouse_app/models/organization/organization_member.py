"""Organization member model."""
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel
from gatehouse_app.utils.constants import OrganizationRole


class OrganizationMember(BaseModel):
    """Organization member model representing user membership in an organization."""

    __tablename__ = "organization_members"

    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)
    organization_id = db.Column(
        db.String(36), db.ForeignKey("organizations.id"), nullable=False, index=True
    )
    role = db.Column(
        db.Enum(OrganizationRole), default=OrganizationRole.MEMBER, nullable=False
    )
    invited_by_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)
    invited_at = db.Column(db.DateTime, nullable=True)
    joined_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    user = db.relationship(
        "User", foreign_keys=[user_id], back_populates="organization_memberships"
    )
    organization = db.relationship("Organization", back_populates="members")
    invited_by = db.relationship("User", foreign_keys=[invited_by_id])

    __table_args__ = (
        db.UniqueConstraint("user_id", "organization_id", name="uix_user_org"),
    )

    def __repr__(self):
        """String representation of OrganizationMember."""
        return (
            f"<OrganizationMember user_id={self.user_id} "
            f"org_id={self.organization_id} role={self.role}>"
        )

    def is_owner(self) -> bool:
        """Check if member is an owner."""
        return self.role == OrganizationRole.OWNER

    def is_admin(self) -> bool:
        """Check if member is an admin or owner."""
        return self.role in [OrganizationRole.OWNER, OrganizationRole.ADMIN]

    def can_manage_members(self) -> bool:
        """Check if member can manage other members."""
        return self.is_admin()

    def can_delete_organization(self) -> bool:
        """Check if member can delete the organization."""
        return self.is_owner()
