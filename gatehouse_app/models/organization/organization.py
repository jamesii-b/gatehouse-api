"""Organization model."""
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel


class Organization(BaseModel):
    """Organization model representing a tenant/workspace."""

    __tablename__ = "organizations"

    name = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(255), unique=True, nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    logo_url = db.Column(db.String(512), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # Settings (stored as JSON)
    settings = db.Column(db.JSON, nullable=True, default=dict)

    # Relationships
    members = db.relationship(
        "OrganizationMember", back_populates="organization", cascade="all, delete-orphan"
    )
    oidc_clients = db.relationship(
        "OIDCClient", back_populates="organization", cascade="all, delete-orphan"
    )
    external_provider_configs = db.relationship(
        "ExternalProviderConfig", back_populates="organization", cascade="all, delete-orphan"
    )
    security_policy = db.relationship(
        "OrganizationSecurityPolicy",
        back_populates="organization",
        uselist=False,
        cascade="all, delete-orphan",
        foreign_keys="OrganizationSecurityPolicy.organization_id",
    )
    departments = db.relationship(
        "Department", back_populates="organization", cascade="all, delete-orphan"
    )
    principals = db.relationship(
        "Principal", back_populates="organization", cascade="all, delete-orphan"
    )
    cas = db.relationship(
        "CA", back_populates="organization", cascade="all, delete-orphan"
    )
    api_keys = db.relationship(
        "OrganizationApiKey", back_populates="organization", cascade="all, delete-orphan"
    )

    def __repr__(self):
        """String representation of Organization."""
        return f"<Organization {self.name}>"

    def get_member_count(self):
        """Get the count of active members in the organization."""
        return len([m for m in self.members if m.deleted_at is None])

    def get_owner(self):
        """Get the owner of the organization."""
        from gatehouse_app.utils.constants import OrganizationRole

        for member in self.members:
            if member.role == OrganizationRole.OWNER and member.deleted_at is None:
                return member.user
        return None

    def is_member(self, user_id: str) -> bool:
        """Check if a user is a member of the organization."""
        from gatehouse_app.models.organization.organization_member import OrganizationMember

        return (
            OrganizationMember.query.filter_by(
                user_id=user_id, organization_id=self.id, deleted_at=None
            ).first()
            is not None
        )
