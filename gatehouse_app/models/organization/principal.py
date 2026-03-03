"""Principal and PrincipalMembership models."""
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel


class Principal(BaseModel):
    """Principal model representing an SSH principal (access level/role).

    In SSH CA terminology, a principal is a string like "eng-prod-servers" or
    "devops-admins" that represents a set of machines or access level. Users
    can be granted access to principals, either directly or via department
    membership.

    Example:
        - Principal: "eng-prod-servers"
        - Users with this principal can SSH to prod servers
        - Can be assigned to departments or directly to users
    """

    __tablename__ = "principals"

    organization_id = db.Column(
        db.String(36),
        db.ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )
    name = db.Column(db.String(255), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)

    # Relationships
    organization = db.relationship("Organization", back_populates="principals")
    memberships = db.relationship(
        "PrincipalMembership",
        back_populates="principal",
        cascade="all, delete-orphan",
    )
    department_links = db.relationship(
        "DepartmentPrincipal",
        back_populates="principal",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        db.UniqueConstraint("organization_id", "name", name="uix_org_principal_name"),
    )

    def __repr__(self):
        """String representation of Principal."""
        return f"<Principal {self.name} (org_id={self.organization_id})>"

    def to_dict(self, exclude=None):
        """Convert principal to dictionary."""
        exclude = exclude or []
        data = super().to_dict(exclude=exclude)
        data["direct_member_count"] = len(
            [m for m in self.memberships if m.deleted_at is None]
        )
        data["department_count"] = len(
            [d for d in self.department_links if d.deleted_at is None]
        )
        return data

    def get_members(self, active_only: bool = True):
        """Get all users who are directly assigned to this principal.

        Does NOT include users who get access via department membership.

        Args:
            active_only: If True, exclude soft-deleted members

        Returns:
            List of PrincipalMembership objects
        """
        if active_only:
            return [m for m in self.memberships if m.deleted_at is None]
        return list(self.memberships)

    def get_all_members(self, active_only: bool = True):
        """Get all users who have access to this principal.

        Includes both direct members and users via department membership.

        Args:
            active_only: If True, exclude soft-deleted members

        Returns:
            Set of User objects with access to this principal
        """
        all_users: set = set()

        # Direct members
        for membership in self.get_members(active_only=active_only):
            if not active_only or membership.user.deleted_at is None:
                all_users.add(membership.user)

        # Members via department assignment
        for dept_link in self.department_links:
            if dept_link.deleted_at is None or not active_only:
                for dept_member in dept_link.department.get_members(active_only=active_only):
                    if not active_only or dept_member.user.deleted_at is None:
                        all_users.add(dept_member.user)

        return all_users

    def get_departments(self, active_only: bool = True):
        """Get all departments this principal is assigned to.

        Args:
            active_only: If True, exclude soft-deleted departments

        Returns:
            List of Department objects
        """
        if active_only:
            return [
                d.department
                for d in self.department_links
                if d.deleted_at is None and d.department.deleted_at is None
            ]
        return [d.department for d in self.department_links]

    def is_member(self, user_id: str, include_via_department: bool = True) -> bool:
        """Check if a user has access to this principal.

        Args:
            user_id: ID of the user to check
            include_via_department: If True, check department memberships too

        Returns:
            True if user has access to this principal
        """
        # Check direct membership
        has_direct = (
            PrincipalMembership.query.filter_by(
                user_id=user_id,
                principal_id=self.id,
                deleted_at=None,
            ).first()
            is not None
        )

        if has_direct:
            return True

        if not include_via_department:
            return False

        # Check department membership
        dept_ids = [d.id for d in self.get_departments(active_only=True)]
        if not dept_ids:
            return False

        from gatehouse_app.models.organization.department import DepartmentMembership

        return (
            DepartmentMembership.query.filter(
                DepartmentMembership.user_id == user_id,
                DepartmentMembership.department_id.in_(dept_ids),
                DepartmentMembership.deleted_at.is_(None),
            ).first()
            is not None
        )

    def get_member_count(self, include_via_department: bool = True) -> int:
        """Get the count of active members with access to this principal.

        Args:
            include_via_department: If True, include members via department

        Returns:
            Count of members
        """
        if not include_via_department:
            return len(self.get_members(active_only=True))
        return len(self.get_all_members(active_only=True))


class PrincipalMembership(BaseModel):
    """Principal membership model representing direct user assignment to a principal.

    When a user is assigned directly to a principal, they get access to that
    principal for SSH authentication. This is in addition to any principals
    they get via department membership.
    """

    __tablename__ = "principal_memberships"

    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id"),
        nullable=False,
        index=True,
    )
    principal_id = db.Column(
        db.String(36),
        db.ForeignKey("principals.id"),
        nullable=False,
        index=True,
    )

    # Relationships
    user = db.relationship("User", back_populates="principal_memberships")
    principal = db.relationship("Principal", back_populates="memberships")

    __table_args__ = (
        db.UniqueConstraint("user_id", "principal_id", name="uix_user_principal"),
    )

    def __repr__(self):
        """String representation of PrincipalMembership."""
        return (
            f"<PrincipalMembership user_id={self.user_id} "
            f"principal_id={self.principal_id}>"
        )
