"""Department, DepartmentMembership, and DepartmentPrincipal models."""
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel


class Department(BaseModel):
    """Department model representing an organizational unit for SSH access control.

    Departments are used to group users and assign SSH principals (access levels)
    to them. A user can be a member of multiple departments, and each department
    can have multiple principals assigned.

    Example:
        - Department: "Engineering"
        - Members: user1@example.com, user2@example.com
        - Principals: "eng-prod", "eng-staging"
        - Users get access based on their principal assignments
    """

    __tablename__ = "departments"

    organization_id = db.Column(
        db.String(36),
        db.ForeignKey("organizations.id"),
        nullable=False,
        index=True,
    )
    name = db.Column(db.String(255), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    can_sudo = db.Column(db.Boolean, default=False, nullable=False)

    # Relationships
    organization = db.relationship("Organization", back_populates="departments")
    memberships = db.relationship(
        "DepartmentMembership",
        back_populates="department",
        cascade="all, delete-orphan",
    )
    principal_links = db.relationship(
        "DepartmentPrincipal",
        back_populates="department",
        cascade="all, delete-orphan",
    )
    cert_policy = db.relationship(
        "DepartmentCertPolicy",
        back_populates="department",
        uselist=False,
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        db.UniqueConstraint("organization_id", "name", name="uix_org_dept_name"),
    )

    def __repr__(self):
        """String representation of Department."""
        return f"<Department {self.name} (org_id={self.organization_id})>"

    def to_dict(self, exclude=None):
        """Convert department to dictionary."""
        exclude = exclude or []
        data = super().to_dict(exclude=exclude)
        data["member_count"] = len([m for m in self.memberships if m.deleted_at is None])
        data["principal_count"] = len([p for p in self.principal_links if p.deleted_at is None])
        return data

    def get_members(self, active_only: bool = True):
        """Get all members of this department.

        Args:
            active_only: If True, exclude soft-deleted members

        Returns:
            List of DepartmentMembership objects
        """
        if active_only:
            return [m for m in self.memberships if m.deleted_at is None]
        return list(self.memberships)

    def get_principals(self, active_only: bool = True):
        """Get all principals assigned to this department.

        Args:
            active_only: If True, exclude soft-deleted principals

        Returns:
            List of Principal objects via DepartmentPrincipal
        """
        if active_only:
            return [
                p.principal
                for p in self.principal_links
                if p.deleted_at is None and p.principal.deleted_at is None
            ]
        return [p.principal for p in self.principal_links]

    def is_member(self, user_id: str) -> bool:
        """Check if a user is a member of this department.

        Args:
            user_id: ID of the user to check

        Returns:
            True if user is an active member, False otherwise
        """
        return (
            DepartmentMembership.query.filter_by(
                user_id=user_id,
                department_id=self.id,
                deleted_at=None,
            ).first()
            is not None
        )

    def get_member_count(self) -> int:
        """Get the count of active members in this department."""
        return len(self.get_members(active_only=True))


class DepartmentMembership(BaseModel):
    """Department membership model representing user membership in a department.

    When a user is added to a department, they become eligible for SSH principals
    assigned to that department.
    """

    __tablename__ = "department_memberships"

    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id"),
        nullable=False,
        index=True,
    )
    department_id = db.Column(
        db.String(36),
        db.ForeignKey("departments.id"),
        nullable=False,
        index=True,
    )

    # Relationships
    user = db.relationship("User", back_populates="department_memberships")
    department = db.relationship("Department", back_populates="memberships")

    __table_args__ = (
        db.UniqueConstraint("user_id", "department_id", name="uix_user_dept"),
    )

    def __repr__(self):
        """String representation of DepartmentMembership."""
        return (
            f"<DepartmentMembership user_id={self.user_id} dept_id={self.department_id}>"
        )


class DepartmentPrincipal(BaseModel):
    """Department principal assignment model.

    Represents the assignment of principals to departments. All members of a
    department get access to its assigned principals (transitively).

    Example:
        - Department: "Engineering"
        - Principal: "eng-prod-servers"
        - All engineering department members can SSH as "eng-prod-servers"
    """

    __tablename__ = "department_principals"

    department_id = db.Column(
        db.String(36),
        db.ForeignKey("departments.id"),
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
    department = db.relationship("Department", back_populates="principal_links")
    principal = db.relationship("Principal", back_populates="department_links")

    __table_args__ = (
        db.UniqueConstraint("department_id", "principal_id", name="uix_dept_principal"),
    )

    def __repr__(self):
        """String representation of DepartmentPrincipal."""
        return (
            f"<DepartmentPrincipal dept_id={self.department_id} "
            f"principal_id={self.principal_id}>"
        )
