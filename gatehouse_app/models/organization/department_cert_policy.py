"""DepartmentCertPolicy — per-department SSH certificate issuance rules."""
from datetime import datetime, timezone
from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel


# Standard SSH certificate extensions
STANDARD_EXTENSIONS = [
    "permit-X11-forwarding",
    "permit-agent-forwarding",
    "permit-pty",
    "permit-port-forwarding",
    "permit-user-rc",
]


class DepartmentCertPolicy(BaseModel):
    """SSH certificate policy for a department.

    Controls:
    - Whether members may choose their own expiry date (up to ``max_expiry_hours``)
    - Default expiry hours when the user doesn't (or can't) pick
    - Maximum expiry hours (hard ceiling, even for admins signing on behalf)
    - Which SSH certificate extensions are granted to members of this department
    - Any custom extensions the admin wants to add beyond the standard five

    Inherits ``id``, ``created_at``, ``updated_at``, and ``deleted_at`` from
    :class:`BaseModel` so soft-delete and the standard timestamp behaviour are
    consistent with every other model in the application.
    """

    __tablename__ = "department_cert_policies"

    department_id = db.Column(
        db.String(36),
        db.ForeignKey("departments.id"),
        nullable=False,
        unique=True,
        index=True,
    )

    # Expiry control
    allow_user_expiry = db.Column(db.Boolean, nullable=False, default=False)
    default_expiry_hours = db.Column(db.Integer, nullable=False, default=1)
    max_expiry_hours = db.Column(db.Integer, nullable=False, default=24)

    # Extensions — list of extension name strings
    allowed_extensions = db.Column(
        db.JSON,
        nullable=False,
        default=lambda: list(STANDARD_EXTENSIONS),
    )
    # Admin-defined extras beyond the standard five
    custom_extensions = db.Column(db.JSON, nullable=False, default=list)

    # Relationship back to department
    department = db.relationship("Department", back_populates="cert_policy", uselist=False)

    def __repr__(self):
        return (
            f"<DepartmentCertPolicy dept={self.department_id} "
            f"allow_user_expiry={self.allow_user_expiry}>"
        )

    def all_extensions(self) -> list:
        """Return the full list of enabled extensions (allowed + custom)."""
        return list((self.allowed_extensions or []) + (self.custom_extensions or []))

    def to_dict(self, exclude=None):
        """Convert to dictionary."""
        exclude = exclude or []
        data = super().to_dict(exclude=exclude)
        # Augment with computed / convenience fields not in the base columns
        data["all_extensions"] = self.all_extensions()
        data["standard_extensions"] = STANDARD_EXTENSIONS
        return data
