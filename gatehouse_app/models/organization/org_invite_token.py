"""Organization invite token model."""
import secrets
from datetime import datetime, timezone, timedelta

from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel


class OrgInviteToken(BaseModel):
    """Token-based invitation to join an organization."""

    __tablename__ = "org_invite_tokens"

    organization_id = db.Column(
        db.String(36),
        db.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    invited_by_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    email = db.Column(db.String(255), nullable=False, index=True)
    role = db.Column(db.String(64), nullable=False, default="member")
    token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    accepted_at = db.Column(db.DateTime, nullable=True)

    organization = db.relationship(
        "Organization",
        backref=db.backref("invite_tokens", cascade="all, delete-orphan"),
    )
    invited_by = db.relationship("User", foreign_keys=[invited_by_id])

    @classmethod
    def generate(
        cls,
        organization_id: str,
        email: str,
        role: str = "member",
        invited_by_id: str = None,
        ttl_days: int = 7,
    ) -> "OrgInviteToken":
        """Create a new invite token for an organization."""
        token_value = secrets.token_urlsafe(48)
        instance = cls(
            organization_id=organization_id,
            email=email.lower(),
            role=role,
            invited_by_id=invited_by_id,
            token=token_value,
            expires_at=datetime.now(timezone.utc) + timedelta(days=ttl_days),
        )
        db.session.add(instance)
        db.session.commit()
        return instance

    @property
    def is_valid(self) -> bool:
        """Return True if the token is unused and not expired."""
        if self.accepted_at is not None:
            return False
        now = datetime.now(timezone.utc)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return now < expires

    def accept(self) -> None:
        """Mark the invite as accepted."""
        self.accepted_at = datetime.now(timezone.utc)
        db.session.commit()

    def __repr__(self) -> str:
        return f"<OrgInviteToken org={self.organization_id} email={self.email}>"
