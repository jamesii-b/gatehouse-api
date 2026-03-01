"""Email verification token model."""
import secrets
from datetime import datetime, timezone, timedelta

from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel


class EmailVerificationToken(BaseModel):
    """Single-use token for verifying a user's email address."""

    __tablename__ = "email_verification_tokens"

    user_id = db.Column(
        db.String(36),
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship(
        "User",
        backref=db.backref("email_verification_tokens", cascade="all, delete-orphan"),
    )

    @classmethod
    def generate(cls, user_id: str, ttl_hours: int = 24) -> "EmailVerificationToken":
        """Create a new verification token for a user.

        Any existing unused tokens for this user are invalidated first.
        """
        cls.query.filter_by(user_id=user_id, used_at=None).delete()
        db.session.flush()

        token_value = secrets.token_urlsafe(48)
        instance = cls(
            user_id=user_id,
            token=token_value,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=ttl_hours),
        )
        db.session.add(instance)
        db.session.commit()
        return instance

    @property
    def is_valid(self) -> bool:
        """Return True if the token has not been used and has not expired."""
        if self.used_at is not None:
            return False
        now = datetime.now(timezone.utc)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return now < expires

    def consume(self) -> None:
        """Mark the token as used."""
        self.used_at = datetime.now(timezone.utc)
        db.session.commit()

    def __repr__(self) -> str:
        return (
            f"<EmailVerificationToken user_id={self.user_id} "
            f"used={self.used_at is not None}>"
        )
