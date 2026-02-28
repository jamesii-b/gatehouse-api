"""Base model with common fields and functionality."""
import uuid
from datetime import datetime, timezone
from gatehouse_app.extensions import db


class BaseModel(db.Model):
    """Base model class with common fields."""

    __abstract__ = True

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        unique=True,
        nullable=False,
    )
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc)
    )
    deleted_at = db.Column(db.DateTime, nullable=True)

    @classmethod
    def create(cls, **kwargs):
        """Create and save a new model instance.
        
        Args:
            **kwargs: Model field values
            
        Returns:
            The created model instance
        """
        instance = cls(**kwargs)
        db.session.add(instance)
        db.session.commit()
        return instance

    def save(self):
        """Save the model instance to database."""
        db.session.add(self)
        db.session.commit()
        return self

    def delete(self, soft=True):
        """
        Delete the model instance.

        Args:
            soft: If True, performs soft delete. If False, hard delete.
        """
        if soft:
            self.deleted_at = datetime.now(timezone.utc)
            db.session.commit()
        else:
            db.session.delete(self)
            db.session.commit()

    def update(self, **kwargs):
        """Update model fields."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        self.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        return self

    def to_dict(self, exclude=None):
        """
        Convert model to dictionary.

        Args:
            exclude: List of fields to exclude from output

        Returns:
            Dictionary representation of the model
        """
        exclude = exclude or []
        result = {}
        for column in self.__table__.columns:
            if column.name not in exclude:
                value = getattr(self, column.name)
                if isinstance(value, datetime):
                    if value.tzinfo is None:
                        result[column.name] = value.isoformat() + "Z"
                    else:
                        result[column.name] = value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                else:
                    result[column.name] = value
        return result
