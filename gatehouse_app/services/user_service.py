"""User service."""
import logging
from flask import current_app
from gatehouse_app.extensions import db
from gatehouse_app.models.user.user import User
from gatehouse_app.exceptions.validation_exceptions import UserNotFoundError
from gatehouse_app.utils.constants import AuditAction
from gatehouse_app.services.audit_service import AuditService

logger = logging.getLogger(__name__)


class UserService:
    """Service for user operations."""

    @staticmethod
    def get_user_by_id(user_id):
        """
        Get user by ID.

        Args:
            user_id: User ID

        Returns:
            User instance

        Raises:
            UserNotFoundError: If user not found
        """
        user = User.query.filter_by(id=user_id, deleted_at=None).first()
        
        # Development-only debug logging for user validation
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[User] Get user by ID: user_id={user_id}, exists={user is not None}")
        
        if not user:
            raise UserNotFoundError()
        return user

    @staticmethod
    def get_user_by_email(email):
        """
        Get user by email.

        Args:
            email: User email

        Returns:
            User instance or None
        """
        user = User.query.filter_by(email=email.lower(), deleted_at=None).first()
        
        # Development-only debug logging for user validation
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[User] Get user by email: email={email}, exists={user is not None}")
        
        return user

    @staticmethod
    def update_user(user, **kwargs):
        """
        Update user profile.

        Args:
            user: User instance
            **kwargs: Fields to update

        Returns:
            Updated User instance
        """
        allowed_fields = ["full_name", "avatar_url"]
        update_data = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if update_data:
            user.update(**update_data)

            # Log user update
            AuditService.log_action(
                action=AuditAction.USER_UPDATE,
                user_id=user.id,
                resource_type="user",
                resource_id=user.id,
                metadata=update_data,
                description="User profile updated",
            )

        return user

    @staticmethod
    def delete_user(user, soft=True):
        """
        Delete user account.

        Args:
            user: User instance
            soft: If True, performs soft delete

        Returns:
            Deleted User instance
        """
        user.delete(soft=soft)

        # Log user deletion
        AuditService.log_action(
            action=AuditAction.USER_DELETE,
            user_id=user.id,
            resource_type="user",
            resource_id=user.id,
            description=f"User account {'soft' if soft else 'hard'} deleted",
        )

        return user

    @staticmethod
    def get_user_organizations(user):
        """
        Get all organizations the user is a member of.

        Args:
            user: User instance

        Returns:
            List of organizations
        """
        return user.get_organizations()
