"""Session service."""
from datetime import datetime, timezone
from gatehouse_app.models.user.session import Session
from gatehouse_app.utils.constants import SessionStatus


class SessionService:
    """Service for session operations."""

    @staticmethod
    def get_active_session_by_token(token):
        """Get active session by token.
        
        Args:
            token: The session token string
            
        Returns:
            Session object if found and active, None otherwise
        """
        from gatehouse_app.models.user.session import Session
        from gatehouse_app.utils.constants import SessionStatus
        return Session.query.filter_by(
            token=token,
            status=SessionStatus.ACTIVE,
            deleted_at=None
        ).first()

    @staticmethod
    def get_user_sessions(user_id, active_only=True):
        """
        Get all sessions for a user.

        Args:
            user_id: User ID
            active_only: If True, only return active sessions

        Returns:
            List of Session instances
        """
        query = Session.query.filter_by(user_id=user_id, deleted_at=None)

        if active_only:
            query = query.filter_by(status=SessionStatus.ACTIVE).filter(
                Session.expires_at > datetime.now(timezone.utc)
            )

        return query.all()

    @staticmethod
    def revoke_user_sessions(user_id, reason="User logged out from all devices"):
        """
        Revoke all active sessions for a user.

        Args:
            user_id: User ID
            reason: Reason for revocation
        """
        sessions = SessionService.get_user_sessions(user_id, active_only=True)

        for session in sessions:
            session.revoke(reason=reason)

    @staticmethod
    def cleanup_expired_sessions():
        """Clean up expired sessions."""
        expired_sessions = Session.query.filter(
            Session.status == SessionStatus.ACTIVE,
            Session.expires_at < datetime.now(timezone.utc),
            Session.deleted_at.is_(None),
        ).all()

        for session in expired_sessions:
            session.status = SessionStatus.EXPIRED
            session.save()

        return len(expired_sessions)
