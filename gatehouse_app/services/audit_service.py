"""Audit service."""
from flask import request, g
from gatehouse_app.models.auth.audit_log import AuditLog
from gatehouse_app.utils.constants import AuditAction


class AuditService:
    """Service for audit logging."""

    @staticmethod
    def log_action(
        action,
        user_id=None,
        organization_id=None,
        resource_type=None,
        resource_id=None,
        metadata=None,
        description=None,
        success=True,
        error_message=None,
    ):
        """
        Create an audit log entry.

        Args:
            action: AuditAction enum value
            user_id: ID of user performing the action
            organization_id: ID of related organization
            resource_type: Type of resource being acted upon
            resource_id: ID of resource being acted upon
            metadata: Additional metadata dictionary
            description: Human-readable description
            success: Whether the action succeeded
            error_message: Error message if action failed

        Returns:
            AuditLog instance
        """
        # Get request details if available
        ip_address = None
        user_agent = None
        request_id = None

        try:
            if request:
                ip_address = request.remote_addr
                user_agent = request.headers.get("User-Agent")
                request_id = g.get("request_id")
        except RuntimeError:
            # No request context
            pass

        log_entry = AuditLog(
            action=action,
            user_id=user_id,
            organization_id=organization_id,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            metadata=metadata,
            description=description,
            success=success,
            error_message=error_message,
        )
        log_entry.save()

        return log_entry

    @staticmethod
    def get_user_activity(user_id, limit=50):
        """
        Get recent activity for a user.

        Args:
            user_id: User ID
            limit: Maximum number of records to return

        Returns:
            List of AuditLog instances
        """
        return (
            AuditLog.query.filter_by(user_id=user_id)
            .order_by(AuditLog.created_at.desc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_organization_activity(organization_id, limit=50):
        """
        Get recent activity for an organization.

        Args:
            organization_id: Organization ID
            limit: Maximum number of records to return

        Returns:
            List of AuditLog instances
        """
        return (
            AuditLog.query.filter_by(organization_id=organization_id)
            .order_by(AuditLog.created_at.desc())
            .limit(limit)
            .all()
        )

    # External Authentication Provider Audit Methods

    @staticmethod
    def log_external_auth_link_initiated(
        user_id: str,
        organization_id: str,
        provider_type: str,
        state_id: str = None,
    ):
        """Log external auth account linking initiated event."""
        return AuditService.log_action(
            action=AuditAction.EXTERNAL_AUTH_LINK_INITIATED,
            user_id=user_id,
            organization_id=organization_id,
            resource_type="oauth_state",
            resource_id=state_id,
            metadata={
                "provider_type": provider_type,
            },
            description=f"External auth link initiated for {provider_type}",
            success=True,
        )

    @staticmethod
    def log_external_auth_link_completed(
        user_id: str,
        organization_id: str,
        provider_type: str,
        provider_user_id: str,
        auth_method_id: str = None,
    ):
        """Log external auth account linking completed event."""
        return AuditService.log_action(
            action=AuditAction.EXTERNAL_AUTH_LINK_COMPLETED,
            user_id=user_id,
            organization_id=organization_id,
            resource_type="authentication_method",
            resource_id=auth_method_id,
            metadata={
                "provider_type": provider_type,
                "provider_user_id": provider_user_id,
            },
            description=f"External auth account linked: {provider_type} ({provider_user_id})",
            success=True,
        )

    @staticmethod
    def log_external_auth_link_failed(
        user_id: str,
        organization_id: str,
        provider_type: str,
        error_message: str,
        failure_reason: str = None,
    ):
        """Log external auth account linking failed event."""
        return AuditService.log_action(
            action=AuditAction.EXTERNAL_AUTH_LINK_FAILED,
            user_id=user_id,
            organization_id=organization_id,
            metadata={
                "provider_type": provider_type,
                "failure_reason": failure_reason,
            },
            description=f"External auth link failed for {provider_type}: {error_message}",
            success=False,
            error_message=error_message,
        )

    @staticmethod
    def log_external_auth_unlink(
        user_id: str,
        organization_id: str,
        provider_type: str,
        provider_user_id: str,
        auth_method_id: str = None,
    ):
        """Log external auth account unlinking event."""
        return AuditService.log_action(
            action=AuditAction.EXTERNAL_AUTH_UNLINK,
            user_id=user_id,
            organization_id=organization_id,
            resource_type="authentication_method",
            resource_id=auth_method_id,
            metadata={
                "provider_type": provider_type,
                "provider_user_id": provider_user_id,
            },
            description=f"External auth account unlinked: {provider_type} ({provider_user_id})",
            success=True,
        )

    @staticmethod
    def log_external_auth_login(
        user_id: str,
        organization_id: str,
        provider_type: str,
        provider_user_id: str,
        auth_method_id: str = None,
        session_id: str = None,
        mfa_used: bool = False,
    ):
        """Log external auth login event."""
        return AuditService.log_action(
            action=AuditAction.EXTERNAL_AUTH_LOGIN,
            user_id=user_id,
            organization_id=organization_id,
            resource_type="session",
            resource_id=session_id,
            metadata={
                "provider_type": provider_type,
                "provider_user_id": provider_user_id,
                "auth_method_id": auth_method_id,
                "mfa_used": mfa_used,
            },
            description=f"User logged in with {provider_type}",
            success=True,
        )

    @staticmethod
    def log_external_auth_login_failed(
        organization_id: str,
        provider_type: str,
        provider_user_id: str = None,
        email: str = None,
        failure_reason: str = None,
        error_message: str = None,
    ):
        """Log external auth login failed event."""
        return AuditService.log_action(
            action=AuditAction.EXTERNAL_AUTH_LOGIN_FAILED,
            user_id=None,  # Unknown user
            organization_id=organization_id,
            metadata={
                "provider_type": provider_type,
                "provider_user_id": provider_user_id,
                "email": email,
                "failure_reason": failure_reason,
            },
            description=f"Failed login attempt with {provider_type}: {failure_reason or error_message}",
            success=False,
            error_message=error_message or failure_reason,
        )

    @staticmethod
    def log_external_auth_token_refresh(
        user_id: str,
        organization_id: str,
        provider_type: str,
        auth_method_id: str = None,
    ):
        """Log external auth token refresh event."""
        return AuditService.log_action(
            action=AuditAction.EXTERNAL_AUTH_TOKEN_REFRESH,
            user_id=user_id,
            organization_id=organization_id,
            resource_type="authentication_method",
            resource_id=auth_method_id,
            metadata={
                "provider_type": provider_type,
            },
            description=f"External auth token refreshed for {provider_type}",
            success=True,
        )

    @staticmethod
    def log_external_auth_config_create(
        user_id: str,
        organization_id: str,
        provider_type: str,
        config_id: str = None,
    ):
        """Log external auth provider config creation event."""
        return AuditService.log_action(
            action=AuditAction.EXTERNAL_AUTH_CONFIG_CREATE,
            user_id=user_id,
            organization_id=organization_id,
            resource_type="external_provider_config",
            resource_id=config_id,
            metadata={
                "provider_type": provider_type,
            },
            description=f"External auth provider config created: {provider_type}",
            success=True,
        )

    @staticmethod
    def log_external_auth_config_update(
        user_id: str,
        organization_id: str,
        provider_type: str,
        config_id: str = None,
        changes: dict = None,
    ):
        """Log external auth provider config update event."""
        return AuditService.log_action(
            action=AuditAction.EXTERNAL_AUTH_CONFIG_UPDATE,
            user_id=user_id,
            organization_id=organization_id,
            resource_type="external_provider_config",
            resource_id=config_id,
            metadata={
                "provider_type": provider_type,
                "changes": changes,
            },
            description=f"External auth provider config updated: {provider_type}",
            success=True,
        )

    @staticmethod
    def log_external_auth_config_delete(
        user_id: str,
        organization_id: str,
        provider_type: str,
        config_id: str = None,
    ):
        """Log external auth provider config deletion event."""
        return AuditService.log_action(
            action=AuditAction.EXTERNAL_AUTH_CONFIG_DELETE,
            user_id=user_id,
            organization_id=organization_id,
            resource_type="external_provider_config",
            resource_id=config_id,
            metadata={
                "provider_type": provider_type,
            },
            description=f"External auth provider config deleted: {provider_type}",
            success=True,
        )
