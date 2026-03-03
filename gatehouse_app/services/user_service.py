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

        For a soft delete this method also soft-deletes every related row that
        has its own ``deleted_at`` column so that those records stop appearing
        in active queries immediately:
          - OrganizationMember      (user no longer shows in member lists)
          - DepartmentMembership
          - PrincipalMembership
          - CAPermission            (CA access revoked)
          - MfaPolicyCompliance     (compliance record hidden)
          - AuthenticationMethod    (login methods hidden)
          - SSHKey                  (keys are hidden)
          - SSHCertificate          (certs are revoked + hidden)
          - Session                 (all active sessions killed)
          - OIDCAuthCode            (pending auth codes invalidated)
          - OIDCRefreshToken        (refresh tokens invalidated)
          - OIDCSession             (OIDC sessions killed)
          - OIDCTokenMetadata       (token metadata hidden)

        All changes are committed in a single transaction after the user row
        itself is marked deleted, preventing any partial-delete state.

        Args:
            user: User instance
            soft: If True, performs soft delete

        Returns:
            Deleted User instance
        """
        from datetime import datetime, timezone
        from gatehouse_app.extensions import db as _db

        if soft:
            now = datetime.now(timezone.utc)

            # --- Org memberships -------------------------------------------
            for m in user.organization_memberships:
                if m.deleted_at is None:
                    m.deleted_at = now

            # --- Department memberships -------------------------------------
            for m in user.department_memberships:
                if m.deleted_at is None:
                    m.deleted_at = now

            # --- Principal memberships --------------------------------------
            for m in user.principal_memberships:
                if m.deleted_at is None:
                    m.deleted_at = now

            # --- CA permissions --------------------------------------------
            for p in user.ca_permissions:
                if p.deleted_at is None:
                    p.deleted_at = now

            # --- MFA compliance records ------------------------------------
            for c in user.mfa_compliance:
                if c.deleted_at is None:
                    c.deleted_at = now

            # --- Authentication methods ------------------------------------
            for m in user.authentication_methods:
                if m.deleted_at is None:
                    m.deleted_at = now

            # --- SSH keys ---------------------------------------------------
            for key in user.ssh_keys:
                if key.deleted_at is None:
                    key.deleted_at = now

            # --- SSH certificates: revoke then soft-delete ------------------
            for cert in user.ssh_certificates:
                if cert.deleted_at is None:
                    try:
                        if not getattr(cert, "revoked", False):
                            cert.revoke("account_deleted")
                    except Exception:
                        pass
                    cert.deleted_at = now

            # --- Sessions ---------------------------------------------------
            for session in user.sessions:
                if session.deleted_at is None:
                    session.deleted_at = now

            # --- OIDC tokens / sessions ------------------------------------
            for code in user.oidc_auth_codes:
                if code.deleted_at is None:
                    code.deleted_at = now

            for token in user.oidc_refresh_tokens:
                if token.deleted_at is None:
                    token.deleted_at = now

            for oidc_session in user.oidc_sessions:
                if oidc_session.deleted_at is None:
                    oidc_session.deleted_at = now

            for meta in user.oidc_token_metadata:
                if meta.deleted_at is None:
                    meta.deleted_at = now

            # --- Mark the user row itself -----------------------------------
            user.deleted_at = now
            _db.session.commit()
        else:
            user.delete(soft=False)

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
