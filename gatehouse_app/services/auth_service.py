"""Authentication service."""
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from flask import request, g, current_app
from gatehouse_app.extensions import db, bcrypt
from gatehouse_app.models.user.user import User
from gatehouse_app.models.auth.authentication_method import AuthenticationMethod
from gatehouse_app.models.user.session import Session
from gatehouse_app.utils.constants import AuthMethodType, SessionStatus, UserStatus, AuditAction
from gatehouse_app.exceptions.auth_exceptions import InvalidCredentialsError, AccountSuspendedError, AccountInactiveError
from gatehouse_app.exceptions.validation_exceptions import EmailAlreadyExistsError
from gatehouse_app.services.audit_service import AuditService
from gatehouse_app.services.totp_service import TOTPService

logger = logging.getLogger(__name__)


class AuthService:
    """Service for authentication operations."""

    @staticmethod
    def register_user(email, password, full_name=None):
        """
        Register a new user with email/password.

        Args:
            email: User email address
            password: Plain text password
            full_name: Optional full name

        Returns:
            User instance

        Raises:
            EmailAlreadyExistsError: If email is already registered
        """
        # Check if email already exists
        existing_user = User.query.filter_by(email=email.lower()).first()
        if existing_user and existing_user.deleted_at is None:
            raise EmailAlreadyExistsError()

        # Create user
        user = User(
            email=email.lower(),
            full_name=full_name,
            status=UserStatus.ACTIVE,
        )
        user.save()

        # Create password authentication method
        password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        auth_method = AuthenticationMethod(
            user_id=user.id,
            method_type=AuthMethodType.PASSWORD,
            password_hash=password_hash,
            is_primary=True,
            verified=True,
        )
        auth_method.save()

        # Log the registration
        AuditService.log_action(
            action=AuditAction.USER_REGISTER,
            user_id=user.id,
            resource_type="user",
            resource_id=user.id,
            description=f"User registered with email: {email}",
        )

        return user

    @staticmethod
    def authenticate(email, password):
        """
        Authenticate user with email/password.

        Args:
            email: User email
            password: Plain text password

        Returns:
            User instance if authentication succeeds

        Raises:
            InvalidCredentialsError: If credentials are invalid
            AccountSuspendedError: If account is suspended
            AccountInactiveError: If account is inactive
        """
        # Find user
        user = User.query.filter_by(email=email.lower(), deleted_at=None).first()
        
        # Development-only debug logging for user existence check
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[Auth] User lookup: email={email}, exists={user is not None}")
        
        if not user:
            raise InvalidCredentialsError()
        
        # Check account status
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[Auth] Account status: user_id={user.id}, status={user.status}")
        
        if user.status in (UserStatus.SUSPENDED, UserStatus.COMPLIANCE_SUSPENDED):
            raise AccountSuspendedError()
        if user.status == UserStatus.INACTIVE:
            raise AccountInactiveError()
        
        # Find password auth method
        auth_method = AuthenticationMethod.query.filter_by(
            user_id=user.id,
            method_type=AuthMethodType.PASSWORD,
            deleted_at=None,
        ).first()
        
        # Development-only debug logging for auth method lookup
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[Auth] Auth method lookup: user_id={user.id}, has_password_auth={auth_method is not None and auth_method.password_hash is not None}")
        
        if not auth_method or not auth_method.password_hash:
            raise InvalidCredentialsError()
        
        # Verify password
        password_valid = bcrypt.check_password_hash(auth_method.password_hash, password)
        
        # Development-only debug logging for password validation (without logging actual password)
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[Auth] Password validation: user_id={user.id}, valid={password_valid}")
        
        if not password_valid:
            raise InvalidCredentialsError()

        # Update last login
        user.last_login_at = datetime.now(timezone.utc)
        user.last_login_ip = request.remote_addr
        auth_method.last_used_at = datetime.now(timezone.utc)
        db.session.commit()

        return user

    @staticmethod
    def create_session(user, duration_seconds=86400, is_compliance_only=False):
        """
        Create a new session for the user.

        Args:
            user: User instance
            duration_seconds: Session duration in seconds
            is_compliance_only: Whether this is a compliance-only session (limited access)

        Returns:
            Session instance
        """
        # Generate session token
        token = secrets.token_urlsafe(32)

        # Create session
        session = Session(
            user_id=user.id,
            token=token,
            status=SessionStatus.ACTIVE,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=duration_seconds),
            last_activity_at=datetime.now(timezone.utc),
            is_compliance_only=is_compliance_only,
        )
        session.save()

        # Log session creation
        AuditService.log_action(
            action=AuditAction.SESSION_CREATE,
            user_id=user.id,
            resource_type="session",
            resource_id=session.id,
            description="User session created",
        )

        return session

    @staticmethod
    def change_password(user, current_password, new_password):
        """
        Change user password.

        Args:
            user: User instance
            current_password: Current password
            new_password: New password

        Raises:
            InvalidCredentialsError: If current password is incorrect
        """
        # Find password auth method
        auth_method = AuthenticationMethod.query.filter_by(
            user_id=user.id,
            method_type=AuthMethodType.PASSWORD,
            deleted_at=None,
        ).first()

        if not auth_method or not auth_method.password_hash:
            raise InvalidCredentialsError("No password authentication method found")

        # Verify current password
        if not bcrypt.check_password_hash(auth_method.password_hash, current_password):
            raise InvalidCredentialsError("Current password is incorrect")

        # Update password
        auth_method.password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
        db.session.commit()

        # Invalidate all other sessions so that if an attacker had a valid
        # session token, changing the password actually locks them out.
        # The current request's session (if any) is preserved so the user
        # doesn't have to log in again immediately.
        from flask import g as flask_g
        current_session_id = getattr(flask_g, "current_session", None)
        current_session_id = current_session_id.id if current_session_id else None
        sessions_to_revoke = Session.query.filter(
            Session.user_id == user.id,
            Session.revoked_at == None,  # noqa: E711
        ).all()
        for sess in sessions_to_revoke:
            if sess.id != current_session_id:
                sess.revoke(reason="Password changed")
        db.session.commit()

        # Log password change
        AuditService.log_action(
            action=AuditAction.PASSWORD_CHANGE,
            user_id=user.id,
            description="User changed password",
        )

    @staticmethod
    def revoke_session(session_id, reason=None):
        """
        Revoke a session.

        Args:
            session_id: Session ID to revoke
            reason: Optional revocation reason
        """
        session = Session.query.get(session_id)
        if session:
            session.revoke(reason=reason)

            # Log session revocation
            AuditService.log_action(
                action=AuditAction.SESSION_REVOKE,
                user_id=session.user_id,
                resource_type="session",
                resource_id=session.id,
                description=f"Session revoked: {reason or 'User logout'}",
            )

    @staticmethod
    def enroll_totp(user: User) -> dict:
        """
        Initiate TOTP enrollment for a user.

        Args:
            user: User instance

        Returns:
            Dictionary containing:
                - secret: TOTP secret (base32 encoded)
                - provisioning_uri: otpauth:// URI for QR code
                - qr_code: Base64 encoded QR code as data URI
                - backup_codes: List of plain text backup codes

        Raises:
            ConflictError: If user already has TOTP enabled
        """
        from gatehouse_app.exceptions.validation_exceptions import ConflictError

        # Check if user already has TOTP enabled
        if user.has_totp_enabled():
            raise ConflictError("TOTP is already enabled for this account")

        # Clean up any existing unverified TOTP enrollment attempts
        # Use hard delete for unverified methods since they're incomplete enrollment attempts
        existing_totp_method = user.get_totp_method()
        if existing_totp_method and not existing_totp_method.verified:
            logger.debug(f"Removing existing unverified TOTP method for user {user.id}")
            db.session.delete(existing_totp_method)  # Hard delete - unverified methods are temporary
            db.session.commit()  # Commit to ensure deletion before creating new record

        # Generate TOTP secret
        secret = TOTPService.generate_secret()

        # Generate provisioning URI
        provisioning_uri = TOTPService.generate_provisioning_uri(
            user_email=user.email,
            secret=secret,
            issuer="Gatehouse",
        )

        # Generate QR code data URI
        qr_code = TOTPService.generate_qr_code_data_uri(provisioning_uri)

        # Generate backup codes
        backup_codes, hashed_backup_codes = TOTPService.generate_backup_codes()

        # Create unverified TOTP authentication method
        auth_method = AuthenticationMethod(
            user_id=user.id,
            method_type=AuthMethodType.TOTP,
            verified=False,
            is_primary=False,
        )
        auth_method.save()

        # Store TOTP data in provider_data (since totp_secret field is commented out)
        auth_method.provider_data = {
            "secret": secret,
            "backup_codes": hashed_backup_codes,
        }
        db.session.commit()

        # Log TOTP enrollment initiation
        AuditService.log_action(
            action=AuditAction.TOTP_ENROLL_INITIATED,
            user_id=user.id,
            resource_type="authentication_method",
            resource_id=auth_method.id,
            description="TOTP enrollment initiated",
        )

        return {
            "secret": secret,
            "provisioning_uri": provisioning_uri,
            "qr_code": qr_code,
            "backup_codes": backup_codes,
        }

    @staticmethod
    def verify_totp_enrollment(user: User, code: str, client_utc_timestamp: Optional[int] = None) -> bool:
        """
        Complete TOTP enrollment by verifying the first TOTP code.

        Args:
            user: User instance
            code: 6-digit TOTP code from authenticator app
            client_utc_timestamp: Optional client UTC timestamp in seconds since epoch

        Returns:
            True if verification successful

        Raises:
            InvalidCredentialsError: If code is invalid or TOTP method not found
        """
        # Get user's TOTP authentication method
        auth_method = user.get_totp_method()
        if not auth_method:
            raise InvalidCredentialsError("TOTP enrollment not found")

        # Get secret from provider_data
        secret = auth_method.provider_data.get("secret") if auth_method.provider_data else None
        if not secret:
            raise InvalidCredentialsError("TOTP secret not found")

        # Verify the code
        if not TOTPService.verify_code(secret, code, client_utc_timestamp=client_utc_timestamp):
            raise InvalidCredentialsError("Invalid TOTP code")

        # Mark TOTP as verified
        auth_method.verified = True
        auth_method.totp_verified_at = datetime.now(timezone.utc)
        db.session.commit()

        # Log TOTP enrollment completion
        AuditService.log_action(
            action=AuditAction.TOTP_ENROLL_COMPLETED,
            user_id=user.id,
            resource_type="authentication_method",
            resource_id=auth_method.id,
            description="TOTP enrollment completed",
        )

        return True

    @staticmethod
    def disable_totp(user: User, password: str) -> bool:
        """
        Disable TOTP for a user.

        Args:
            user: User instance
            password: User's current password for verification (ignored for OAuth-only users)

        Returns:
            True if TOTP disabled successfully

        Raises:
            InvalidCredentialsError: If password is invalid or TOTP method not found
        """
        # Verify user's password — only required when the user actually has one.
        # OAuth-only users have no PASSWORD auth method; they authenticate via their
        # identity provider so there is nothing to check here.
        auth_method = AuthenticationMethod.query.filter_by(
            user_id=user.id,
            method_type=AuthMethodType.PASSWORD,
            deleted_at=None,
        ).first()

        if auth_method and auth_method.password_hash:
            # Password-based account: a password must be supplied and must match.
            if not password:
                raise InvalidCredentialsError("Password is required")
            if not bcrypt.check_password_hash(auth_method.password_hash, password):
                raise InvalidCredentialsError("Invalid password")

        # Get user's TOTP authentication method
        totp_method = user.get_totp_method()
        if not totp_method:
            raise InvalidCredentialsError("TOTP is not enabled for this account")

        # Soft-delete the TOTP authentication method
        totp_method.delete(soft=True)

        # Log TOTP disabled
        AuditService.log_action(
            action=AuditAction.TOTP_DISABLED,
            user_id=user.id,
            resource_type="authentication_method",
            resource_id=totp_method.id,
            description="TOTP disabled",
        )

        return True

    @staticmethod
    def authenticate_with_totp(user: User, code: str, is_backup_code: bool = False, client_utc_timestamp: Optional[int] = None) -> bool:
        """
        Verify TOTP code during login.

        Args:
            user: User instance
            code: 6-digit TOTP code or backup code
            is_backup_code: True if code is a backup code, False if TOTP code
            client_utc_timestamp: Optional client UTC timestamp in seconds since epoch

        Returns:
            True if code is valid

        Raises:
            InvalidCredentialsError: If code is invalid or TOTP method not found
        """
        # Get user's TOTP authentication method
        auth_method = user.get_totp_method()
        if not auth_method:
            raise InvalidCredentialsError("TOTP is not enabled for this account")

        if is_backup_code:
            # Verify backup code
            backup_codes = (
                auth_method.provider_data.get("backup_codes")
                if auth_method.provider_data
                else []
            )
            is_valid, remaining_codes = TOTPService.verify_backup_code(backup_codes, code)

            if is_valid:
                # Update remaining backup codes
                auth_method.provider_data = {
                    "secret": auth_method.provider_data.get("secret"),
                    "backup_codes": remaining_codes,
                }
                auth_method.last_used_at = datetime.now(timezone.utc)
                db.session.add(auth_method)
                db.session.commit()
                logger.debug(f"[BACKUP CODE] Updated provider_data: {auth_method.provider_data}")

                # Log backup code usage
                AuditService.log_action(
                    action=AuditAction.TOTP_BACKUP_CODE_USED,
                    user_id=user.id,
                    resource_type="authentication_method",
                    resource_id=auth_method.id,
                    description="Backup code used for authentication",
                )
            else:
                # Log failed verification
                AuditService.log_action(
                    action=AuditAction.TOTP_VERIFY_FAILED,
                    user_id=user.id,
                    resource_type="authentication_method",
                    resource_id=auth_method.id,
                    description="Invalid backup code provided",
                )
                raise InvalidCredentialsError("Invalid backup code")
        else:
            # Verify TOTP code
            secret = (
                auth_method.provider_data.get("secret")
                if auth_method.provider_data
                else None
            )
            if not secret:
                raise InvalidCredentialsError("TOTP secret not found")

            # Replay-attack prevention: reject codes that have already been
            # accepted within the current validity window.
            if TOTPService.is_code_already_used(str(user.id), code):
                AuditService.log_action(
                    action=AuditAction.TOTP_VERIFY_FAILED,
                    user_id=user.id,
                    resource_type="authentication_method",
                    resource_id=auth_method.id,
                    description="TOTP code replay attempt detected",
                )
                raise InvalidCredentialsError("Invalid TOTP code")

            is_valid = TOTPService.verify_code(secret, code, client_utc_timestamp=client_utc_timestamp)

            if is_valid:
                # Mark this code as used to prevent replay within the validity window
                TOTPService.mark_code_used(str(user.id), code)

                auth_method.last_used_at = datetime.now(timezone.utc)
                db.session.commit()

                # Log successful verification
                AuditService.log_action(
                    action=AuditAction.TOTP_VERIFY_SUCCESS,
                    user_id=user.id,
                    resource_type="authentication_method",
                    resource_id=auth_method.id,
                    description="TOTP code verified successfully",
                )
            else:
                # Log failed verification
                AuditService.log_action(
                    action=AuditAction.TOTP_VERIFY_FAILED,
                    user_id=user.id,
                    resource_type="authentication_method",
                    resource_id=auth_method.id,
                    description="Invalid TOTP code provided",
                )
                raise InvalidCredentialsError("Invalid TOTP code")

        return True

    @staticmethod
    def regenerate_totp_backup_codes(user: User, password: str) -> list[str]:
        """
        Generate new backup codes for TOTP.

        Args:
            user: User instance
            password: User's current password for verification

        Returns:
            List of new plain text backup codes

        Raises:
            InvalidCredentialsError: If password is invalid or TOTP method not found
        """
        # Verify user's password
        auth_method = AuthenticationMethod.query.filter_by(
            user_id=user.id,
            method_type=AuthMethodType.PASSWORD,
            deleted_at=None,
        ).first()

        if not auth_method or not auth_method.password_hash:
            raise InvalidCredentialsError("No password authentication method found")

        if not bcrypt.check_password_hash(auth_method.password_hash, password):
            raise InvalidCredentialsError("Invalid password")

        # Get user's TOTP authentication method
        totp_method = user.get_totp_method()
        if not totp_method:
            raise InvalidCredentialsError("TOTP is not enabled for this account")

        # Generate new backup codes
        backup_codes, hashed_backup_codes = TOTPService.generate_backup_codes()

        # Update the authentication method with new backup codes
        totp_method.provider_data = {
            "secret": totp_method.provider_data.get("secret"),
            "backup_codes": hashed_backup_codes,
        }
        db.session.commit()

        # Log backup codes regeneration
        AuditService.log_action(
            action=AuditAction.TOTP_BACKUP_CODES_REGENERATED,
            user_id=user.id,
            resource_type="authentication_method",
            resource_id=totp_method.id,
            description="TOTP backup codes regenerated",
        )

        return backup_codes
