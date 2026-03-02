"""Authentication endpoints."""
import json
import logging
from flask import request, session, g, jsonify, current_app
from marshmallow import ValidationError
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.extensions import limiter
from gatehouse_app.utils.response import api_response
from gatehouse_app.schemas.auth_schema import (
    RegisterSchema,
    LoginSchema,
    TOTPVerifyEnrollmentSchema,
    TOTPVerifySchema,
    TOTPDisableSchema,
    TOTPRegenerateBackupCodesSchema,
)
from gatehouse_app.schemas.webauthn_schema import (
    WebAuthnRegistrationBeginSchema,
    WebAuthnRegistrationCompleteSchema,
    WebAuthnLoginBeginSchema,
    WebAuthnLoginCompleteSchema,
    WebAuthnCredentialRenameSchema,
)
from gatehouse_app.services.auth_service import AuthService
from gatehouse_app.services.webauthn_service import WebAuthnService
from gatehouse_app.services.user_service import UserService
from gatehouse_app.services.mfa_policy_service import MfaPolicyService
from gatehouse_app.services.notification_service import NotificationService
from gatehouse_app.utils.decorators import login_required
from gatehouse_app.utils.constants import AuditAction
from gatehouse_app.exceptions.auth_exceptions import InvalidCredentialsError
from gatehouse_app.exceptions.validation_exceptions import ConflictError, NotFoundError


@api_v1_bp.route("/auth/register", methods=["POST"])
@limiter.limit(lambda: current_app.config["RATELIMIT_AUTH_REGISTER"])
def register():
    """
    Register a new user.

    Request body:
        email: User email
        password: User password
        password_confirm: Password confirmation
        full_name: Optional full name

    Returns:
        201: User created successfully
        400: Validation error
        409: Email already exists
    """
    try:
        # Validate request data
        schema = RegisterSchema()
        data = schema.load(request.json)

        # Register user
        user = AuthService.register_user(
            email=data["email"],
            password=data["password"],
            full_name=data.get("full_name"),
        )

        # Send verification email
        try:
            from gatehouse_app.models import EmailVerificationToken
            verify_token = EmailVerificationToken.generate(user_id=user.id)
            app_url = current_app.config.get("APP_URL", "http://localhost:8080")
            verify_link = f"{app_url}/verify-email?token={verify_token.token}"
            subject = "Verify your Gatehouse email address"
            body = (
                f"Hi {user.full_name or user.email},\n\n"
                f"Welcome to Gatehouse! Please verify your email address by clicking the link below (valid for 24 hours):\n"
                f"{verify_link}\n\n"
                f"Gatehouse Security Team"
            )
            NotificationService._send_email(to_address=user.email, subject=subject, body=body)
        except Exception as exc:
            logging.getLogger(__name__).warning(f"Failed to send verification email on register: {exc}")

        # Create session
        user_session = AuthService.create_session(user)

        # ── Post-registration hints ─────────────────────────────────────────
        from gatehouse_app.models.organization.org_invite_token import OrgInviteToken
        from gatehouse_app.models.user.user import User as _User
        from datetime import datetime, timezone as _tz

        now = datetime.now(_tz.utc)
        pending_invites = OrgInviteToken.query.filter(
            OrgInviteToken.email == user.email,
            OrgInviteToken.accepted_at.is_(None),
            OrgInviteToken.expires_at > now,
            OrgInviteToken.deleted_at.is_(None),
        ).all()

        # Determine if this is the very first user ever registered on this
        # instance (exactly 1 active user means it must be this one).
        total_users = _User.query.filter(_User.deleted_at.is_(None)).count()
        is_first_user = total_users == 1

        expires_str = user_session.expires_at.isoformat()
        if expires_str[-1] != "Z":
            expires_str += "Z"

        return api_response(
            data={
                "user": user.to_dict(),
                "token": user_session.token,
                "expires_at": expires_str,
                "is_first_user": is_first_user,
                "pending_invites": [
                    {
                        "token": inv.token,
                        "organization": {
                            "id": str(inv.organization_id),
                            "name": inv.organization.name,
                        },
                        "role": inv.role,
                        "expires_at": inv.expires_at.isoformat(),
                    }
                    for inv in pending_invites
                ],
            },
            message="Registration successful",
            status=201,
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )


@api_v1_bp.route("/auth/login", methods=["POST"])
@limiter.limit(lambda: current_app.config["RATELIMIT_AUTH_LOGIN"])
def login():
    """
    Login user.

    Request body:
        email: User email
        password: User password
        remember_me: Optional boolean for extended session

    Returns:
        200: Login successful or TOTP code required
        400: Validation error
        401: Invalid credentials
    """
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        # Validate request data
        schema = LoginSchema()
        data = schema.load(request.json)

        # Authenticate user with email and password
        user = AuthService.authenticate(
            email=data["email"],
            password=data["password"],
        )

        # Check MFA enrollment status
        has_totp = user.has_totp_enabled()
        has_webauthn = user.has_webauthn_enabled()
        logger.info(f"Login attempt for user {user.email} - TOTP enabled: {has_totp}, WebAuthn enabled: {has_webauthn}")

        # MFA Enforcement: Check WebAuthn first (most secure), then TOTP fallback
        # Priority: WebAuthn > TOTP > No MFA
        if has_webauthn:
            # User has WebAuthn enrolled - require WebAuthn verification
            # Store user_id in session for WebAuthn verification
            # The /auth/webauthn/login/complete endpoint will retrieve this user_id
            session["webauthn_pending_user_id"] = user.id

            # Return response indicating WebAuthn verification is required
            return api_response(
                data={
                    "requires_webauthn": True,
                },
                message="Passkey verification required. Please use your passkey to complete login.",
            )

        # Check if user has TOTP enabled for two-factor authentication
        if has_totp:
            # TOTP is enabled - store user_id in session for TOTP verification
            # The /auth/totp/verify endpoint will retrieve this user_id
            session["totp_pending_user_id"] = user.id

            # Return response indicating TOTP code is required
            # Do NOT create session or return token yet - wait for TOTP verification
            return api_response(
                data={
                    "requires_totp": True,
                },
                message="TOTP code required. Please enter your 6-digit code from your authenticator app.",
            )
        
        # Evaluate MFA policy after primary authentication
        remember_me = data.get("remember_me", False)
        policy_result = MfaPolicyService.after_primary_auth_success(user, remember_me)

        # Create session with appropriate duration based on remember_me preference
        duration = 2592000 if remember_me else 86400  # 30 days vs 1 day

        # Determine if this should be a compliance-only session
        is_compliance_only = policy_result.create_compliance_only_session

        user_session = AuthService.create_session(
            user,
            duration_seconds=duration,
            is_compliance_only=is_compliance_only
        )

        # Build response data
        response_data = {
            "user": user.to_dict(),
            "token": user_session.token,
            "expires_at": user_session.expires_at.isoformat() + "Z" if user_session.expires_at.isoformat()[-1] != "Z" else user_session.expires_at.isoformat(),
        }

        # Add MFA compliance information
        if policy_result.compliance_summary:
            response_data["mfa_compliance"] = {
                "overall_status": policy_result.compliance_summary.overall_status,
                "missing_methods": policy_result.compliance_summary.missing_methods,
                "deadline_at": policy_result.compliance_summary.deadline_at,
                "orgs": [
                    {
                        "organization_id": org.organization_id,
                        "organization_name": org.organization_name,
                        "status": org.status,
                        "effective_mode": org.effective_mode,
                        "deadline_at": org.deadline_at,
                        "applied_at": org.applied_at,
                    }
                    for org in policy_result.compliance_summary.orgs
                ],
            }

        # Add requires_mfa_enrollment flag if compliance-only session
        if is_compliance_only:
            response_data["requires_mfa_enrollment"] = True

        # ── Org-setup hint for org-less users ────────────────────────────────
        # If the user has no organisation memberships, surface any pending
        # invitations so the UI can redirect straight to /org-setup instead of
        # showing an empty dashboard.
        user_orgs = user.get_organizations()
        if not user_orgs:
            from gatehouse_app.models.organization.org_invite_token import OrgInviteToken
            from datetime import datetime, timezone as _tz
            _now = datetime.now(_tz.utc)
            pending_invites = OrgInviteToken.query.filter(
                OrgInviteToken.email == user.email,
                OrgInviteToken.accepted_at.is_(None),
                OrgInviteToken.expires_at > _now,
                OrgInviteToken.deleted_at.is_(None),
            ).all()
            response_data["pending_invites"] = [
                {
                    "token": inv.token,
                    "organization": {
                        "id": str(inv.organization_id),
                        "name": inv.organization.name,
                    },
                    "role": inv.role,
                    "expires_at": inv.expires_at.isoformat(),
                }
                for inv in pending_invites
            ]
            # Flag so the UI knows to send this user through org-setup
            response_data["requires_org_setup"] = True

        return api_response(
            data=response_data,
            message="Login successful",
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )


@api_v1_bp.route("/auth/logout", methods=["POST"])
@login_required
def logout():
    """
    Logout current user.

    Returns:
        200: Logout successful
        401: Not authenticated
    """
    # Revoke current session (g.current_session is set by login_required decorator)
    if g.current_session:
        AuthService.revoke_session(g.current_session.id, reason="User logout")

    return api_response(
        message="Logout successful",
    )


@api_v1_bp.route("/auth/me", methods=["GET"])
@login_required
def get_current_user():
    """
    Get current authenticated user.

    Returns:
        200: User data
        401: Not authenticated
    """
    user = g.current_user

    return api_response(
        data={
            "user": user.to_dict(),
            "organizations": [
                {
                    "id": membership.organization.id,
                    "name": membership.organization.name,
                    "slug": membership.organization.slug,
                    "role": membership.role,
                }
                for membership in user.organization_memberships
            ],
        },
        message="User retrieved successfully",
    )


@api_v1_bp.route("/auth/sessions", methods=["GET"])
@login_required
def get_user_sessions():
    """
    Get all active sessions for current user.

    Returns:
        200: List of active sessions
        401: Not authenticated
    """
    from gatehouse_app.services.session_service import SessionService

    sessions = SessionService.get_user_sessions(g.current_user.id, active_only=True)

    return api_response(
        data={
            "sessions": [session.to_dict() for session in sessions],
            "count": len(sessions),
        },
        message="Sessions retrieved successfully",
    )


@api_v1_bp.route("/auth/sessions/<session_id>", methods=["DELETE"])
@login_required
def revoke_session(session_id):
    """
    Revoke a specific session.

    Args:
        session_id: ID of session to revoke

    Returns:
        200: Session revoked
        401: Not authenticated
        404: Session not found
    """
    from gatehouse_app.models.user.session import Session

    # Ensure session belongs to current user
    user_session = Session.query.filter_by(
        id=session_id, user_id=g.current_user.id, deleted_at=None
    ).first()

    if not user_session:
        return api_response(
            success=False,
            message="Session not found",
            status=404,
            error_type="NOT_FOUND",
        )

    AuthService.revoke_session(session_id, reason="Revoked by user")

    return api_response(
        message="Session revoked successfully",
    )


@api_v1_bp.route("/auth/totp/enroll", methods=["POST"])
@login_required
def enroll_totp():
    """
    Initiate TOTP enrollment for the current user.

    Returns:
        201: TOTP enrollment initiated with secret, provisioning_uri, qr_code, and backup_codes
        401: Not authenticated
        409: TOTP already enabled
    """
    try:
        # Initiate TOTP enrollment
        result = AuthService.enroll_totp(g.current_user)

        return api_response(
            data={
                "secret": result["secret"],
                "provisioning_uri": result["provisioning_uri"],
                "qr_code": result["qr_code"],
                "backup_codes": result["backup_codes"],
            },
            message="TOTP enrollment initiated. Please verify with your authenticator app.",
            status=201,
        )

    except ConflictError as e:
        return api_response(
            success=False,
            message=e.message,
            status=e.status_code,
            error_type=e.error_type,
        )


@api_v1_bp.route("/auth/totp/verify-enrollment", methods=["POST"])
@login_required
def verify_totp_enrollment():
    """
    Complete TOTP enrollment by verifying the first TOTP code.

    Request body:
        code: 6-digit TOTP code from authenticator app
        client_timestamp: Optional client UTC timestamp in seconds since epoch

    Returns:
        200: TOTP enrollment completed successfully
        400: Validation error
        401: Not authenticated
        401: Invalid TOTP code
    """
    try:
        # Validate request data
        schema = TOTPVerifyEnrollmentSchema()
        data = schema.load(request.json)

        # Verify TOTP enrollment
        AuthService.verify_totp_enrollment(
            g.current_user,
            data["code"],
            client_utc_timestamp=data.get("client_timestamp"),
        )

        return api_response(
            message="TOTP enrollment completed successfully",
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )

    except InvalidCredentialsError as e:
        return api_response(
            success=False,
            message=e.message,
            status=e.status_code,
            error_type=e.error_type,
        )


@api_v1_bp.route("/auth/totp/verify", methods=["POST"])
@limiter.limit(lambda: current_app.config["RATELIMIT_AUTH_TOTP_VERIFY"])
def verify_totp():
    """
    Verify TOTP code during login.

    Request body:
        code: 6-digit TOTP code or backup code
        is_backup_code: True if code is a backup code, False if TOTP code (default: False)
        client_timestamp: Optional client UTC timestamp in seconds since epoch

    Returns:
        200: TOTP code verified successfully with session token
        400: Validation error
        401: Invalid TOTP code or session not found
    """
    try:
        # Validate request data
        schema = TOTPVerifySchema()
        data = schema.load(request.json)

        # Get user from temporary session (stored in Flask session by login endpoint)
        # Check totp_pending_user_id first, then fall back to webauthn_pending_user_id
        # This allows TOTP to be used as a fallback when WebAuthn was the primary MFA method
        user_id = session.get("totp_pending_user_id") or session.get("webauthn_pending_user_id")
        if not user_id:
            return api_response(
                success=False,
                message="No pending TOTP verification. Please login first.",
                status=401,
                error_type="AUTHENTICATION_ERROR",
            )

        # Get user from database
        from gatehouse_app.models.user.user import User
        user = User.query.get(user_id)
        if not user:
            return api_response(
                success=False,
                message="User not found",
                status=401,
                error_type="AUTHENTICATION_ERROR",
            )

        # Check account suspension before completing TOTP verification
        from gatehouse_app.utils.constants import UserStatus
        if user.status in (UserStatus.SUSPENDED, UserStatus.COMPLIANCE_SUSPENDED):
            session.pop("totp_pending_user_id", None)
            session.pop("webauthn_pending_user_id", None)
            return api_response(
                success=False,
                message="Account is suspended. Contact an administrator.",
                status=403,
                error_type="ACCOUNT_SUSPENDED",
            )

        # Verify TOTP code
        AuthService.authenticate_with_totp(
            user,
            data["code"],
            data.get("is_backup_code", False),
            client_utc_timestamp=data.get("client_timestamp"),
        )

        # Evaluate MFA policy after primary authentication
        policy_result = MfaPolicyService.after_primary_auth_success(user, remember_me=False)

        # Determine if this should be a compliance-only session
        is_compliance_only = policy_result.create_compliance_only_session

        # Create session
        user_session = AuthService.create_session(user, is_compliance_only=is_compliance_only)

        # Clear temporary session - clear both pending user IDs
        session.pop("totp_pending_user_id", None)
        session.pop("webauthn_pending_user_id", None)

        # Build response data
        response_data = {
            "user": user.to_dict(),
            "token": user_session.token,
            "expires_at": user_session.expires_at.isoformat() + "Z"
            if user_session.expires_at.isoformat()[-1] != "Z"
            else user_session.expires_at.isoformat(),
        }

        # Add MFA compliance information
        if policy_result.compliance_summary:
            response_data["mfa_compliance"] = {
                "overall_status": policy_result.compliance_summary.overall_status,
                "missing_methods": policy_result.compliance_summary.missing_methods,
                "deadline_at": policy_result.compliance_summary.deadline_at,
                "orgs": [
                    {
                        "organization_id": org.organization_id,
                        "organization_name": org.organization_name,
                        "status": org.status,
                        "effective_mode": org.effective_mode,
                        "deadline_at": org.deadline_at,
                        "applied_at": org.applied_at,
                    }
                    for org in policy_result.compliance_summary.orgs
                ],
            }

        # Add requires_mfa_enrollment flag if compliance-only session
        if is_compliance_only:
            response_data["requires_mfa_enrollment"] = True

        return api_response(
            data=response_data,
            message="TOTP verification successful",
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )

    except InvalidCredentialsError as e:
        return api_response(
            success=False,
            message=e.message,
            status=e.status_code,
            error_type=e.error_type,
        )


@api_v1_bp.route("/auth/totp/disable", methods=["DELETE"])
@login_required
def disable_totp():
    """
    Disable TOTP for the current user.

    Request body:
        password: User's current password for verification

    Returns:
        200: TOTP disabled successfully
        400: Validation error
        401: Not authenticated or invalid password
        401: TOTP not enabled
    """
    try:
        # Validate request data
        schema = TOTPDisableSchema()
        data = schema.load(request.json)

        # Disable TOTP
        AuthService.disable_totp(g.current_user, data["password"])

        return api_response(
            message="TOTP disabled successfully",
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )

    except InvalidCredentialsError as e:
        return api_response(
            success=False,
            message=e.message,
            status=e.status_code,
            error_type=e.error_type,
        )


@api_v1_bp.route("/auth/totp/status", methods=["GET"])
@login_required
def get_totp_status():
    """
    Get TOTP status for the current user.

    Returns:
        200: TOTP status with totp_enabled, verified_at, and backup_codes_remaining
        401: Not authenticated
    """
    user = g.current_user

    # Check if TOTP is enabled
    totp_enabled = user.has_totp_enabled()

    # Get TOTP method to check backup codes remaining
    backup_codes_remaining = 0
    verified_at = None

    if totp_enabled:
        totp_method = user.get_totp_method()
        if totp_method and totp_method.provider_data:
            backup_codes = totp_method.provider_data.get("backup_codes", [])
            backup_codes_remaining = len(backup_codes)
        if totp_method and totp_method.totp_verified_at:
            verified_at = totp_method.totp_verified_at.isoformat() + "Z" if totp_method.totp_verified_at.isoformat()[-1] != "Z" else totp_method.totp_verified_at.isoformat()

    return api_response(
        data={
            "totp_enabled": totp_enabled,
            "verified_at": verified_at,
            "backup_codes_remaining": backup_codes_remaining,
        },
        message="TOTP status retrieved successfully",
    )


@api_v1_bp.route("/auth/totp/regenerate-backup-codes", methods=["POST"])
@login_required
def regenerate_totp_backup_codes():
    """
    Generate new backup codes for TOTP.

    Request body:
        password: User's current password for verification

    Returns:
        200: New backup codes generated successfully
        400: Validation error
        401: Not authenticated or invalid password
        401: TOTP not enabled
    """
    try:
        # Validate request data
        schema = TOTPRegenerateBackupCodesSchema()
        data = schema.load(request.json)

        # Regenerate backup codes
        backup_codes = AuthService.regenerate_totp_backup_codes(
            g.current_user, data["password"]
        )

        return api_response(
            data={
                "backup_codes": backup_codes,
            },
            message="Backup codes regenerated successfully",
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )

    except InvalidCredentialsError as e:
        return api_response(
            success=False,
            message=e.message,
            status=e.status_code,
            error_type=e.error_type,
        )


# =============================================================================
# WebAuthn Passkey Endpoints
# =============================================================================


@api_v1_bp.route("/auth/webauthn/register/begin", methods=["POST"])
@login_required
def begin_webauthn_registration():
    """
    Begin WebAuthn passkey registration.
    
    Returns:
        200: PublicKeyCredentialCreationOptions (raw JSON, no wrapper)
        401: Not authenticated
    """
    user = g.current_user
    
    # Generate registration challenge
    options = WebAuthnService.generate_registration_challenge(user)
    
    # Return unwrapped JSON for WebAuthn
    return jsonify(options), 200


@api_v1_bp.route("/auth/webauthn/register/complete", methods=["POST"])
@login_required
def complete_webauthn_registration():
    """
    Complete WebAuthn passkey registration.
    
    Request body:
        id: Credential ID
        rawId: Base64URL-encoded credential ID
        type: "public-key"
        response: Attestation response data
        transports: List of transport types
    
    Returns:
        200: Registration successful
        400: Validation error
        401: Not authenticated
        409: Credential already exists
    """
    import base64
    import logging
    logger = logging.getLogger(__name__)
    
    user_email = g.current_user.email
    logger.info(f"WebAuthn registration completion started for user: {user_email}")
    
    try:
        # Validate request data
        schema = WebAuthnRegistrationCompleteSchema()
        data = schema.load(request.json)
        
        # Extract challenge from client data
        client_data_json_b64 = data.get("response", {}).get("clientDataJSON", "")
        
        if not client_data_json_b64:
            logger.error(f"WebAuthn registration failed - missing clientDataJSON for user: {user_email}")
            return api_response(
                success=False,
                message="Missing clientDataJSON in response",
                status=400,
                error_type="VALIDATION_ERROR",
            )
        
        try:
            # Add padding if needed
            padding = 4 - (len(client_data_json_b64) % 4)
            if padding != 4:
                client_data_json_b64_padded = client_data_json_b64 + '=' * padding
            else:
                client_data_json_b64_padded = client_data_json_b64
            
            client_data_json = base64.urlsafe_b64decode(client_data_json_b64_padded)
            client_data_dict = json.loads(client_data_json)
            
        except Exception as e:
            logger.error(f"WebAuthn registration failed - client data decode error for user {user_email}: {e}")
            return api_response(
                success=False,
                message=f"Failed to decode client data JSON: {str(e)}",
                status=400,
                error_type="VALIDATION_ERROR",
            )
        
        challenge = client_data_dict.get("challenge")
        
        if not challenge:
            logger.error(f"WebAuthn registration failed - no challenge in client data for user: {user_email}")
            return api_response(
                success=False,
                message="Invalid challenge in client data",
                status=400,
                error_type="VALIDATION_ERROR",
            )
        
        # Verify registration response
        auth_method = WebAuthnService.verify_registration_response(
            g.current_user,
            data,
            challenge
        )
        
        logger.info(f"WebAuthn registration completed successfully for user: {user_email}")
        
        return api_response(
            data={
                "credential": auth_method.to_webauthn_dict(),
            },
            message="Passkey registered successfully",
            status=201,
        )
        
    except ValidationError as e:
        logger.error(f"WebAuthn registration validation error for user {user_email}: {e.messages}")
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )
        
    except InvalidCredentialsError as e:
        logger.warning(f"WebAuthn registration failed for user {user_email}: {e.message}")
        return api_response(
            success=False,
            message=e.message,
            status=e.status_code,
            error_type=e.error_type,
        )
        
    except Exception as e:
        logger.exception(f"WebAuthn registration unexpected error for user {user_email}: {e}")
        return api_response(
            success=False,
            message="An unexpected error occurred during registration",
            status=500,
            error_type="INTERNAL_ERROR",
        )


@api_v1_bp.route("/auth/webauthn/login/begin", methods=["POST"])
def begin_webauthn_login():
    """
    Begin WebAuthn passkey login.
    
    Request body:
        email: User email address
    
    Returns:
        200: PublicKeyCredentialRequestOptions (raw JSON, no wrapper)
        400: Validation error
        404: User not found
    """
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        # Validate request data
        schema = WebAuthnLoginBeginSchema()
        data = schema.load(request.json)
        
        # Find user by email
        from gatehouse_app.models.user.user import User
        user = User.query.filter_by(
            email=data["email"].lower(),
            deleted_at=None
        ).first()
        
        if not user:
            logger.warning(f"WebAuthn login begin - user not found: {data['email']}")
            return api_response(
                success=False,
                message="User not found",
                status=404,
                error_type="NOT_FOUND",
            )

        # Check account suspension before proceeding
        from gatehouse_app.utils.constants import UserStatus
        if user.status in (UserStatus.SUSPENDED, UserStatus.COMPLIANCE_SUSPENDED):
            logger.warning(f"WebAuthn login begin - suspended account attempt: {user.email}")
            return api_response(
                success=False,
                message="Account is suspended. Contact an administrator.",
                status=403,
                error_type="ACCOUNT_SUSPENDED",
            )

        # Check if user has any WebAuthn credentials
        if not user.has_webauthn_enabled():
            logger.warning(f"WebAuthn login begin - no credentials for user: {user.email}")
            return api_response(
                success=False,
                message="No passkeys found for this account",
                status=404,
                error_type="NOT_FOUND",
            )
        
        logger.info(f"WebAuthn login challenge generated for user: {user.email}")
        
        # Generate authentication challenge
        options = WebAuthnService.generate_authentication_challenge(user)
        
        # Store user_id in Flask session for WebAuthn verification
        session["webauthn_pending_user_id"] = user.id
        
        # Return unwrapped JSON for WebAuthn
        return jsonify(options), 200
        
    except ValidationError as e:
        logger.error(f"WebAuthn login begin validation error: {e.messages}")
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )
    except Exception as e:
        logger.exception(f"WebAuthn login begin unexpected error: {e}")
        raise


@api_v1_bp.route("/auth/webauthn/login/complete", methods=["POST"])
def complete_webauthn_login():
    """
    Complete WebAuthn passkey login.
    
    Request body:
        id: Credential ID
        rawId: Base64URL-encoded credential ID
        type: "public-key"
        response: Assertion response data
    
    Returns:
        200: Login successful with session token
        400: Validation error
        401: Authentication failed
    """
    import logging
    import base64
    logger = logging.getLogger(__name__)
    
    try:
        # Get user from Flask session (stored by /begin endpoint)
        user_id = session.get("webauthn_pending_user_id")
        if not user_id:
            logger.error("WebAuthn login complete - no pending verification in session")
            return api_response(
                success=False,
                message="No pending WebAuthn verification. Please initiate login first.",
                status=401,
                error_type="AUTHENTICATION_ERROR",
            )
        
        # Validate request data
        schema = WebAuthnLoginCompleteSchema()
        data = schema.load(request.json)
        
        # Get user from database
        from gatehouse_app.models.user.user import User
        user = User.query.get(user_id)
        if not user:
            logger.error(f"WebAuthn login complete - user not found: {user_id}")
            return api_response(
                success=False,
                message="User not found",
                status=401,
                error_type="AUTHENTICATION_ERROR",
            )

        # Check account suspension before completing login
        from gatehouse_app.utils.constants import UserStatus
        if user.status in (UserStatus.SUSPENDED, UserStatus.COMPLIANCE_SUSPENDED):
            session.pop("webauthn_pending_user_id", None)
            logger.warning(f"WebAuthn login complete - suspended account attempt: {user.email}")
            return api_response(
                success=False,
                message="Account is suspended. Contact an administrator.",
                status=403,
                error_type="ACCOUNT_SUSPENDED",
            )

        # Extract challenge from client data
        client_data = data.get("response", {}).get("clientDataJSON", "")
        
        client_data_json = base64.urlsafe_b64decode(client_data + "==")
        client_data_dict = json.loads(client_data_json)
        
        challenge = client_data_dict.get("challenge")
        
        if not challenge:
            logger.error(f"WebAuthn login complete - no challenge in client data for user: {user.email}")
            return api_response(
                success=False,
                message="Invalid challenge in client data",
                status=400,
                error_type="VALIDATION_ERROR",
            )
        
        # Verify authentication response
        WebAuthnService.verify_authentication_response(
            user,
            data,
            challenge
        )
        
        # Evaluate MFA policy after primary authentication
        policy_result = MfaPolicyService.after_primary_auth_success(user, remember_me=False)
        
        # Determine if this should be a compliance-only session
        is_compliance_only = policy_result.create_compliance_only_session
        
        # Create session
        user_session = AuthService.create_session(user, is_compliance_only=is_compliance_only)
        
        # Clear pending session
        session.pop("webauthn_pending_user_id", None)
        
        logger.info(f"WebAuthn login completed successfully for user: {user.email}")
        
        # Build response data
        response_data = {
            "user": user.to_dict(),
            "token": user_session.token,
            "expires_at": user_session.expires_at.isoformat() + "Z"
            if user_session.expires_at.isoformat()[-1] != "Z"
            else user_session.expires_at.isoformat(),
        }
        
        # Add MFA compliance information
        if policy_result.compliance_summary:
            response_data["mfa_compliance"] = {
                "overall_status": policy_result.compliance_summary.overall_status,
                "missing_methods": policy_result.compliance_summary.missing_methods,
                "deadline_at": policy_result.compliance_summary.deadline_at,
                "orgs": [
                    {
                        "organization_id": org.organization_id,
                        "organization_name": org.organization_name,
                        "status": org.status,
                        "effective_mode": org.effective_mode,
                        "deadline_at": org.deadline_at,
                        "applied_at": org.applied_at,
                    }
                    for org in policy_result.compliance_summary.orgs
                ],
            }
        
        # Add requires_mfa_enrollment flag if compliance-only session
        if is_compliance_only:
            response_data["requires_mfa_enrollment"] = True
        
        return api_response(
            data=response_data,
            message="Login successful",
        )
        
    except ValidationError as e:
        logger.error(f"WebAuthn login complete validation error: {e.messages}")
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )
        
    except InvalidCredentialsError as e:
        logger.warning(f"WebAuthn login complete authentication failed: {e.message}")
        return api_response(
            success=False,
            message=e.message,
            status=e.status_code,
            error_type=e.error_type,
        )
    
    except Exception as e:
        logger.exception(f"WebAuthn login complete unexpected error: {e}")
        raise


@api_v1_bp.route("/auth/webauthn/credentials", methods=["GET"])
@login_required
def list_webauthn_credentials():
    """
    List all WebAuthn passkey credentials for the current user.
    
    Returns:
        200: List of credentials
        401: Not authenticated
    """
    user = g.current_user
    credentials = WebAuthnService.get_user_credentials(user)
    
    return api_response(
        data={
            "credentials": [cred.to_webauthn_dict() for cred in credentials],
            "count": len(credentials),
        },
        message="Credentials retrieved successfully",
    )


@api_v1_bp.route("/auth/webauthn/credentials/<credential_id>", methods=["DELETE"])
@login_required
def delete_webauthn_credential(credential_id):
    """
    Delete a WebAuthn passkey credential.
    
    Args:
        credential_id: ID of the credential to delete
    
    Returns:
        200: Credential deleted successfully
        401: Not authenticated
        404: Credential not found
    """
    user = g.current_user
    
    # First check that the specific credential actually belongs to this user.
    # Only then check whether it is the last one — otherwise a user with zero
    # credentials gets a misleading "Cannot delete the last passkey" error
    # instead of a 404.
    credential_exists = WebAuthnService.credential_belongs_to_user(credential_id, user)
    if not credential_exists:
        return api_response(
            success=False,
            message="Credential not found",
            status=404,
            error_type="NOT_FOUND",
        )

    # Check if this is the last credential
    credential_count = user.get_webauthn_credential_count()
    if credential_count <= 1:
        return api_response(
            success=False,
            message="Cannot delete the last passkey. Add another passkey first.",
            status=400,
            error_type="BAD_REQUEST",
        )
    
    # Delete the credential
    success = WebAuthnService.delete_credential(credential_id, user)
    
    if not success:
        return api_response(
            success=False,
            message="Credential not found",
            status=404,
            error_type="NOT_FOUND",
        )
    
    return api_response(
        message="Passkey deleted successfully",
    )


@api_v1_bp.route("/auth/webauthn/credentials/<credential_id>", methods=["PATCH"])
@login_required
def rename_webauthn_credential(credential_id):
    """
    Rename a WebAuthn passkey credential.
    
    Args:
        credential_id: ID of the credential to rename
    
    Request body:
        name: New name for the credential
    
    Returns:
        200: Credential renamed successfully
        400: Validation error
        401: Not authenticated
        404: Credential not found
    """
    try:
        # Validate request data
        schema = WebAuthnCredentialRenameSchema()
        data = schema.load(request.json)
        
        # Rename the credential
        success = WebAuthnService.rename_credential(
            credential_id,
            g.current_user,
            data["name"]
        )
        
        if not success:
            return api_response(
                success=False,
                message="Credential not found",
                status=404,
                error_type="NOT_FOUND",
            )
        
        # Get updated credential
        credential = WebAuthnService.get_credential_by_id(credential_id, g.current_user)
        
        return api_response(
            data={
                "credential": credential.to_webauthn_dict() if credential else None,
            },
            message="Passkey renamed successfully",
        )
        
    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )


@api_v1_bp.route("/auth/webauthn/status", methods=["GET"])
@login_required
def get_webauthn_status():
    """
    Get WebAuthn status for the current user.
    
    Returns:
        200: WebAuthn status with webauthn_enabled and credential_count
        401: Not authenticated
    """
    user = g.current_user
    
    return api_response(
        data={
            "webauthn_enabled": user.has_webauthn_enabled(),
            "credential_count": user.get_webauthn_credential_count(),
        },
        message="WebAuthn status retrieved successfully",
    )


_pw_logger = logging.getLogger(__name__)


@api_v1_bp.route("/auth/forgot-password", methods=["POST"])
@limiter.limit(lambda: current_app.config["RATELIMIT_AUTH_FORGOT_PASSWORD"])
def forgot_password():
    """Request a password reset email.

    Always returns 200 to avoid leaking account existence.

    Request body:
        email: User email address

    Returns:
        200: Password reset email sent (or silently no-op if email not found)
    """
    from gatehouse_app.models import User, PasswordResetToken

    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()

    if not email:
        return api_response(
            success=False,
            message="Email is required",
            status=400,
            error_type="VALIDATION_ERROR",
        )

    # Always return 200 — don't leak whether the email exists
    user = User.query.filter_by(email=email, deleted_at=None).first()
    if user:
        try:
            reset_token = PasswordResetToken.generate(user_id=user.id)
            app_url = current_app.config.get("APP_URL", "http://localhost:8080")
            reset_link = f"{app_url}/reset-password?token={reset_token.token}"
            subject = "Reset your Gatehouse password"
            body = (
                f"Hi {user.full_name or user.email},\n\n"
                f"You requested a password reset for your Gatehouse account.\n\n"
                f"Click the link below to reset your password (valid for 2 hours):\n"
                f"{reset_link}\n\n"
                f"If you did not request this, you can safely ignore this email.\n\n"
                f"Gatehouse Security Team"
            )
            NotificationService._send_email(
                to_address=user.email,
                subject=subject,
                body=body,
            )
            _pw_logger.info(f"Password reset token generated for user {user.id}")
        except Exception as exc:
            _pw_logger.exception(f"Error generating password reset token: {exc}")

    return api_response(
        data={},
        message="If an account exists for this email, you will receive a password reset link shortly.",
    )


@api_v1_bp.route("/auth/reset-password", methods=["POST"])
@limiter.limit(lambda: current_app.config["RATELIMIT_AUTH_RESET_PASSWORD"])
def reset_password():
    """Reset a user's password using a reset token.

    Request body:
        token: Password reset token from email
        password: New password
        password_confirm: Password confirmation

    Returns:
        200: Password reset successfully
        400: Invalid or expired token / validation error
    """
    import bcrypt as _bcrypt
    from gatehouse_app.extensions import bcrypt
    from gatehouse_app.models import PasswordResetToken, AuthenticationMethod
    from gatehouse_app.utils.constants import AuthMethodType

    data = request.get_json() or {}
    token_value = (data.get("token") or "").strip()
    new_password = data.get("password") or ""
    password_confirm = data.get("password_confirm") or ""

    if not token_value or not new_password:
        return api_response(
            success=False,
            message="Token and new password are required",
            status=400,
            error_type="VALIDATION_ERROR",
        )

    if new_password != password_confirm:
        return api_response(
            success=False,
            message="Passwords do not match",
            status=400,
            error_type="VALIDATION_ERROR",
        )

    if len(new_password) < 8:
        return api_response(
            success=False,
            message="Password must be at least 8 characters",
            status=400,
            error_type="VALIDATION_ERROR",
        )

    reset_token = PasswordResetToken.query.filter_by(token=token_value).first()
    if not reset_token or not reset_token.is_valid:
        return api_response(
            success=False,
            message="This password reset link is invalid or has expired.",
            status=400,
            error_type="INVALID_TOKEN",
        )

    try:
        user = reset_token.user
        # Update the password hash on the authentication method
        auth_method = AuthenticationMethod.query.filter_by(
            user_id=user.id,
            method_type=AuthMethodType.PASSWORD,
            deleted_at=None,
        ).first()
        if auth_method:
            auth_method.password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
            from gatehouse_app.extensions import db
            db.session.add(auth_method)

        reset_token.consume()
        _pw_logger.info(f"Password reset for user {user.id}")

        return api_response(
            data={},
            message="Your password has been reset. You can now sign in with your new password.",
        )
    except Exception as exc:
        _pw_logger.exception(f"Error resetting password: {exc}")
        return api_response(
            success=False,
            message="An error occurred while resetting your password.",
            status=500,
            error_type="INTERNAL_ERROR",
        )


@api_v1_bp.route("/auth/verify-email", methods=["POST"])
def verify_email():
    """Verify a user's email address using a verification token.

    Request body:
        token: Email verification token

    Returns:
        200: Email verified successfully
        400: Invalid or expired token
    """
    from gatehouse_app.models import EmailVerificationToken

    data = request.get_json() or {}
    token_value = (data.get("token") or "").strip()

    if not token_value:
        return api_response(
            success=False,
            message="Verification token is required",
            status=400,
            error_type="VALIDATION_ERROR",
        )

    verify_token = EmailVerificationToken.query.filter_by(token=token_value).first()
    if not verify_token or not verify_token.is_valid:
        return api_response(
            success=False,
            message="This verification link is invalid or has expired.",
            status=400,
            error_type="INVALID_TOKEN",
        )

    try:
        user = verify_token.user
        user.email_verified = True
        from gatehouse_app.extensions import db
        db.session.add(user)
        verify_token.consume()
        _pw_logger.info(f"Email verified for user {user.id}")

        return api_response(
            data={},
            message="Your email has been verified. You can now sign in.",
        )
    except Exception as exc:
        _pw_logger.exception(f"Error verifying email: {exc}")
        return api_response(
            success=False,
            message="An error occurred while verifying your email.",
            status=500,
            error_type="INTERNAL_ERROR",
        )


@api_v1_bp.route("/auth/resend-verification", methods=["POST"])
def resend_verification():
    """Resend email verification link.

    Always returns 200 to avoid leaking account existence.

    Request body:
        email: User email address

    Returns:
        200: Verification email sent (or silently no-op)
    """
    from gatehouse_app.models import User, EmailVerificationToken

    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()

    if not email:
        return api_response(
            success=False,
            message="Email is required",
            status=400,
            error_type="VALIDATION_ERROR",
        )

    user = User.query.filter_by(email=email, deleted_at=None).first()
    if user and not user.email_verified:
        try:
            verify_token = EmailVerificationToken.generate(user_id=user.id)
            app_url = current_app.config.get("APP_URL", "http://localhost:8080")
            verify_link = f"{app_url}/verify-email?token={verify_token.token}"
            subject = "Verify your Gatehouse email address"
            body = (
                f"Hi {user.full_name or user.email},\n\n"
                f"Please verify your email address by clicking the link below (valid for 24 hours):\n"
                f"{verify_link}\n\n"
                f"Gatehouse Security Team"
            )
            NotificationService._send_email(
                to_address=user.email,
                subject=subject,
                body=body,
            )
            _pw_logger.info(f"Verification email sent for user {user.id}")
        except Exception as exc:
            _pw_logger.exception(f"Error sending verification email: {exc}")

    return api_response(
        data={},
        message="If an account exists for this email and is not yet verified, you will receive a verification link shortly.",
    )


# =============================================================================
# Account Activation (separate from email-verification)
# =============================================================================

@api_v1_bp.route("/auth/activate", methods=["POST"])
def activate_account():
    """Activate a user account via a one-time activation code.

    Request body:
        code  – the activation_key from the welcome email

    Returns:
        200: Account activated, session token returned
        400: Missing code
        404: Invalid or already-used code
    """
    import secrets
    from gatehouse_app.models.user.user import User
    from gatehouse_app.extensions import db

    data = request.get_json() or {}
    code = (data.get("code") or "").strip()
    if not code:
        return api_response(success=False, message="Activation code is required", status=400, error_type="VALIDATION_ERROR")

    user = User.query.filter_by(activation_key=code, deleted_at=None).first()
    if not user:
        return api_response(success=False, message="Invalid or expired activation code", status=404, error_type="NOT_FOUND")

    user.activated = True
    user.activation_key = None  # one-time use
    db.session.add(user)
    db.session.commit()

    user_session = AuthService.create_session(user)
    _pw_logger.info(f"Account activated for user {user.id}")

    return api_response(
        data={
            "user": user.to_dict(),
            "token": user_session.token,
            "expires_at": user_session.expires_at.isoformat() + "Z"
            if user_session.expires_at.isoformat()[-1] != "Z"
            else user_session.expires_at.isoformat(),
        },
        message="Account activated successfully",
    )


@api_v1_bp.route("/auth/resend-activation", methods=["POST"])
def resend_activation():
    """Re-send an account activation email.

    Always returns 200 to avoid leaking whether an account exists.

    Request body:
        email – user email address
    """
    import secrets
    from gatehouse_app.models.user.user import User
    from gatehouse_app.extensions import db

    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return api_response(success=False, message="Email is required", status=400, error_type="VALIDATION_ERROR")

    user = User.query.filter_by(email=email, deleted_at=None).first()
    if user and not user.activated:
        try:
            code = secrets.token_urlsafe(32)
            user.activation_key = code
            db.session.add(user)
            db.session.commit()

            app_url = current_app.config.get("APP_URL", current_app.config.get("FRONTEND_URL", "http://localhost:8080"))
            activate_link = f"{app_url}/activate?code={code}"
            subject = "Activate your Gatehouse account"
            body = (
                f"Hi {user.full_name or user.email},\n\n"
                f"Please activate your Gatehouse account by clicking the link below:\n"
                f"{activate_link}\n\n"
                f"If you did not create an account, you can safely ignore this email.\n\n"
                f"Gatehouse Security Team"
            )
            NotificationService._send_email(to_address=user.email, subject=subject, body=body)
            _pw_logger.info(f"Activation email re-sent to {user.id}")
        except Exception as exc:
            _pw_logger.exception(f"Error re-sending activation email: {exc}")

    return api_response(
        data={},
        message="If an unactivated account exists for this email, you will receive a new activation link shortly.",
    )


# =============================================================================
# Token retrieval / redirect (for CLI / external tools)
# =============================================================================

@api_v1_bp.route("/auth/token", methods=["GET"])
@login_required
def get_token():
    """Return the current session token, optionally redirecting to a URL.

    Query parameters:
        redirect  – optional URL to redirect to with the token appended as
                    a query param: ``<redirect>?token=<token>``

    Returns:
        200: JSON ``{"token": "<token>"}``  (no redirect given)
        302: Redirect to ``<redirect>?token=<token>``
    """
    from flask import redirect as flask_redirect
    from urllib.parse import urlparse

    token = g.current_session.token
    redirect_url = request.args.get("redirect", "").strip()

    if redirect_url:
        # Validate redirect URL against allowed origins to prevent open-redirect
        # token exfiltration attacks (CWE-601).
        allowed_origins = set(current_app.config.get("CORS_ORIGINS", []))
        frontend_url = current_app.config.get("FRONTEND_URL", "")
        if frontend_url:
            parsed = urlparse(frontend_url)
            allowed_origins.add(f"{parsed.scheme}://{parsed.netloc}")

        parsed_redirect = urlparse(redirect_url)
        redirect_origin = f"{parsed_redirect.scheme}://{parsed_redirect.netloc}"

        if redirect_origin not in allowed_origins:
            return api_response(
                success=False,
                message="Redirect URL is not allowed.",
                status=400,
                error_type="INVALID_REDIRECT",
            )

        sep = "&" if "?" in redirect_url else "?"
        return flask_redirect(f"{redirect_url}{sep}token={token}", code=302)

    return api_response(data={"token": token}, message="Token retrieved")
