"""Core auth endpoints: register, login, logout, sessions."""
import logging
from flask import request, session, g, current_app
from marshmallow import ValidationError
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.extensions import limiter
from gatehouse_app.utils.response import api_response
from gatehouse_app.schemas.auth_schema import RegisterSchema, LoginSchema
from gatehouse_app.services.auth_service import AuthService
from gatehouse_app.services.mfa_policy_service import MfaPolicyService
from gatehouse_app.services.notification_service import NotificationService
from gatehouse_app.utils.decorators import login_required
from gatehouse_app.utils.constants import AuditAction
from gatehouse_app.exceptions.auth_exceptions import InvalidCredentialsError


@api_v1_bp.route("/auth/register", methods=["POST"])
@limiter.limit(lambda: current_app.config["RATELIMIT_AUTH_REGISTER"])
def register():
    try:
        schema = RegisterSchema()
        data = schema.load(request.json)

        user = AuthService.register_user(
            email=data["email"],
            password=data["password"],
            full_name=data.get("full_name"),
        )

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

        user_session = AuthService.create_session(user)

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
                        "organization": {"id": str(inv.organization_id), "name": inv.organization.name},
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
        return api_response(success=False, message="Validation failed", status=400, error_type="VALIDATION_ERROR", error_details=e.messages)


@api_v1_bp.route("/auth/login", methods=["POST"])
@limiter.limit(lambda: current_app.config["RATELIMIT_AUTH_LOGIN"])
def login():
    logger = logging.getLogger(__name__)

    try:
        schema = LoginSchema()
        data = schema.load(request.json)

        user = AuthService.authenticate(email=data["email"], password=data["password"])

        has_totp = user.has_totp_enabled()
        has_webauthn = user.has_webauthn_enabled()
        logger.info(f"Login attempt for user {user.email} - TOTP enabled: {has_totp}, WebAuthn enabled: {has_webauthn}")

        if has_webauthn:
            session["webauthn_pending_user_id"] = user.id
            return api_response(data={"requires_webauthn": True}, message="Passkey verification required. Please use your passkey to complete login.")

        if has_totp:
            session["totp_pending_user_id"] = user.id
            return api_response(data={"requires_totp": True}, message="TOTP code required. Please enter your 6-digit code from your authenticator app.")

        remember_me = data.get("remember_me", False)
        policy_result = MfaPolicyService.after_primary_auth_success(user, remember_me)
        duration = 2592000 if remember_me else 86400
        is_compliance_only = policy_result.create_compliance_only_session

        user_session = AuthService.create_session(user, duration_seconds=duration, is_compliance_only=is_compliance_only)

        response_data = {
            "user": user.to_dict(),
            "token": user_session.token,
            "expires_at": user_session.expires_at.isoformat() + "Z" if user_session.expires_at.isoformat()[-1] != "Z" else user_session.expires_at.isoformat(),
        }

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

        if is_compliance_only:
            response_data["requires_mfa_enrollment"] = True

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
                    "organization": {"id": str(inv.organization_id), "name": inv.organization.name},
                    "role": inv.role,
                    "expires_at": inv.expires_at.isoformat(),
                }
                for inv in pending_invites
            ]
            response_data["requires_org_setup"] = True

        return api_response(data=response_data, message="Login successful")
    except ValidationError as e:
        return api_response(success=False, message="Validation failed", status=400, error_type="VALIDATION_ERROR", error_details=e.messages)


@api_v1_bp.route("/auth/logout", methods=["POST"])
@login_required
def logout():
    if g.current_session:
        AuthService.revoke_session(g.current_session.id, reason="User logout")
    return api_response(message="Logout successful")


@api_v1_bp.route("/auth/me", methods=["GET"])
@login_required
def get_current_user():
    user = g.current_user
    return api_response(
        data={
            "user": user.to_dict(),
            "organizations": [
                {
                    "id": membership.organization.id,
                    "name": membership.organization.name,
                    "slug": membership.organization.slug,
                    "role": membership.role.value if hasattr(membership.role, "value") else str(membership.role),
                }
                for membership in user.organization_memberships
                if membership.deleted_at is None and membership.organization and not membership.organization.deleted_at
            ],
        },
        message="User retrieved successfully",
    )


@api_v1_bp.route("/auth/sessions", methods=["GET"])
@login_required
def get_user_sessions():
    from gatehouse_app.services.session_service import SessionService

    sessions = SessionService.get_user_sessions(g.current_user.id, active_only=True)
    return api_response(data={"sessions": [s.to_dict() for s in sessions], "count": len(sessions)}, message="Sessions retrieved successfully")


@api_v1_bp.route("/auth/sessions/<session_id>", methods=["DELETE"])
@login_required
def revoke_session(session_id):
    from gatehouse_app.models.user.session import Session

    user_session = Session.query.filter_by(id=session_id, user_id=g.current_user.id, deleted_at=None).first()
    if not user_session:
        return api_response(success=False, message="Session not found", status=404, error_type="NOT_FOUND")

    AuthService.revoke_session(session_id, reason="Revoked by user")
    return api_response(message="Session revoked successfully")


@api_v1_bp.route("/auth/token", methods=["GET"])
@login_required
def get_token():
    from flask import redirect as flask_redirect
    from urllib.parse import urlparse

    token = g.current_session.token
    redirect_url = request.args.get("redirect", "").strip()

    if redirect_url:
        allowed_origins = set(current_app.config.get("CORS_ORIGINS", []))
        frontend_url = current_app.config.get("FRONTEND_URL", "")
        if frontend_url:
            parsed = urlparse(frontend_url)
            allowed_origins.add(f"{parsed.scheme}://{parsed.netloc}")

        parsed_redirect = urlparse(redirect_url)
        redirect_origin = f"{parsed_redirect.scheme}://{parsed_redirect.netloc}"

        if redirect_origin not in allowed_origins:
            return api_response(success=False, message="Redirect URL is not allowed.", status=400, error_type="INVALID_REDIRECT")

        sep = "&" if "?" in redirect_url else "?"
        return flask_redirect(f"{redirect_url}{sep}token={token}", code=302)

    return api_response(data={"token": token}, message="Token retrieved")
