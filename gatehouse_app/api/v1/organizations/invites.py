"""Organization invite token endpoints."""
import logging
from flask import g, request, current_app
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.utils.decorators import login_required, require_admin
from gatehouse_app.services.notification_service import NotificationService
from gatehouse_app.services.auth_service import AuthService
from gatehouse_app.services.organization_service import OrganizationService
from gatehouse_app.utils.constants import OrganizationRole


@api_v1_bp.route("/organizations/<org_id>/invites", methods=["POST"])
@login_required
@require_admin
def create_org_invite(org_id):
    from gatehouse_app.models import OrgInviteToken, Organization

    org = Organization.query.filter_by(id=org_id, deleted_at=None).first()
    if not org:
        return api_response(success=False, message="Organization not found", status=404)

    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    role = (data.get("role") or "member").strip()

    if not email:
        return api_response(success=False, message="Email is required", status=400, error_type="VALIDATION_ERROR")

    invite = OrgInviteToken.generate(
        organization_id=org_id,
        email=email,
        role=role,
        invited_by_id=g.current_user.id,
    )

    app_url = current_app.config.get("APP_URL", "http://localhost:8080")
    invite_link = f"{app_url}/invite?token={invite.token}"

    email_sent = NotificationService._send_email(
        to_address=email,
        subject=f"You're invited to join {org.name} on Gatehouse",
        body=(
            f"You've been invited to join {org.name} on Gatehouse.\n\n"
            f"Click the link below to accept the invitation (valid for 7 days):\n"
            f"{invite_link}\n\n"
            f"Gatehouse Security Team"
        ),
    )

    if not email_sent:
        logging.getLogger(__name__).warning(
            f"[INVITE LINK] Email not sent (EMAIL_ENABLED=False or SMTP down). "
            f"Invite for {email} → {invite_link}"
        )
    else:
        logging.getLogger(__name__).info(
            f"[INVITE] Email sent successfully to {email}"
        )

    response_data = {
        "invite": {
            "id": invite.id,
            "email": invite.email,
            "role": invite.role,
            "expires_at": invite.expires_at.isoformat() + "Z",
            # Only include invite_link when email delivery failed — signals frontend to show copy dialog
            **({"invite_link": invite_link} if not email_sent else {}),
        }
    }

    return api_response(
        data=response_data,
        message="Invite sent successfully",
        status=201,
    )


@api_v1_bp.route("/organizations/<org_id>/invites", methods=["GET"])
@login_required
@require_admin
def list_org_invites(org_id):
    from gatehouse_app.models import OrgInviteToken, Organization

    org = Organization.query.filter_by(id=org_id, deleted_at=None).first()
    if not org:
        return api_response(success=False, message="Organization not found", status=404)

    invites = (
        OrgInviteToken.query.filter_by(organization_id=org_id)
        .filter(OrgInviteToken.accepted_at == None)
        .filter(OrgInviteToken.deleted_at == None)
        .all()
    )

    def invite_to_dict(inv):
        return {
            "id": inv.id,
            "email": inv.email,
            "role": inv.role,
            "invited_by_id": inv.invited_by_id,
            "expires_at": inv.expires_at.isoformat() + "Z",
            "token": inv.token,
        }

    return api_response(
        data={"invites": [invite_to_dict(i) for i in invites]},
        message="Invites retrieved",
    )


@api_v1_bp.route("/organizations/<org_id>/invites/<invite_id>", methods=["DELETE"])
@login_required
@require_admin
def cancel_org_invite(org_id, invite_id):
    from gatehouse_app.models import OrgInviteToken, Organization

    org = Organization.query.filter_by(id=org_id, deleted_at=None).first()
    if not org:
        return api_response(success=False, message="Organization not found", status=404)

    invite = OrgInviteToken.query.filter_by(id=invite_id, organization_id=org_id, deleted_at=None).first()
    if not invite:
        return api_response(success=False, message="Invite not found", status=404)

    invite.delete(soft=True)
    return api_response(data={}, message="Invite cancelled")


@api_v1_bp.route("/invites/<token>", methods=["GET"])
def get_invite(token):
    from gatehouse_app.models import OrgInviteToken, User

    invite = OrgInviteToken.query.filter_by(token=token).first()
    if not invite or not invite.is_valid:
        return api_response(success=False, message="This invitation link is invalid or has expired.", status=400, error_type="INVALID_TOKEN")

    user_exists = User.query.filter_by(email=invite.email, deleted_at=None).first() is not None

    return api_response(
        data={
            "email": invite.email,
            "organization": {"id": invite.organization_id, "name": invite.organization.name},
            "role": invite.role,
            "user_exists": user_exists,
        },
        message="Invite found",
    )


@api_v1_bp.route("/invites/<token>/accept", methods=["POST"])
def accept_invite(token):
    """Accept an organization invite.

    """
    from gatehouse_app.models import OrgInviteToken, User
    from gatehouse_app.services.session_service import SessionService

    invite = OrgInviteToken.query.filter_by(token=token).first()
    if not invite or not invite.is_valid:
        return api_response(success=False, message="This invitation link is invalid or has expired.", status=400, error_type="INVALID_TOKEN")

    # --- Resolve the user -----------------------------------------------
    # If the request carries a valid session token the user is already
    # authenticated (e.g. via Google OAuth).  Use that identity and skip
    # any password / registration logic entirely.
    user = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        bearer_token = auth_header.split(None, 1)[1].strip()
        session = SessionService.get_active_session_by_token(bearer_token)
        if session and session.is_active():
            session_user = session.user
            # Verify the authenticated user's email matches the invite
            if session_user.email.lower() != invite.email.lower():
                return api_response(
                    success=False,
                    message="This invite was sent to a different email address.",
                    status=403,
                    error_type="EMAIL_MISMATCH",
                )
            user = session_user

    data = request.get_json() or {}
    full_name = data.get("full_name") or ""
    password = data.get("password") or ""
    password_confirm = data.get("password_confirm") or ""

    if user is None:
        # Fall back to email lookup (existing account created by any method)
        user = User.query.filter(
            User.email.ilike(invite.email),
            User.deleted_at.is_(None),
        ).first()

    if not user:
        # Brand-new account — password registration required
        if not password:
            return api_response(success=False, message="Password is required for new accounts.", status=400, error_type="VALIDATION_ERROR")
        if password != password_confirm:
            return api_response(success=False, message="Passwords do not match.", status=400, error_type="VALIDATION_ERROR")
        if len(password) < 8:
            return api_response(success=False, message="Password must be at least 8 characters.", status=400, error_type="VALIDATION_ERROR")
        try:
            user = AuthService.register_user(email=invite.email, password=password, full_name=full_name or None)
        except Exception as exc:
            return api_response(success=False, message=str(exc), status=400, error_type="REGISTRATION_ERROR")

    # Add to org
    try:
        org_role = OrganizationRole(invite.role)
    except ValueError:
        org_role = OrganizationRole.MEMBER

    try:
        OrganizationService.add_member(
            org=invite.organization,
            user_id=user.id,
            role=org_role,
            inviter_id=invite.invited_by_id,
        )
    except Exception:
        from gatehouse_app.extensions import db
        db.session.rollback()
        return api_response(
            success=False,
            message="Failed to add you to the organization. You may already be a member.",
            status=409,
            error_type="CONFLICT",
        )

    invite.accept()

    has_webauthn = user.has_webauthn_enabled()
    has_totp = user.has_totp_enabled()

    if has_webauthn:
        from flask import session as flask_session
        flask_session["webauthn_pending_user_id"] = user.id
        return api_response(data={"requires_webauthn": True}, message="Passkey verification required. Please use your passkey to complete sign-in.")

    if has_totp:
        from flask import session as flask_session
        flask_session["totp_pending_user_id"] = user.id
        return api_response(data={"requires_totp": True}, message="TOTP code required. Please enter your 6-digit code from your authenticator app.")

    user_session = AuthService.create_session(user)

    return api_response(
        data={
            "user": user.to_dict(),
            "token": user_session.token,
            "expires_at": user_session.expires_at.isoformat() + "Z",
        },
        message="Invitation accepted. Welcome!",
    )
