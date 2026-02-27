"""Organization endpoints."""
from flask import g, request
from marshmallow import ValidationError
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.utils.decorators import login_required, require_admin, require_owner, full_access_required
from gatehouse_app.schemas.organization_schema import (
    OrganizationCreateSchema,
    OrganizationUpdateSchema,
    InviteMemberSchema,
    UpdateMemberRoleSchema,
)
from gatehouse_app.services.organization_service import OrganizationService
from gatehouse_app.services.user_service import UserService
from gatehouse_app.utils.constants import OrganizationRole
@api_v1_bp.route("/organizations", methods=["POST"])
@login_required
@full_access_required
def create_organization():
    """
    Create a new organization.

    Request body:
        name: Organization name
        slug: Organization slug (unique)
        description: Optional description
        logo_url: Optional logo URL

    Returns:
        201: Organization created successfully
        400: Validation error
        401: Not authenticated
        409: Slug already exists
    """
    try:
        # Validate request data
        schema = OrganizationCreateSchema()
        data = schema.load(request.json)

        # Create organization
        org = OrganizationService.create_organization(
            name=data["name"],
            slug=data["slug"],
            owner_user_id=g.current_user.id,
            description=data.get("description"),
            logo_url=data.get("logo_url"),
        )

        return api_response(
            data={"organization": org.to_dict()},
            message="Organization created successfully",
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


@api_v1_bp.route("/organizations/<org_id>", methods=["GET"])
@login_required
@full_access_required
def get_organization(org_id):
    """
    Get organization by ID.

    Args:
        org_id: Organization ID

    Returns:
        200: Organization data
        401: Not authenticated
        403: Not a member
        404: Organization not found
    """
    org = OrganizationService.get_organization_by_id(org_id)

    # Check if user is a member
    if not org.is_member(g.current_user.id):
        return api_response(
            success=False,
            message="You are not a member of this organization",
            status=403,
            error_type="AUTHORIZATION_ERROR",
        )

    return api_response(
        data={
            "organization": org.to_dict(),
            "member_count": org.get_member_count(),
        },
        message="Organization retrieved successfully",
    )


@api_v1_bp.route("/organizations/<org_id>", methods=["PATCH"])
@login_required
@require_admin
@full_access_required
def update_organization(org_id):
    """
    Update organization.

    Args:
        org_id: Organization ID

    Request body:
        name: Optional organization name
        description: Optional description
        logo_url: Optional logo URL

    Returns:
        200: Organization updated successfully
        400: Validation error
        401: Not authenticated
        403: Not an admin
        404: Organization not found
    """
    try:
        # Validate request data
        schema = OrganizationUpdateSchema()
        data = schema.load(request.json)

        org = OrganizationService.get_organization_by_id(org_id)

        # Update organization
        org = OrganizationService.update_organization(
            org=org,
            user_id=g.current_user.id,
            **data
        )

        return api_response(
            data={"organization": org.to_dict()},
            message="Organization updated successfully",
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )


@api_v1_bp.route("/organizations/<org_id>", methods=["DELETE"])
@login_required
@require_owner
@full_access_required
def delete_organization(org_id):
    """
    Delete organization (soft delete).

    Args:
        org_id: Organization ID

    Returns:
        200: Organization deleted successfully
        401: Not authenticated
        403: Not the owner
        404: Organization not found
    """
    org = OrganizationService.get_organization_by_id(org_id)

    OrganizationService.delete_organization(
        org=org,
        user_id=g.current_user.id,
        soft=True,
    )

    return api_response(
        message="Organization deleted successfully",
    )


@api_v1_bp.route("/organizations/<org_id>/members", methods=["GET"])
@login_required
@full_access_required
def get_organization_members(org_id):
    """
    Get all members of an organization.

    Args:
        org_id: Organization ID

    Returns:
        200: List of members
        401: Not authenticated
        403: Not a member
        404: Organization not found
    """
    org = OrganizationService.get_organization_by_id(org_id)

    # Check if user is a member
    if not org.is_member(g.current_user.id):
        return api_response(
            success=False,
            message="You are not a member of this organization",
            status=403,
            error_type="AUTHORIZATION_ERROR",
        )

    members_data = []
    for member in org.members:
        if member.deleted_at is None:
            member_dict = member.to_dict()
            member_dict["user"] = member.user.to_dict()
            members_data.append(member_dict)

    return api_response(
        data={
            "members": members_data,
            "count": len(members_data),
        },
        message="Members retrieved successfully",
    )


@api_v1_bp.route("/organizations/<org_id>/members", methods=["POST"])
@login_required
@require_admin
@full_access_required
def add_organization_member(org_id):
    """
    Add a member to the organization.

    Args:
        org_id: Organization ID

    Request body:
        email: User email to invite
        role: Member role (owner, admin, member, guest)

    Returns:
        201: Member added successfully
        400: Validation error
        401: Not authenticated
        403: Not an admin
        404: Organization or user not found
        409: User already a member
    """
    try:
        # Validate request data
        schema = InviteMemberSchema()
        data = schema.load(request.json)

        org = OrganizationService.get_organization_by_id(org_id)

        # Find user by email
        user = UserService.get_user_by_email(data["email"])
        if not user:
            return api_response(
                success=False,
                message="User not found",
                status=404,
                error_type="NOT_FOUND",
            )

        # Add member
        role = OrganizationRole(data["role"])
        member = OrganizationService.add_member(
            org=org,
            user_id=user.id,
            role=role,
            inviter_id=g.current_user.id,
        )

        member_dict = member.to_dict()
        member_dict["user"] = user.to_dict()

        return api_response(
            data={"member": member_dict},
            message="Member added successfully",
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


@api_v1_bp.route("/organizations/<org_id>/members/<user_id>", methods=["DELETE"])
@login_required
@require_admin
@full_access_required
def remove_organization_member(org_id, user_id):
    """
    Remove a member from the organization.

    Args:
        org_id: Organization ID
        user_id: User ID to remove

    Returns:
        200: Member removed successfully
        401: Not authenticated
        403: Not an admin
        404: Organization or member not found
    """
    org = OrganizationService.get_organization_by_id(org_id)

    OrganizationService.remove_member(
        org=org,
        user_id=user_id,
        remover_id=g.current_user.id,
    )

    return api_response(
        message="Member removed successfully",
    )


@api_v1_bp.route("/organizations/<org_id>/members/<user_id>/role", methods=["PATCH"])
@login_required
@require_admin
@full_access_required
def update_member_role(org_id, user_id):
    """
    Update a member's role.

    Args:
        org_id: Organization ID
        user_id: User ID

    Request body:
        role: New role (owner, admin, member, guest)

    Returns:
        200: Role updated successfully
        400: Validation error
        401: Not authenticated
        403: Not an admin
        404: Organization or member not found
    """
    try:
        # Validate request data
        schema = UpdateMemberRoleSchema()
        data = schema.load(request.json)

        org = OrganizationService.get_organization_by_id(org_id)

        # Update role
        new_role = OrganizationRole(data["role"])
        member = OrganizationService.update_member_role(
            org=org,
            user_id=user_id,
            new_role=new_role,
            updater_id=g.current_user.id,
        )

        member_dict = member.to_dict()
        member_dict["user"] = member.user.to_dict()

        return api_response(
            data={"member": member_dict},
            message="Member role updated successfully",
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )


@api_v1_bp.route("/organizations/<org_id>/audit-logs", methods=["GET"])
@login_required
@full_access_required
def get_organization_audit_logs(org_id):
    """
    Get audit logs for an organization.

    Query params:
        page: Page number (default 1)
        per_page: Results per page (default 50, max 200)
        action: Filter by action type

    Returns:
        200: List of audit log entries
        401: Not authenticated
        403: Not a member / insufficient permissions
        404: Organization not found
    """
    from gatehouse_app.models.audit_log import AuditLog

    # Ensure org exists and user is a member (full_access_required handles this)
    OrganizationService.get_organization_by_id(org_id)

    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 50)), 200)
    action_filter = request.args.get("action")

    query = AuditLog.query.filter_by(organization_id=org_id)
    if action_filter:
        query = query.filter_by(action=action_filter)

    query = query.order_by(AuditLog.created_at.desc())
    total = query.count()
    logs = query.offset((page - 1) * per_page).limit(per_page).all()

    def log_to_dict(log):
        return {
            "id": log.id,
            "action": log.action.value if log.action else None,
            "user_id": log.user_id,
            "user_email": log.user.email if log.user else None,
            "user": {"id": log.user.id, "email": log.user.email, "full_name": log.user.full_name} if log.user else None,
            "organization_id": log.organization_id,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "request_id": log.request_id,
            "description": log.description,
            "success": log.success,
            "error_message": log.error_message,
            "metadata": log.extra_data,
            "created_at": log.created_at.isoformat() if log.created_at else None,
            "updated_at": log.updated_at.isoformat() if log.updated_at else None,
        }

    return api_response(
        data={
            "audit_logs": [log_to_dict(log) for log in logs],
            "count": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
        },
        message="Audit logs retrieved successfully",
    )


# ============================================================================
# Organization Invite Tokens
# ============================================================================

@api_v1_bp.route("/organizations/<org_id>/invites", methods=["POST"])
@login_required
@require_admin
def create_org_invite(org_id):
    """Create an invite token for an organization.

    Request body:
        email: Email address to invite
        role: Role to assign (default: member)

    Returns:
        201: Invite created
        400: Validation error
        403: Not an admin
        404: Organization not found
    """
    from gatehouse_app.models import OrgInviteToken, Organization
    from gatehouse_app.services.notification_service import NotificationService
    from flask import current_app

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

    NotificationService._send_email(
        to_address=email,
        subject=f"You're invited to join {org.name} on Gatehouse",
        body=(
            f"You've been invited to join {org.name} on Gatehouse.\n\n"
            f"Click the link below to accept the invitation (valid for 7 days):\n"
            f"{invite_link}\n\n"
            f"Gatehouse Security Team"
        ),
    )

    return api_response(
        data={"invite": {"id": invite.id, "email": invite.email, "role": invite.role, "expires_at": invite.expires_at.isoformat() + "Z"}},
        message="Invite sent successfully",
        status=201,
    )


@api_v1_bp.route("/invites/<token>", methods=["GET"])
def get_invite(token):
    """Get invite details by token.

    Returns:
        200: Invite details (org name, email)
        400: Invalid or expired token
    """
    from gatehouse_app.models import OrgInviteToken

    invite = OrgInviteToken.query.filter_by(token=token).first()
    if not invite or not invite.is_valid:
        return api_response(success=False, message="This invitation link is invalid or has expired.", status=400, error_type="INVALID_TOKEN")

    return api_response(
        data={
            "email": invite.email,
            "organization": {"id": invite.organization_id, "name": invite.organization.name},
            "role": invite.role,
        },
        message="Invite found",
    )


@api_v1_bp.route("/invites/<token>/accept", methods=["POST"])
def accept_invite(token):
    """Accept an organization invite.

    Creates the user account (if not already registered) and adds them
    to the organization.

    Request body:
        full_name: User's display name
        password: Password for new account (if not already registered)
        password_confirm: Password confirmation

    Returns:
        200: Invite accepted, returns user token
        400: Invalid/expired token or validation error
        409: Already a member
    """
    from gatehouse_app.models import OrgInviteToken, User
    from gatehouse_app.services.auth_service import AuthService
    from gatehouse_app.services.organization_service import OrganizationService
    from gatehouse_app.utils.constants import OrganizationRole

    invite = OrgInviteToken.query.filter_by(token=token).first()
    if not invite or not invite.is_valid:
        return api_response(success=False, message="This invitation link is invalid or has expired.", status=400, error_type="INVALID_TOKEN")

    data = request.get_json() or {}
    full_name = data.get("full_name") or ""
    password = data.get("password") or ""
    password_confirm = data.get("password_confirm") or ""

    user = User.query.filter_by(email=invite.email, deleted_at=None).first()

    if not user:
        # Register a new user
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
    role_value = invite.role
    try:
        org_role = OrganizationRole(role_value)
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
        pass  # Already a member is fine

    invite.accept()

    user_session = AuthService.create_session(user)

    return api_response(
        data={
            "user": user.to_dict(),
            "token": user_session.token,
            "expires_at": user_session.expires_at.isoformat() + "Z",
        },
        message="Invitation accepted. Welcome!",
    )


# ============================================================================
# Organization OIDC Clients
# ============================================================================

@api_v1_bp.route("/organizations/<org_id>/clients", methods=["GET"])
@login_required
def list_org_clients(org_id):
    """List OIDC clients for an organization.

    Returns:
        200: List of OIDC clients
        403: Not a member
        404: Organization not found
    """
    from gatehouse_app.models import OIDCClient, Organization

    org = Organization.query.filter_by(id=org_id, deleted_at=None).first()
    if not org:
        return api_response(success=False, message="Organization not found", status=404)

    clients = OIDCClient.query.filter_by(organization_id=org_id, is_active=True).all()

    def client_to_dict(c):
        return {
            "id": c.id,
            "name": c.name,
            "client_id": c.client_id,
            "redirect_uris": c.redirect_uris,
            "scopes": c.scopes,
            "grant_types": c.grant_types,
            "is_active": c.is_active,
            "created_at": c.created_at.isoformat() + "Z",
        }

    return api_response(
        data={"clients": [client_to_dict(c) for c in clients], "count": len(clients)},
        message="Clients retrieved successfully",
    )


@api_v1_bp.route("/organizations/<org_id>/clients", methods=["POST"])
@login_required
@require_admin
def create_org_client(org_id):
    """Create a new OIDC client for an organization.

    Request body:
        name: Client name
        redirect_uris: List of allowed redirect URIs (newline or comma separated string)

    Returns:
        201: Client created with client_id and client_secret
        403: Not an admin
        404: Organization not found
    """
    import secrets as _secrets
    from gatehouse_app.extensions import bcrypt
    from gatehouse_app.models import OIDCClient, Organization

    org = Organization.query.filter_by(id=org_id, deleted_at=None).first()
    if not org:
        return api_response(success=False, message="Organization not found", status=404)

    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    redirect_uris_raw = data.get("redirect_uris") or []

    if not name:
        return api_response(success=False, message="Client name is required", status=400, error_type="VALIDATION_ERROR")

    if isinstance(redirect_uris_raw, str):
        redirect_uris = [u.strip() for u in redirect_uris_raw.replace(",", "\n").splitlines() if u.strip()]
    else:
        redirect_uris = [u.strip() for u in redirect_uris_raw if isinstance(u, str) and u.strip()]

    if not redirect_uris:
        return api_response(success=False, message="At least one redirect URI is required", status=400, error_type="VALIDATION_ERROR")

    client_id = _secrets.token_hex(16)
    client_secret = _secrets.token_urlsafe(32)

    client = OIDCClient(
        organization_id=org_id,
        name=name,
        client_id=client_id,
        client_secret_hash=bcrypt.generate_password_hash(client_secret).decode("utf-8"),
        redirect_uris=redirect_uris,
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scopes=["openid", "profile", "email"],
        is_active=True,
        is_confidential=True,
    )
    from gatehouse_app.extensions import db
    db.session.add(client)
    db.session.commit()

    return api_response(
        data={
            "client": {
                "id": client.id,
                "name": client.name,
                "client_id": client.client_id,
                "client_secret": client_secret,  # Only returned once
                "redirect_uris": client.redirect_uris,
                "scopes": client.scopes,
                "created_at": client.created_at.isoformat() + "Z",
            }
        },
        message="OIDC client created successfully",
        status=201,
    )


@api_v1_bp.route("/organizations/<org_id>/clients/<client_id>", methods=["DELETE"])
@login_required
@require_admin
def delete_org_client(org_id, client_id):
    """Deactivate an OIDC client.

    Returns:
        200: Client deactivated
        403: Not an admin
        404: Client not found
    """
    from gatehouse_app.models import OIDCClient
    from gatehouse_app.extensions import db

    client = OIDCClient.query.filter_by(id=client_id, organization_id=org_id).first()
    if not client:
        return api_response(success=False, message="Client not found", status=404)

    client.is_active = False
    db.session.commit()

    return api_response(data={}, message="Client deactivated successfully")


@api_v1_bp.route("/organizations/<org_id>/members/<user_id>/send-mfa-reminder", methods=["POST"])
@login_required
@require_admin
def send_mfa_reminder(org_id, user_id):
    """Send an MFA reminder email to a specific member.

    Returns:
        200: Reminder sent (or silently skipped if no deadline record)
        403: Not an admin
        404: Member not found
    """
    from gatehouse_app.models import User, MfaPolicyCompliance, OrganizationSecurityPolicy
    from gatehouse_app.services.notification_service import NotificationService

    user = User.query.filter_by(id=user_id, deleted_at=None).first()
    if not user:
        return api_response(success=False, message="User not found", status=404)

    compliance = MfaPolicyCompliance.query.filter_by(
        user_id=user_id, organization_id=org_id
    ).first()
    policy = OrganizationSecurityPolicy.query.filter_by(organization_id=org_id).first()

    if compliance and policy and compliance.deadline_at:
        NotificationService.send_mfa_deadline_reminder(user, compliance, policy)
    else:
        # No compliance deadline — send a generic nudge
        NotificationService._send_email(
            to_address=user.email,
            subject="Reminder: Set up multi-factor authentication",
            body=(
                f"Hi {user.full_name or user.email},\n\n"
                "Your organization administrator has asked you to set up "
                "multi-factor authentication (MFA) on your Gatehouse account.\n\n"
                "Please log in and configure MFA as soon as possible.\n\n"
                "Gatehouse Security Team"
            ),
        )

    return api_response(data={}, message="Reminder sent successfully")


# =============================================================================
# System-wide Audit Log (admin view) + User self audit
# =============================================================================

def _audit_log_to_dict(log):
    """Serialize an AuditLog record to a dict."""
    return {
        "id": log.id,
        "action": log.action.value if log.action else None,
        "user_id": log.user_id,
        "user": (
            {"id": log.user.id, "email": log.user.email, "full_name": log.user.full_name}
            if log.user else None
        ),
        "organization_id": log.organization_id,
        "resource_type": log.resource_type,
        "resource_id": log.resource_id,
        "ip_address": log.ip_address,
        "user_agent": log.user_agent,
        "request_id": log.request_id,
        "description": log.description,
        "success": log.success,
        "error_message": log.error_message,
        "metadata": log.extra_data,
        "created_at": log.created_at.isoformat() if log.created_at else None,
        "updated_at": log.updated_at.isoformat() if log.updated_at else None,
    }


@api_v1_bp.route("/audit-logs", methods=["GET"])
@login_required
def get_system_audit_logs():
    """
    Get all audit logs (system-wide). Any authenticated user can query
    their own logs; org owners/admins also see org-scoped logs; this
    endpoint returns ALL logs for users who own at least one org
    (acting as an admin view).

    Query params:
        page          – page number (default 1)
        per_page      – results per page (default 50, max 200)
        action        – filter by AuditAction value
        user_id       – filter by user id
        resource_type – filter by resource type
        success       – "true"/"false"
        q             – free-text search on description
    """
    from gatehouse_app.models.audit_log import AuditLog
    from gatehouse_app.models.organization_member import OrganizationMember

    current_user = g.current_user
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(int(request.args.get("per_page", 50)), 200)

    # Check if the user is an owner of any org to grant admin-level access
    is_admin = OrganizationMember.query.filter_by(
        user_id=current_user.id, role="OWNER"
    ).first() is not None

    query = AuditLog.query

    if not is_admin:
        # Non-admins can only see their own logs
        query = query.filter(AuditLog.user_id == current_user.id)

    # Optional filters
    action_filter = request.args.get("action")
    if action_filter:
        query = query.filter(AuditLog.action == action_filter)

    user_id_filter = request.args.get("user_id")
    if user_id_filter:
        query = query.filter(AuditLog.user_id == user_id_filter)

    resource_type_filter = request.args.get("resource_type")
    if resource_type_filter:
        query = query.filter(AuditLog.resource_type == resource_type_filter)

    success_filter = request.args.get("success")
    if success_filter is not None:
        query = query.filter(AuditLog.success == (success_filter.lower() == "true"))

    q = request.args.get("q", "").strip()
    if q:
        query = query.filter(AuditLog.description.ilike(f"%{q}%"))

    query = query.order_by(AuditLog.created_at.desc())
    total = query.count()
    logs = query.offset((page - 1) * per_page).limit(per_page).all()

    return api_response(
        data={
            "audit_logs": [_audit_log_to_dict(log) for log in logs],
            "count": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
            "is_admin_view": is_admin,
        },
        message="Audit logs retrieved",
    )


@api_v1_bp.route("/auth/audit-logs", methods=["GET"])
@login_required
def get_my_audit_logs():
    """
    Get audit logs for the currently authenticated user only.

    Query params:
        page     – page number (default 1)
        per_page – results per page (default 50, max 200)
        action   – filter by AuditAction value
    """
    from gatehouse_app.models.audit_log import AuditLog

    current_user = g.current_user
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(int(request.args.get("per_page", 50)), 200)

    query = AuditLog.query.filter(AuditLog.user_id == current_user.id)

    action_filter = request.args.get("action")
    if action_filter:
        query = query.filter(AuditLog.action == action_filter)

    query = query.order_by(AuditLog.created_at.desc())
    total = query.count()
    logs = query.offset((page - 1) * per_page).limit(per_page).all()

    return api_response(
        data={
            "audit_logs": [_audit_log_to_dict(log) for log in logs],
            "count": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
        },
        message="Activity retrieved",
    )
