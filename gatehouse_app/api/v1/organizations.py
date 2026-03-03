"""Organization endpoints."""
from flask import g, request, current_app
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
from gatehouse_app.extensions import db



def _get_system_ca_dict():
    """Return a synthetic read-only CA dict for the config-file CA, or None.

    This is injected into the org CA list when no DB CA exists for a given
    ca_type so that the admin UI correctly shows "configured" rather than
    "Not configured" when a system-level CA key is present.

    The returned dict has ``is_system=True`` so the frontend can render it
    as read-only (no delete / edit / generate buttons).
    """
    import os
    try:
        from gatehouse_app.config.ssh_ca_config import get_ssh_ca_config
        from gatehouse_app.utils.crypto import compute_ssh_fingerprint

        # Check env var first (takes priority over file path)
        priv_key = os.environ.get("SSH_CA_PRIVATE_KEY", "").strip()
        pub_key = ""

        if not priv_key:
            cfg = get_ssh_ca_config()
            key_path = cfg.get_str("ca_key_path", "").strip()
            if not key_path:
                return None
            pub_path = key_path + ".pub"
            if not os.path.exists(pub_path):
                return None
            with open(pub_path) as f:
                pub_key = f.read().strip()
        else:
            # Derive the public key from the private key
            from sshkey_tools.keys import PrivateKey
            pk = PrivateKey.from_string(priv_key)
            pub_key = pk.public_key.to_string()

        fingerprint = compute_ssh_fingerprint(pub_key)
        return {
            "id": f"system-ca-{fingerprint[:16]}",
            "organization_id": None,
            "name": "System CA (config file)",
            "description": (
                "Read-only — this CA is loaded from the server's SSH_CA_PRIVATE_KEY "
                "environment variable or etc/ssh_ca.conf. Manage it on the server."
            ),
            # ca_type is set by the caller
            "ca_type": "user",
            "key_type": "unknown",
            "public_key": pub_key,
            "fingerprint": fingerprint,
            "is_active": True,
            "is_system": True,
            "default_cert_validity_hours": 0,
            "max_cert_validity_hours": 0,
            "total_certs": 0,
            "active_certs": 0,
            "revoked_certs": 0,
            "created_at": None,
            "updated_at": None,
        }
    except Exception:
        return None



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

    The owner may only delete the organization if they are the *sole* remaining
    member.  If other active members exist they must first transfer ownership
    (or remove all other members) before deleting the organization.

    Args:
        org_id: Organization ID

    Returns:
        200: Organization deleted successfully
        401: Not authenticated
        403: Not the owner
        404: Organization not found
        409: Organization still has other members — transfer ownership first
    """
    org = OrganizationService.get_organization_by_id(org_id)

    # Guard: block deletion while non-owner members still exist so ownership
    # can be transferred rather than silently orphaning them.
    active_member_count = org.get_member_count()
    if active_member_count > 1:
        return api_response(
            success=False,
            message=(
                "This organization still has other members. "
                "Please transfer ownership to another member or remove all "
                "other members before deleting the organization."
            ),
            status=409,
            error_type="ORG_HAS_MEMBERS",
            error_details={"member_count": active_member_count},
        )

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


@api_v1_bp.route("/organizations/<org_id>/transfer-ownership", methods=["POST"])
@login_required
@full_access_required
def transfer_organization_ownership(org_id):
    """Transfer organization ownership from the current user to another member.

    Only the current OWNER of the organization may call this endpoint.
    The caller will be demoted to ADMIN and the target user will be promoted to OWNER.

    Request body:
        new_owner_user_id (str): UUID of the member to promote to OWNER.

    Returns:
        200: Ownership transferred successfully
        400: Validation error / missing fields
        403: Caller is not the OWNER of this org
        404: Organization or target member not found
        409: Target is already the OWNER
    """
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.utils.constants import OrganizationRole, AuditAction
    from gatehouse_app.services.audit_service import AuditService

    caller = g.current_user

    data = request.get_json() or {}
    new_owner_user_id = data.get("new_owner_user_id")
    if not new_owner_user_id:
        return api_response(
            success=False,
            message="new_owner_user_id is required",
            status=400,
            error_type="VALIDATION_ERROR",
        )

    if str(new_owner_user_id) == str(caller.id):
        return api_response(
            success=False,
            message="You are already the owner of this organization.",
            status=409,
            error_type="CONFLICT",
        )

    # Fetch org (raises NotFound internally)
    org = OrganizationService.get_organization_by_id(org_id)

    # Confirm caller is the current OWNER
    caller_membership = OrganizationMember.query.filter_by(
        organization_id=org.id,
        user_id=caller.id,
        deleted_at=None,
    ).first()
    if not caller_membership or caller_membership.role != OrganizationRole.OWNER:
        return api_response(
            success=False,
            message="Only the organization owner can transfer ownership.",
            status=403,
            error_type="AUTHORIZATION_ERROR",
        )

    # Verify the target is an active member
    target_membership = OrganizationMember.query.filter_by(
        organization_id=org.id,
        user_id=new_owner_user_id,
        deleted_at=None,
    ).first()
    if not target_membership:
        return api_response(
            success=False,
            message="Target user is not a member of this organization.",
            status=404,
            error_type="NOT_FOUND",
        )

    if target_membership.role == OrganizationRole.OWNER:
        return api_response(
            success=False,
            message="Target user is already the owner.",
            status=409,
            error_type="CONFLICT",
        )

    # ── Atomic role swap ─────────────────────────────────────────────────────
    # Demote caller → ADMIN, promote target → OWNER.
    # Both updates go through OrganizationService so all hooks/auditing fire.
    try:
        demoted = OrganizationService.update_member_role(
            org=org,
            user_id=str(caller.id),
            new_role=OrganizationRole.ADMIN,
            updater_id=str(caller.id),
        )
        promoted = OrganizationService.update_member_role(
            org=org,
            user_id=str(new_owner_user_id),
            new_role=OrganizationRole.OWNER,
            updater_id=str(caller.id),
        )
    except Exception as exc:
        from gatehouse_app.extensions import db as _db
        _db.session.rollback()
        return api_response(
            success=False,
            message=f"Failed to transfer ownership: {exc}",
            status=500,
            error_type="SERVER_ERROR",
        )

    AuditService.log_action(
        action=AuditAction.ORG_OWNERSHIP_TRANSFERRED,
        user_id=caller.id,
        organization_id=org.id,
        resource_type="organization",
        resource_id=str(org.id),
        description=(
            f"Ownership of '{org.name}' transferred from {caller.email} "
            f"to {target_membership.user.email if target_membership.user else new_owner_user_id}"
        ),
        metadata={
            "previous_owner_id": str(caller.id),
            "previous_owner_email": caller.email,
            "new_owner_id": str(new_owner_user_id),
            "new_owner_email": (
                target_membership.user.email if target_membership.user else None
            ),
        },
    )

    def _member_dict(m):
        d = m.to_dict()
        if m.user:
            d["user"] = m.user.to_dict()
        return d

    return api_response(
        data={
            "previous_owner": _member_dict(demoted),
            "new_owner": _member_dict(promoted),
        },
        message=(
            f"Ownership of '{org.name}' successfully transferred to "
            f"{target_membership.user.email if target_membership.user else new_owner_user_id}."
        ),
    )


@api_v1_bp.route("/organizations/<org_id>/audit-logs", methods=["GET"])
@login_required
@require_admin
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
    from gatehouse_app.models.auth.audit_log import AuditLog

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

    # In dev mode email may not be configured — always log the link so it's findable
    import logging
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
    """List pending invite tokens for an organization.

    Returns:
        200: List of invites
        403: Not an admin
        404: Organization not found
    """
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
            "created_at": inv.created_at.isoformat() + "Z",
            "expires_at": inv.expires_at.isoformat() + "Z",
        }

    return api_response(
        data={"invites": [invite_to_dict(i) for i in invites]},
        message="Invites retrieved",
    )


@api_v1_bp.route("/organizations/<org_id>/invites/<invite_id>", methods=["DELETE"])
@login_required
@require_admin
def cancel_org_invite(org_id, invite_id):
    """Cancel (soft-delete) an organization invite.

    Returns:
        200: Invite cancelled
        403: Not an admin
        404: Invite not found
    """
    from gatehouse_app.models import OrgInviteToken, Organization

    org = Organization.query.filter_by(id=org_id, deleted_at=None).first()
    if not org:
        return api_response(success=False, message="Organization not found", status=404)

    invite = OrgInviteToken.query.filter_by(id=invite_id, organization_id=org_id, deleted_at=None).first()
    if not invite:
        return api_response(success=False, message="Invite not found", status=404)

    # Soft delete the invite so it's no longer usable
    invite.delete(soft=True)

    return api_response(data={}, message="Invite cancelled")


@api_v1_bp.route("/invites/<token>", methods=["GET"])
def get_invite(token):
    """Get invite details by token.

    Returns:
        200: Invite details (org name, email)
        400: Invalid or expired token
    """
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
        from gatehouse_app.extensions import db
        db.session.rollback()  # Clear broken transaction so invite.accept() can commit

    invite.accept()

    has_webauthn = user.has_webauthn_enabled()
    has_totp = user.has_totp_enabled()

    if has_webauthn:
        from flask import session as flask_session
        flask_session["webauthn_pending_user_id"] = user.id
        return api_response(
            data={"requires_webauthn": True},
            message="Passkey verification required. Please use your passkey to complete sign-in.",
        )

    if has_totp:
        from flask import session as flask_session
        flask_session["totp_pending_user_id"] = user.id
        return api_response(
            data={"requires_totp": True},
            message="TOTP code required. Please enter your 6-digit code from your authenticator app.",
        )

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
@require_admin
@full_access_required
def list_org_clients(org_id):
    """List OIDC clients for an organization.

    Returns:
        200: List of OIDC clients
        403: Not an admin
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
    from gatehouse_app.models.auth.audit_log import AuditLog
    from gatehouse_app.models.organization.organization_member import OrganizationMember

    current_user = g.current_user
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(int(request.args.get("per_page", 50)), 200)

    # Check if the user is an admin or owner of any org to grant admin-level access
    is_admin = OrganizationMember.query.filter(
        OrganizationMember.user_id == current_user.id,
        OrganizationMember.role.in_(["OWNER", "ADMIN"]),
        OrganizationMember.deleted_at == None,
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
    from gatehouse_app.models.auth.audit_log import AuditLog

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



@api_v1_bp.route("/organizations/<org_id>/roles", methods=["GET"])
@login_required
def list_organization_roles(org_id):
    """List the available roles for an organization.

    Returns the canonical set of OrganizationRole values together with every
    current member assigned to each role.

    Returns:
        200: roles list with member counts
        401: Not authenticated
        404: Organization not found
    """
    from gatehouse_app.models.organization.organization import Organization
    from gatehouse_app.models.organization.organization_member import OrganizationMember

    org = Organization.query.filter_by(id=org_id, deleted_at=None).first()
    if not org:
        return api_response(success=False, message="Organization not found", status=404, error_type="NOT_FOUND")

    # Load all active members grouped by role
    members = OrganizationMember.query.filter_by(organization_id=org_id, deleted_at=None).all()
    by_role: dict = {r.value: [] for r in OrganizationRole}
    for m in members:
        role_key = m.role.value if hasattr(m.role, "value") else str(m.role)
        if role_key in by_role:
            by_role[role_key].append({
                "user_id": m.user_id,
                "email": m.user.email if m.user else None,
                "full_name": m.user.full_name if m.user else None,
                "joined_at": m.created_at.isoformat() if m.created_at else None,
            })

    roles = [
        {
            "role": r.value,
            "member_count": len(by_role[r.value]),
            "members": by_role[r.value],
        }
        for r in OrganizationRole
    ]
    return api_response(data={"roles": roles, "organization_id": org_id}, message="Roles retrieved")


@api_v1_bp.route("/organizations/<org_id>/roles/<role_name>/members", methods=["POST"])
@login_required
@require_admin
def assign_role_to_member(org_id, role_name):
    """Assign a role to a user in the organization (admin/owner only).

    This is a convenience endpoint equivalent to PATCH
    /organizations/<org_id>/members/<user_id>/role but driven by role name.

    Request body:
        user_id – UUID of the member to assign

    Returns:
        200: Role assigned
        400: Invalid role / missing user_id
        403: Not an admin/owner
        404: Org or member not found
    """
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.extensions import db

    try:
        new_role = OrganizationRole(role_name.lower())
    except ValueError:
        valid = [r.value for r in OrganizationRole]
        return api_response(success=False, message=f"Invalid role. Must be one of: {valid}", status=400, error_type="VALIDATION_ERROR")

    data = request.get_json() or {}
    target_user_id = data.get("user_id")
    if not target_user_id:
        return api_response(success=False, message="user_id is required", status=400, error_type="VALIDATION_ERROR")

    membership = OrganizationMember.query.filter_by(
        organization_id=org_id, user_id=target_user_id, deleted_at=None
    ).first()
    if not membership:
        return api_response(success=False, message="Member not found in this organization", status=404, error_type="NOT_FOUND")

    membership.role = new_role
    db.session.commit()
    return api_response(
        data={"user_id": target_user_id, "role": new_role.value},
        message=f"Role updated to {new_role.value}",
    )


@api_v1_bp.route("/organizations/<org_id>/roles/<role_name>/members/<user_id>", methods=["DELETE"])
@login_required
@require_admin
def remove_role_from_member(org_id, role_name, user_id):
    """Demote a member to GUEST (effectively removing a named role).

    Removing a role downgrades the member to GUEST rather than removing them
    from the organization entirely.  Use the existing DELETE
    /organizations/<org_id>/members/<user_id> endpoint to fully remove.

    Returns:
        200: Role removed (member demoted to GUEST)
        400: Invalid role name
        403: Not an admin/owner
        404: Org or member not found
    """
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.extensions import db

    try:
        OrganizationRole(role_name.lower())  # validate the name
    except ValueError:
        valid = [r.value for r in OrganizationRole]
        return api_response(success=False, message=f"Invalid role. Must be one of: {valid}", status=400, error_type="VALIDATION_ERROR")

    membership = OrganizationMember.query.filter_by(
        organization_id=org_id, user_id=user_id, deleted_at=None
    ).first()
    if not membership:
        return api_response(success=False, message="Member not found in this organization", status=404, error_type="NOT_FOUND")

    membership.role = OrganizationRole.GUEST
    db.session.commit()
    return api_response(
        data={"user_id": user_id, "role": OrganizationRole.GUEST.value},
        message="Role removed; member demoted to GUEST",
    )


@api_v1_bp.route("/organizations/<org_id>/cas", methods=["GET"])
@login_required
@require_admin
def list_org_cas(org_id):
    """List all Certificate Authorities for an organization.

    If the system config-file CA is configured (via SSH_CA_PRIVATE_KEY env var
    or ca_key_path in etc/ssh_ca.conf) and no DB CA exists for a given ca_type,
    a synthetic read-only entry is injected so the UI correctly shows the
    system CA as configured rather than "Not configured".

    Returns:
        200: List of CAs (private_key excluded)
        403: Not admin/owner
        404: Org not found
    """
    from gatehouse_app.models.ssh_ca.ca import CA, CaType
    from gatehouse_app.models.organization.organization import Organization

    org = Organization.query.filter_by(id=org_id, deleted_at=None).first()
    if not org:
        return api_response(success=False, message="Organization not found", status=404, error_type="NOT_FOUND")

    cas = CA.query.filter_by(organization_id=org_id, deleted_at=None).all()
    ca_list = [ca.to_dict() for ca in cas]

    # Determine which ca_types are already covered by a DB CA
    covered_types = {ca.ca_type for ca in cas}

    # Check whether a system config-file CA is available
    system_ca_dict = _get_system_ca_dict()
    if system_ca_dict:
        # Inject a synthetic entry for each ca_type NOT covered by a real DB CA.
        # The system CA only signs user certs (cert_type="user"), so we only
        # inject it for the user slot.  Host signing always needs a DB CA.
        if CaType.USER not in covered_types:
            ca_list.append({**system_ca_dict, "ca_type": "user"})

    return api_response(
        data={"cas": ca_list, "count": len(ca_list)},
        message="CAs retrieved",
    )


@api_v1_bp.route("/organizations/<org_id>/cas/<ca_id>", methods=["PATCH"])
@login_required
@require_admin
def update_org_ca(org_id, ca_id):
    """Update CA configuration (validity hours).

    Request body:
        default_cert_validity_hours: Default validity in hours (optional)
        max_cert_validity_hours: Maximum validity in hours (optional)

    Returns:
        200: CA updated successfully
        400: Validation error
        403: Not admin/owner
        404: Org or CA not found
    """
    from gatehouse_app.models.ssh_ca.ca import CA
    from gatehouse_app.models.organization.organization import Organization
    from marshmallow import Schema, fields, validate, ValidationError

    org = Organization.query.filter_by(id=org_id, deleted_at=None).first()
    if not org:
        return api_response(success=False, message="Organization not found", status=404, error_type="NOT_FOUND")

    ca = CA.query.filter_by(id=ca_id, organization_id=org_id, deleted_at=None).first()
    if not ca:
        return api_response(success=False, message="CA not found", status=404, error_type="NOT_FOUND")

    try:
        class CAUpdateSchema(Schema):
            default_cert_validity_hours = fields.Int(
                validate=validate.Range(min=1),
                required=False
            )
            max_cert_validity_hours = fields.Int(
                validate=validate.Range(min=1),
                required=False
            )

        schema = CAUpdateSchema()
        data = schema.load(request.json or {})

        # Validate that max >= default if both are provided
        default_hours = data.get('default_cert_validity_hours', ca.default_cert_validity_hours)
        max_hours = data.get('max_cert_validity_hours', ca.max_cert_validity_hours)

        if default_hours > max_hours:
            return api_response(
                success=False,
                message="Default validity must be less than or equal to maximum validity",
                status=400,
                error_type="VALIDATION_ERROR",
            )

        # Update fields
        if 'default_cert_validity_hours' in data:
            ca.default_cert_validity_hours = data['default_cert_validity_hours']
        if 'max_cert_validity_hours' in data:
            ca.max_cert_validity_hours = data['max_cert_validity_hours']

        db.session.commit()

        return api_response(
            data={"ca": ca.to_dict()},
            message="CA updated successfully",
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )
    except Exception as e:
        db.session.rollback()
        return api_response(
            success=False,
            message="Failed to update CA",
            status=500,
            error_type="SERVER_ERROR",
        )


@api_v1_bp.route("/organizations/<org_id>/cas", methods=["POST"])
@login_required
@require_admin
def create_org_ca(org_id):
    """Create a new Certificate Authority for an organization.

    Request body:
        name: CA display name (required)
        description: Optional description
        key_type: "ed25519" (default), "rsa", or "ecdsa"
        default_cert_validity_hours: Default cert validity in hours (optional)
        max_cert_validity_hours: Max cert validity in hours (optional)

    Returns:
        201: CA created successfully
        400: Validation error or name already taken
        403: Not admin/owner
        404: Org not found
    """
    from gatehouse_app.models.ssh_ca.ca import CA, KeyType
    from gatehouse_app.models.organization.organization import Organization
    from gatehouse_app.utils.crypto import compute_ssh_fingerprint
    from gatehouse_app.utils.ca_key_encryption import encrypt_ca_key
    from marshmallow import Schema, fields as ma_fields, validate, ValidationError as MaValidationError
    from sshkey_tools.keys import Ed25519PrivateKey, RsaPrivateKey, EcdsaPrivateKey

    org = Organization.query.filter_by(id=org_id, deleted_at=None).first()
    if not org:
        return api_response(success=False, message="Organization not found", status=404, error_type="NOT_FOUND")

    class CreateCASchema(Schema):
        name = ma_fields.Str(required=True, validate=validate.Length(min=1, max=255))
        description = ma_fields.Str(load_default=None, allow_none=True)
        ca_type = ma_fields.Str(load_default="user", validate=validate.OneOf(["user", "host"]))
        key_type = ma_fields.Str(load_default="ed25519", validate=validate.OneOf(["ed25519", "rsa", "ecdsa"]))
        default_cert_validity_hours = ma_fields.Int(load_default=8, validate=validate.Range(min=1))
        max_cert_validity_hours = ma_fields.Int(load_default=720, validate=validate.Range(min=1))

    try:
        schema = CreateCASchema()
        data = schema.load(request.get_json() or {})

        # Check name uniqueness within org
        existing = CA.query.filter_by(
            organization_id=org_id, name=data["name"], deleted_at=None
        ).first()
        if existing:
            return api_response(
                success=False,
                message="A CA with that name already exists in this organization",
                status=400,
                error_type="DUPLICATE_NAME",
            )

        # Enforce one CA per type per org
        from gatehouse_app.models.ssh_ca.ca import CaType
        ca_type_val = data["ca_type"]
        existing_type = CA.query.filter_by(
            organization_id=org_id, deleted_at=None
        ).filter(CA.ca_type == CaType(ca_type_val)).first()
        if existing_type:
            type_label = "User" if ca_type_val == "user" else "Host"
            return api_response(
                success=False,
                message=f"A {type_label} CA already exists for this organization. "
                        f"You can only have one {type_label} CA per organization.",
                status=400,
                error_type="DUPLICATE_CA_TYPE",
            )

        # Validate cross-field
        if data["default_cert_validity_hours"] > data["max_cert_validity_hours"]:
            return api_response(
                success=False,
                message="Default validity must be less than or equal to maximum validity",
                status=400,
                error_type="VALIDATION_ERROR",
            )

        # Generate key pair
        key_type = data["key_type"]
        if key_type == "ed25519":
            private_key_obj = Ed25519PrivateKey.generate()
        elif key_type == "rsa":
            private_key_obj = RsaPrivateKey.generate(4096)
        else:  # ecdsa
            private_key_obj = EcdsaPrivateKey.generate()

        private_key_pem = private_key_obj.to_string()
        public_key_str = private_key_obj.public_key.to_string()
        fingerprint = compute_ssh_fingerprint(public_key_str)

        # Encrypt the private key before storing in the database
        encrypted_private_key = encrypt_ca_key(private_key_pem)

        ca = CA(
            organization_id=org_id,
            name=data["name"],
            description=data["description"],
            ca_type=CaType(ca_type_val),
            key_type=KeyType(key_type),
            private_key=encrypted_private_key,
            public_key=public_key_str,
            fingerprint=fingerprint,
            default_cert_validity_hours=data["default_cert_validity_hours"],
            max_cert_validity_hours=data["max_cert_validity_hours"],
            is_active=True,
        )
        db.session.add(ca)
        try:
            db.session.commit()
        except Exception as commit_exc:
            db.session.rollback()
            # Surface unique-constraint violations (soft-deleted record with same name) as a
            # user-friendly 400 instead of a 500.
            exc_str = str(commit_exc).lower()
            if "uix_org_ca_name" in exc_str or "unique" in exc_str:
                return api_response(
                    success=False,
                    message=(
                        "A CA with that name already exists in this organization "
                        "(it may have been recently deleted — choose a different name)."
                    ),
                    status=400,
                    error_type="DUPLICATE_NAME",
                )
            raise

        return api_response(
            data={"ca": ca.to_dict()},
            message="CA created successfully",
            status=201,
        )

    except MaValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("Failed to create CA")
        return api_response(
            success=False,
            message="Failed to create CA",
            status=500,
            error_type="SERVER_ERROR",
        )


@api_v1_bp.route("/organizations/<org_id>/cas/<ca_id>", methods=["DELETE"])
@login_required
@require_admin
def delete_org_ca(org_id, ca_id):
    """Soft-delete a Certificate Authority.

    Deactivates the CA so no new certificates can be signed with it.
    Existing certificates remain valid until they expire.

    Returns:
        200: CA deleted successfully
        403: Not admin/owner
        404: Org or CA not found
    """
    from gatehouse_app.models.ssh_ca.ca import CA
    from gatehouse_app.models.organization.organization import Organization
    from gatehouse_app.utils.constants import AuditAction
    from gatehouse_app.models import AuditLog

    org = Organization.query.filter_by(id=org_id, deleted_at=None).first()
    if not org:
        return api_response(success=False, message="Organization not found", status=404, error_type="NOT_FOUND")

    ca = CA.query.filter_by(id=ca_id, organization_id=org_id, deleted_at=None).first()
    if not ca:
        return api_response(success=False, message="CA not found", status=404, error_type="NOT_FOUND")

    try:
        ca_name = ca.name
        ca_type = ca.ca_type.value if hasattr(ca.ca_type, "value") else str(ca.ca_type)
        ca.is_active = False
        ca.delete(soft=True)

        AuditLog.log(
            action=AuditAction.CA_DELETED,
            user_id=g.current_user.id,
            resource_type="CA",
            resource_id=ca_id,
            organization_id=org_id,
            ip_address=request.remote_addr,
            description=f"CA '{ca_name}' ({ca_type}) deleted",
        )

        return api_response(
            data={"ca_id": ca_id},
            message="CA deleted successfully",
        )
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("Failed to delete CA")
        return api_response(
            success=False,
            message="Failed to delete CA",
            status=500,
            error_type="SERVER_ERROR",
        )


@api_v1_bp.route("/organizations/<org_id>/cas/<ca_id>/rotate", methods=["POST"])
@login_required
@require_admin
def rotate_org_ca(org_id, ca_id):
    """Rotate (replace) a CA's key pair.

    Generates a new key pair of the same or different type.  The old public key
    fingerprint is returned so admins can update TrustedUserCAKeys / known_hosts
    on their servers.  All previously-issued certificates remain valid until they
    expire but no new certificates will be signed with the old key.

    Request body (all optional):
        key_type: "ed25519" (default keeps current), "rsa", or "ecdsa"
        reason: Human-readable reason for the rotation

    Returns:
        200: CA rotated — { ca, old_fingerprint }
        403: Not admin/owner
        404: Org or CA not found
    """
    from gatehouse_app.models.ssh_ca.ca import CA, KeyType
    from gatehouse_app.models.organization.organization import Organization
    from gatehouse_app.utils.crypto import compute_ssh_fingerprint
    from gatehouse_app.utils.ca_key_encryption import encrypt_ca_key
    from gatehouse_app.utils.constants import AuditAction
    from gatehouse_app.models import AuditLog
    from sshkey_tools.keys import Ed25519PrivateKey, RsaPrivateKey, EcdsaPrivateKey

    org = Organization.query.filter_by(id=org_id, deleted_at=None).first()
    if not org:
        return api_response(success=False, message="Organization not found", status=404, error_type="NOT_FOUND")

    ca = CA.query.filter_by(id=ca_id, organization_id=org_id, deleted_at=None).first()
    if not ca:
        return api_response(success=False, message="CA not found", status=404, error_type="NOT_FOUND")

    data = request.get_json() or {}
    new_key_type = data.get("key_type") or (ca.key_type.value if hasattr(ca.key_type, "value") else str(ca.key_type))
    reason = data.get("reason", "Admin-initiated key rotation")

    if new_key_type not in ("ed25519", "rsa", "ecdsa"):
        return api_response(
            success=False,
            message="Invalid key_type. Must be one of: ed25519, rsa, ecdsa",
            status=400,
            error_type="VALIDATION_ERROR",
        )

    try:
        old_fingerprint = ca.fingerprint

        # Generate new key pair
        if new_key_type == "ed25519":
            private_key_obj = Ed25519PrivateKey.generate()
        elif new_key_type == "rsa":
            private_key_obj = RsaPrivateKey.generate(4096)
        else:  # ecdsa
            private_key_obj = EcdsaPrivateKey.generate()

        new_private_key = private_key_obj.to_string()
        new_public_key = private_key_obj.public_key.to_string()
        new_fingerprint = compute_ssh_fingerprint(new_public_key)

        # Encrypt the new private key before storing
        encrypted_new_private_key = encrypt_ca_key(new_private_key)

        ca.rotate_key(
            new_private_key=encrypted_new_private_key,
            new_public_key=new_public_key,
            new_fingerprint=new_fingerprint,
            reason=reason,
        )
        ca.key_type = KeyType(new_key_type)
        db.session.commit()

        AuditLog.log(
            action=AuditAction.CA_KEY_ROTATED,
            user_id=g.current_user.id,
            resource_type="CA",
            resource_id=ca_id,
            organization_id=org_id,
            ip_address=request.remote_addr,
            description=(
                f"CA '{ca.name}' key rotated. "
                f"Old fingerprint: {old_fingerprint}, New fingerprint: {new_fingerprint}. "
                f"Reason: {reason}"
            ),
        )

        return api_response(
            data={
                "ca": ca.to_dict(),
                "old_fingerprint": old_fingerprint,
            },
            message="CA key rotated successfully. Update TrustedUserCAKeys / known_hosts on your servers.",
        )
    except Exception as e:
        db.session.rollback()
        current_app.logger.exception("Failed to rotate CA key")
        return api_response(
            success=False,
            message="Failed to rotate CA key",
            status=500,
            error_type="SERVER_ERROR",
        )

