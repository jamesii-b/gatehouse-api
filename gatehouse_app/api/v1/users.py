"""User endpoints."""
from flask import g, request
from marshmallow import ValidationError
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.utils.decorators import login_required, full_access_required
from gatehouse_app.schemas.user_schema import UserUpdateSchema, ChangePasswordSchema
from gatehouse_app.services.user_service import UserService
from gatehouse_app.services.auth_service import AuthService


@api_v1_bp.route("/users/me", methods=["GET"])
@login_required
def get_me():
    """
    Get current user profile.

    Returns:
        200: User profile data
        401: Not authenticated
    """
    user = g.current_user

    return api_response(
        data={"user": user.to_dict()},
        message="User profile retrieved successfully",
    )


@api_v1_bp.route("/users/me", methods=["PATCH"])
@login_required
@full_access_required
def update_me():
    """
    Update current user profile.

    Request body:
        full_name: Optional full name
        avatar_url: Optional avatar URL

    Returns:
        200: User updated successfully
        400: Validation error
        401: Not authenticated
    """
    try:
        # Validate request data
        schema = UserUpdateSchema()
        data = schema.load(request.json)

        # Update user
        user = UserService.update_user(g.current_user, **data)

        return api_response(
            data={"user": user.to_dict()},
            message="Profile updated successfully",
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )


@api_v1_bp.route("/users/me", methods=["DELETE"])
@login_required
@full_access_required
def delete_me():
    """
    Delete current user account (soft delete).

    Behaviour for owned organizations:
      - If the org has other active members  → blocked; user must transfer ownership first.
      - If they are the sole member          → org is automatically cascade-deleted (no orphan risk).

    Returns:
        200: Account deleted successfully (sole-member orgs auto-deleted)
        401: Not authenticated
        409: USER_IS_SOLE_OWNER — user owns orgs that still have other members
    """
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.utils.constants import OrganizationRole
    from gatehouse_app.services.organization_service import OrganizationService

    user = g.current_user

    # Find all orgs where this user is the owner.
    owned_memberships = OrganizationMember.query.filter_by(
        user_id=user.id,
        role=OrganizationRole.OWNER,
        deleted_at=None,
    ).all()

    # Separate into two buckets depending on whether other members exist.
    transfer_needed = []   # org has other members → must transfer ownership first
    auto_delete = []       # user is sole member   → safe to cascade-delete automatically

    for membership in owned_memberships:
        org = membership.organization
        if org.deleted_at is not None:
            continue
        member_count = org.get_member_count()
        if member_count > 1:
            transfer_needed.append(org.name)
        else:
            auto_delete.append(org)

    # Hard block: user owns orgs with other members — must transfer first.
    if transfer_needed:
        names = ", ".join(f'"{n}"' for n in transfer_needed)
        return api_response(
            success=False,
            message=(
                f"You are the owner of {len(transfer_needed)} organization"
                f"{'s' if len(transfer_needed) > 1 else ''} that still "
                f"{'have' if len(transfer_needed) > 1 else 'has'} other members "
                f"({names}). Transfer ownership to another member first."
            ),
            status=409,
            error_type="USER_IS_SOLE_OWNER",
            error_details={"transfer_ownership": transfer_needed},
        )

    # Auto-delete any sole-member orgs so no orphaned org rows can ever be left behind.
    for org in auto_delete:
        OrganizationService.force_delete_organization(org, user_id=user.id)

    UserService.delete_user(user, soft=True)

    return api_response(
        message="Account deleted successfully",
    )


@api_v1_bp.route("/users/me/password", methods=["POST"])
@login_required
@full_access_required
def change_password():
    """
    Change current user password.

    Request body:
        current_password: Current password
        new_password: New password
        new_password_confirm: New password confirmation

    Returns:
        200: Password changed successfully
        400: Validation error
        401: Not authenticated or invalid current password
    """
    try:
        # Validate request data
        schema = ChangePasswordSchema()
        data = schema.load(request.json)

        # Verify passwords match
        if data["new_password"] != data["new_password_confirm"]:
            return api_response(
                success=False,
                message="New passwords do not match",
                status=400,
                error_type="VALIDATION_ERROR",
                error_details={"new_password_confirm": ["Passwords do not match"]},
            )

        # Change password
        AuthService.change_password(
            user=g.current_user,
            current_password=data["current_password"],
            new_password=data["new_password"],
        )

        return api_response(
            message="Password changed successfully",
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )


@api_v1_bp.route("/users/me/organizations", methods=["GET"])
@login_required
@full_access_required
def get_my_organizations():
    """
    Get all organizations current user is a member of, including the user's role.

    Returns:
        200: List of organizations with role
        401: Not authenticated
    """
    from gatehouse_app.models.organization.organization_member import OrganizationMember

    user = g.current_user
    memberships = OrganizationMember.query.filter_by(
        user_id=user.id,
        deleted_at=None,
    ).all()

    orgs = []
    for membership in memberships:
        org = membership.organization
        if not org or org.deleted_at is not None:
            continue
        org_dict = org.to_dict()
        org_dict["role"] = membership.role.value if hasattr(membership.role, "value") else str(membership.role)
        orgs.append(org_dict)

    return api_response(
        data={
            "organizations": orgs,
            "count": len(orgs),
        },
        message="Organizations retrieved successfully",
    )


@api_v1_bp.route("/users/me/principals", methods=["GET"])
@login_required
@full_access_required
def get_my_principals():
    """Return all principals the current user can sign certificates for.

    For each organization the user belongs to, returns:
      - Their effective principals (direct membership + via department)
      - Their role in that org (so the frontend can offer admin-mode selection)
      - All principals in the org (admin/owner only — so they can pick any)

    Returns:
        200: {
            orgs: [{
                org_id, org_name, role,
                my_principals: [{id, name, description}],
                all_principals: [{id, name, description}]  # populated for admin/owner only
            }]
        }
    """
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.models.organization.principal import Principal, PrincipalMembership
    from gatehouse_app.models.organization.department import DepartmentMembership, DepartmentPrincipal
    from gatehouse_app.utils.constants import OrganizationRole

    user = g.current_user
    user_id = user.id

    # Get all org memberships
    memberships = OrganizationMember.query.filter_by(
        user_id=user_id,
    ).all()

    orgs_result = []
    for membership in memberships:
        org = membership.organization
        if not org or org.deleted_at is not None:
            continue

        role = membership.role
        is_admin = role in (OrganizationRole.ADMIN, OrganizationRole.OWNER)

        # Collect the user's effective principals for this org
        # Track direct vs via-department separately
        direct_principal_ids = set()
        via_dept_principal_ids = set()

        # Direct memberships
        direct = PrincipalMembership.query.filter_by(
            user_id=user_id,
            deleted_at=None,
        ).all()
        for pm in direct:
            if pm.principal and pm.principal.organization_id == org.id and pm.principal.deleted_at is None:
                direct_principal_ids.add(pm.principal_id)

        # Via department
        dept_memberships = DepartmentMembership.query.filter_by(
            user_id=user_id,
            deleted_at=None,
        ).all()
        for dm in dept_memberships:
            if dm.department and dm.department.organization_id == org.id and dm.department.deleted_at is None:
                dept_principals = DepartmentPrincipal.query.filter_by(
                    department_id=dm.department_id,
                    deleted_at=None,
                ).all()
                for dp in dept_principals:
                    if dp.principal and dp.principal.deleted_at is None:
                        via_dept_principal_ids.add(dp.principal_id)

        effective_principal_ids = direct_principal_ids | via_dept_principal_ids

        # Fetch principal objects
        my_principals = []
        if effective_principal_ids:
            my_p = Principal.query.filter(
                Principal.id.in_(list(effective_principal_ids)),
                Principal.deleted_at == None,
            ).all()
            my_principals = [
                {
                    "id": p.id,
                    "name": p.name,
                    "description": p.description,
                    # direct=True means removable via API; False=inherited via department
                    "direct": p.id in direct_principal_ids,
                }
                for p in my_p
            ]

        # For admins/owners: also return all principals in the org
        all_principals = []
        if is_admin:
            all_p = Principal.query.filter_by(
                organization_id=org.id,
                deleted_at=None,
            ).all()
            all_principals = [{"id": p.id, "name": p.name, "description": p.description} for p in all_p]

        orgs_result.append({
            "org_id": org.id,
            "org_name": org.name,
            "role": role.value if hasattr(role, "value") else role,
            "is_admin": is_admin,
            "my_principals": my_principals,
            "all_principals": all_principals,
        })

    return api_response(
        data={"orgs": orgs_result},
        message="Principals retrieved successfully",
    )


@api_v1_bp.route("/admin/users", methods=["GET"])
@login_required
@full_access_required
def admin_list_users():
    """List all users the caller has admin rights to see.

    The caller must be an OWNER or ADMIN of at least one organization.
    Returns users that share an organization with the caller and where the
    caller holds admin/owner role in that organization.

    Query params:
        q       – optional search string (matched against name/email)
        page    – page number (default 1)
        per_page – page size (default 50, max 200)
    """
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.models.user.user import User as _User
    from gatehouse_app.extensions import db as _db
    from sqlalchemy import or_

    caller = g.current_user

    # Find orgs where caller is admin/owner
    admin_memberships = OrganizationMember.query.filter(
        OrganizationMember.user_id == caller.id,
        OrganizationMember.role.in_(["OWNER", "ADMIN"]),
        OrganizationMember.deleted_at == None,
    ).all()

    if not admin_memberships:
        return api_response(
            success=False,
            message="Admin or owner role required",
            status=403,
            error_type="AUTHORIZATION_ERROR",
        )

    admin_org_ids = [m.organization_id for m in admin_memberships]

    # Collect user IDs in those orgs
    member_rows = OrganizationMember.query.filter(
        OrganizationMember.organization_id.in_(admin_org_ids),
        OrganizationMember.deleted_at == None,
    ).all()
    visible_user_ids = list({row.user_id for row in member_rows})

    # Optional search
    q = request.args.get("q", "").strip()
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(200, max(1, int(request.args.get("per_page", 50))))
    except ValueError:
        page, per_page = 1, 50

    query = _User.query.filter(
        _User.id.in_(visible_user_ids),
        _User.deleted_at == None,
    )
    if q:
        like = f"%{q}%"
        query = query.filter(or_(_User.email.ilike(like), _User.full_name.ilike(like)))

    total = query.count()
    users = query.order_by(_User.email).offset((page - 1) * per_page).limit(per_page).all()

    member_lookup: dict = {}
    for row in member_rows:
        if row.user_id not in member_lookup:
            member_lookup[row.user_id] = {
                "organization_id": row.organization_id,
                "role": row.role.value if hasattr(row.role, "value") else row.role,
            }

    users_data = []
    for u in users:
        d = u.to_dict()
        m = member_lookup.get(u.id, {})
        d["org_role"] = m.get("role", "member")
        d["org_id"] = m.get("organization_id")
        users_data.append(d)

    return api_response(
        data={
            "users": users_data,
            "count": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
        },
        message="Users retrieved successfully",
    )


@api_v1_bp.route("/admin/users/<user_id>", methods=["GET"])
@login_required
@full_access_required
def admin_get_user(user_id):
    """Get a single user's profile (admin view with SSH keys)."""
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.models.user.user import User as _User
    from gatehouse_app.models.ssh_ca.ssh_key import SSHKey

    caller = g.current_user

    target = _User.query.filter_by(id=user_id, deleted_at=None).first()
    if not target:
        return api_response(success=False, message="User not found", status=404, error_type="NOT_FOUND")

    # Verify caller has admin access to a shared org
    target_org_ids = {m.organization_id for m in target.organization_memberships if m.deleted_at is None}
    has_access = OrganizationMember.query.filter(
        OrganizationMember.user_id == caller.id,
        OrganizationMember.organization_id.in_(target_org_ids),
        OrganizationMember.role.in_(["OWNER", "ADMIN"]),
        OrganizationMember.deleted_at == None,
    ).first() is not None

    if not has_access:
        return api_response(success=False, message="Access denied", status=403, error_type="AUTHORIZATION_ERROR")

    ssh_keys = SSHKey.query.filter_by(user_id=user_id, deleted_at=None).all()

    return api_response(
        data={
            "user": target.to_dict(),
            "ssh_keys": [k.to_dict() for k in ssh_keys],
        },
        message="User retrieved",
    )


@api_v1_bp.route("/admin/users/<user_id>/suspend", methods=["POST"])
@login_required
@full_access_required
def admin_suspend_user(user_id):
    """Suspend a user account (blocks CA issuance and login).

    The caller must be an OWNER or ADMIN of an organization the target user belongs to.
    """
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.models.user.user import User as _User
    from gatehouse_app.extensions import db as _db
    from gatehouse_app.utils.constants import UserStatus, AuditAction
    from gatehouse_app.services.audit_service import AuditService

    caller = g.current_user
    target = _User.query.filter_by(id=user_id, deleted_at=None).first()
    if not target:
        return api_response(success=False, message="User not found", status=404, error_type="NOT_FOUND")

    if target.id == caller.id:
        return api_response(success=False, message="Cannot suspend yourself", status=400, error_type="BAD_REQUEST")

    # Verify caller has admin access to a shared org
    target_org_ids = {m.organization_id for m in target.organization_memberships if m.deleted_at is None}
    admin_in_shared_org = OrganizationMember.query.filter(
        OrganizationMember.user_id == caller.id,
        OrganizationMember.organization_id.in_(target_org_ids),
        OrganizationMember.role.in_(["OWNER", "ADMIN"]),
        OrganizationMember.deleted_at == None,
    ).first()

    if not admin_in_shared_org:
        return api_response(success=False, message="Access denied", status=403, error_type="AUTHORIZATION_ERROR")

    # ── Owner protection ──────────────────────────────────────────────────────
    # An org owner cannot be suspended until they transfer ownership.
    from gatehouse_app.utils.constants import OrganizationRole
    owner_memberships = OrganizationMember.query.filter(
        OrganizationMember.user_id == target.id,
        OrganizationMember.role == OrganizationRole.OWNER,
        OrganizationMember.deleted_at == None,
    ).all()
    if owner_memberships:
        org_names = [
            m.organization.name
            for m in owner_memberships
            if m.organization and not m.organization.deleted_at
        ]
        return api_response(
            success=False,
            message=(
                f"Cannot suspend an organization owner. "
                f"{target.email} is the owner of: {', '.join(org_names)}. "
                "Transfer ownership to another member first."
            ),
            status=403,
            error_type="OWNER_PROTECTION",
        )

    if target.status in (UserStatus.SUSPENDED, UserStatus.COMPLIANCE_SUSPENDED):
        return api_response(success=False, message="User is already suspended", status=409, error_type="CONFLICT")

    target.status = UserStatus.SUSPENDED
    _db.session.commit()

    AuditService.log_action(
        action=AuditAction.USER_SUSPEND,
        user_id=caller.id,
        organization_id=admin_in_shared_org.organization_id,
        resource_type="user",
        resource_id=str(target.id),
        description=f"Admin suspended user {target.email}",
        metadata={"target_user_id": str(target.id), "target_email": target.email},
    )

    return api_response(data={"user": target.to_dict()}, message="User suspended successfully")


@api_v1_bp.route("/admin/users/<user_id>/unsuspend", methods=["POST"])
@login_required
@full_access_required
def admin_unsuspend_user(user_id):
    """Restore a suspended user account to active status."""
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.models.user.user import User as _User
    from gatehouse_app.extensions import db as _db
    from gatehouse_app.utils.constants import UserStatus, AuditAction
    from gatehouse_app.services.audit_service import AuditService

    caller = g.current_user
    target = _User.query.filter_by(id=user_id, deleted_at=None).first()
    if not target:
        return api_response(success=False, message="User not found", status=404, error_type="NOT_FOUND")

    # Verify caller has admin access to a shared org
    target_org_ids = {m.organization_id for m in target.organization_memberships if m.deleted_at is None}
    admin_in_shared_org = OrganizationMember.query.filter(
        OrganizationMember.user_id == caller.id,
        OrganizationMember.organization_id.in_(target_org_ids),
        OrganizationMember.role.in_(["OWNER", "ADMIN"]),
        OrganizationMember.deleted_at == None,
    ).first()

    if not admin_in_shared_org:
        return api_response(success=False, message="Access denied", status=403, error_type="AUTHORIZATION_ERROR")

    if target.status not in (UserStatus.SUSPENDED, UserStatus.COMPLIANCE_SUSPENDED):
        return api_response(success=False, message="User is not suspended", status=409, error_type="CONFLICT")

    target.status = UserStatus.ACTIVE
    _db.session.commit()

    AuditService.log_action(
        action=AuditAction.USER_UNSUSPEND,
        user_id=caller.id,
        organization_id=admin_in_shared_org.organization_id,
        resource_type="user",
        resource_id=str(target.id),
        description=f"Admin unsuspended user {target.email}",
        metadata={"target_user_id": str(target.id), "target_email": target.email},
    )

    return api_response(data={"user": target.to_dict()}, message="User unsuspended successfully")


@api_v1_bp.route("/users/me/invites", methods=["GET"])
@login_required
def get_my_pending_invites():
    """Return pending (unaccepted, non-expired) invitations for the current user's email."""
    from gatehouse_app.models.organization.org_invite_token import OrgInviteToken
    from datetime import datetime, timezone

    user = g.current_user
    now = datetime.now(timezone.utc)

    invites = OrgInviteToken.query.filter(
        OrgInviteToken.email == user.email,
        OrgInviteToken.accepted_at.is_(None),
        OrgInviteToken.expires_at > now,
        OrgInviteToken.deleted_at.is_(None),
    ).all()

    return api_response(
        data={
            "invites": [
                {
                    "token": i.token,
                    "organization": {"id": str(i.organization_id), "name": i.organization.name},
                    "role": i.role,
                    "expires_at": i.expires_at.isoformat(),
                }
                for i in invites
            ]
        },
        message="Pending invitations retrieved",
    )


@api_v1_bp.route("/users/me/memberships", methods=["GET"])
@login_required
def get_my_memberships():
    """Return the current user's department and principal memberships across all orgs.

    Returns:
        200: {
            orgs: [{
                org_id, org_name, role,
                departments: [{id, name, description}],
                principals: [{id, name, description, via_department: bool}]
            }]
        }
    """
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.models.organization.department import DepartmentMembership, DepartmentPrincipal, Department
    from gatehouse_app.models.organization.principal import Principal, PrincipalMembership

    user = g.current_user

    memberships = OrganizationMember.query.filter_by(
        user_id=user.id,
        deleted_at=None,
    ).all()

    orgs_result = []
    for membership in memberships:
        org = membership.organization
        if not org or org.deleted_at is not None:
            continue

        # Departments the user belongs to
        dept_memberships = DepartmentMembership.query.filter_by(
            user_id=user.id,
            deleted_at=None,
        ).all()
        user_depts = [
            dm.department for dm in dept_memberships
            if dm.department
            and dm.department.organization_id == org.id
            and dm.department.deleted_at is None
        ]

        # Principals: direct
        direct_pm = PrincipalMembership.query.filter_by(
            user_id=user.id,
            deleted_at=None,
        ).all()
        direct_principal_ids = {
            pm.principal_id for pm in direct_pm
            if pm.principal
            and pm.principal.organization_id == org.id
            and pm.principal.deleted_at is None
        }

        # Principals: via department
        via_dept_principal_ids = set()
        for dept in user_depts:
            for dp in DepartmentPrincipal.query.filter_by(department_id=dept.id, deleted_at=None).all():
                if dp.principal and dp.principal.deleted_at is None:
                    via_dept_principal_ids.add(dp.principal_id)

        all_principal_ids = direct_principal_ids | via_dept_principal_ids
        principals_list = []
        if all_principal_ids:
            for p in Principal.query.filter(
                Principal.id.in_(list(all_principal_ids)),
                Principal.deleted_at == None,
            ).all():
                principals_list.append({
                    "id": str(p.id),
                    "name": p.name,
                    "description": p.description,
                    "via_department": p.id not in direct_principal_ids,
                })

        role = membership.role
        orgs_result.append({
            "org_id": str(org.id),
            "org_name": org.name,
            "role": role.value if hasattr(role, "value") else role,
            "departments": [
                {"id": str(d.id), "name": d.name, "description": d.description}
                for d in user_depts
            ],
            "principals": principals_list,
        })

    return api_response(
        data={"orgs": orgs_result},
        message="Memberships retrieved",
    )


@api_v1_bp.route("/admin/users/<user_id>/delete", methods=["POST"])
@login_required
@full_access_required
def admin_hard_delete_user(user_id):
    """Permanently delete a user and ALL associated data (hard delete, irreversible).

    Required body: {"confirm": true}

    Pre-conditions:
      - Caller is OWNER or ADMIN of a shared org with the target.
      - Cannot delete yourself.
      - Target must not be the OWNER of any active organization (transfer first).

    Side-effects:
      - All active SSH certificates are revoked before deletion.
      - The user row and all cascaded rows are hard-deleted from the database.
      - An audit log entry is written by the *caller* (so it is not lost with the user).
    """
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.models.user.user import User as _User
    from gatehouse_app.extensions import db as _db
    from gatehouse_app.utils.constants import UserStatus, AuditAction, OrganizationRole
    from gatehouse_app.services.audit_service import AuditService

    caller = g.current_user
    data = request.get_json() or {}

    if not data.get("confirm"):
        return api_response(
            success=False,
            message="Deletion requires explicit confirmation. Send {\"confirm\": true} to proceed.",
            status=400,
            error_type="CONFIRMATION_REQUIRED",
        )

    target = _User.query.filter_by(id=user_id).first()
    if not target:
        return api_response(success=False, message="User not found", status=404, error_type="NOT_FOUND")

    if target.id == caller.id:
        return api_response(
            success=False,
            message="Cannot delete your own account via this endpoint.",
            status=400,
            error_type="BAD_REQUEST",
        )

    # Caller must be OWNER/ADMIN of a shared org.
    # Include soft-deleted memberships so that already-soft-deleted users can
    # still be hard-deleted by an admin who shared an org with them.
    target_org_ids = {m.organization_id for m in target.organization_memberships}
    admin_in_shared_org = OrganizationMember.query.filter(
        OrganizationMember.user_id == caller.id,
        OrganizationMember.organization_id.in_(target_org_ids),
        OrganizationMember.role.in_(["OWNER", "ADMIN"]),
        OrganizationMember.deleted_at == None,
    ).first()
    if not admin_in_shared_org:
        return api_response(success=False, message="Access denied", status=403, error_type="AUTHORIZATION_ERROR")

    # Block deletion if target is an org owner — they must transfer first
    owner_memberships = OrganizationMember.query.filter(
        OrganizationMember.user_id == target.id,
        OrganizationMember.role == OrganizationRole.OWNER,
        OrganizationMember.deleted_at == None,
    ).all()
    if owner_memberships:
        org_names = [
            m.organization.name
            for m in owner_memberships
            if m.organization and not m.organization.deleted_at
        ]
        return api_response(
            success=False,
            message=(
                f"Cannot delete an organization owner. "
                f"{target.email} is the owner of: {', '.join(org_names)}. "
                "Transfer ownership to another member first."
            ),
            status=403,
            error_type="OWNER_PROTECTION",
        )

    # ── Collect counts for audit metadata ────────────────────────────────────
    from gatehouse_app.models.ssh_ca.ssh_key import SSHKey
    from gatehouse_app.models.ssh_ca.ssh_certificate import SSHCertificate, CertificateStatus

    ssh_key_count = SSHKey.query.filter_by(user_id=target.id, deleted_at=None).count()
    active_cert_count = SSHCertificate.query.filter_by(
        user_id=target.id, revoked=False
    ).filter(SSHCertificate.deleted_at == None).count()

    # ── Revoke all active SSH certificates before deletion ───────────────────
    active_certs = SSHCertificate.query.filter_by(
        user_id=target.id, revoked=False
    ).filter(SSHCertificate.deleted_at == None).all()
    for cert in active_certs:
        try:
            cert.revoke("account_deleted")
        except Exception:
            pass

    if active_certs:
        try:
            _db.session.flush()
        except Exception:
            pass

    # ── Hard delete ───────────────────────────────────────────────────────────
    target_email = target.email          # capture before deletion
    target_id_str = str(target.id)

    try:
        _db.session.delete(target)       # cascades to all child tables
        _db.session.flush()
    except Exception as exc:
        _db.session.rollback()
        import logging
        logging.getLogger(__name__).error(f"Hard delete failed for {target_id_str}: {exc}")
        return api_response(
            success=False,
            message="Failed to delete user account. Please try again.",
            status=500,
            error_type="SERVER_ERROR",
        )

    # ── Audit log (written as the caller so it survives the deletion) ─────────
    AuditService.log_action(
        action=AuditAction.USER_HARD_DELETE,
        user_id=caller.id,
        organization_id=admin_in_shared_org.organization_id,
        resource_type="user",
        resource_id=target_id_str,
        description=f"Admin permanently deleted user account: {target_email}",
        metadata={
            "deleted_user_id": target_id_str,
            "deleted_user_email": target_email,
            "ssh_keys_deleted": ssh_key_count,
            "certs_revoked": active_cert_count,
        },
    )

    _db.session.commit()

    return api_response(
        message=f"User account {target_email} has been permanently deleted.",
        data={
            "deleted_user_id": target_id_str,
            "deleted_user_email": target_email,
            "ssh_keys_deleted": ssh_key_count,
            "certs_revoked": active_cert_count,
        },
    )
