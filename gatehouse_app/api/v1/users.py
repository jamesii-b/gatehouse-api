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

    Returns:
        200: Account deleted successfully
        401: Not authenticated
    """
    UserService.delete_user(g.current_user, soft=True)

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
    Get all organizations current user is a member of.

    Returns:
        200: List of organizations
        401: Not authenticated
    """
    organizations = UserService.get_user_organizations(g.current_user)

    return api_response(
        data={
            "organizations": [org.to_dict() for org in organizations],
            "count": len(organizations),
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
    from gatehouse_app.models.organization_member import OrganizationMember
    from gatehouse_app.models.principal import Principal, PrincipalMembership
    from gatehouse_app.models.department import DepartmentMembership, DepartmentPrincipal
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
        effective_principal_ids = set()

        # Direct memberships
        direct = PrincipalMembership.query.filter_by(
            user_id=user_id,
            deleted_at=None,
        ).all()
        for pm in direct:
            if pm.principal and pm.principal.organization_id == org.id and pm.principal.deleted_at is None:
                effective_principal_ids.add(pm.principal_id)

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
                        effective_principal_ids.add(dp.principal_id)

        # Fetch principal objects
        my_principals = []
        if effective_principal_ids:
            my_p = Principal.query.filter(
                Principal.id.in_(list(effective_principal_ids)),
                Principal.deleted_at == None,
            ).all()
            my_principals = [{"id": p.id, "name": p.name, "description": p.description} for p in my_p]

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
    from gatehouse_app.models.organization_member import OrganizationMember
    from gatehouse_app.models.user import User as _User
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
def admin_get_user(user_id):
    """Get a single user's profile (admin view with SSH keys)."""
    from gatehouse_app.models.organization_member import OrganizationMember
    from gatehouse_app.models.user import User as _User
    from gatehouse_app.models.ssh_key import SSHKey

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
