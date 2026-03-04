"""Current user (self-service) endpoints."""
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
    from gatehouse_app.models.auth.authentication_method import AuthenticationMethod
    from gatehouse_app.utils.constants import AuthMethodType

    user = g.current_user
    user_dict = user.to_dict()

    OAUTH_TYPES = {
        AuthMethodType.GOOGLE, AuthMethodType.GITHUB,
        AuthMethodType.MICROSOFT, AuthMethodType.OIDC,
    }
    auth_methods = AuthenticationMethod.query.filter_by(user_id=user.id, deleted_at=None).all()

    has_password = any(m.method_type == AuthMethodType.PASSWORD and m.password_hash for m in auth_methods)
    totp_enabled = any(m.method_type == AuthMethodType.TOTP and m.verified for m in auth_methods)
    linked_providers = [m.method_type.value for m in auth_methods if m.method_type in OAUTH_TYPES]

    user_dict["has_password"] = has_password
    user_dict["totp_enabled"] = totp_enabled
    user_dict["linked_providers"] = linked_providers

    return api_response(data={"user": user_dict}, message="User profile retrieved successfully")


@api_v1_bp.route("/users/me", methods=["PATCH"])
@login_required
@full_access_required
def update_me():
    try:
        schema = UserUpdateSchema()
        data = schema.load(request.json)
        user = UserService.update_user(g.current_user, **data)
        return api_response(data={"user": user.to_dict()}, message="Profile updated successfully")
    except ValidationError as e:
        return api_response(success=False, message="Validation failed", status=400, error_type="VALIDATION_ERROR", error_details=e.messages)


@api_v1_bp.route("/users/me", methods=["DELETE"])
@login_required
@full_access_required
def delete_me():
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.utils.constants import OrganizationRole
    from gatehouse_app.services.organization_service import OrganizationService

    user = g.current_user

    owned_memberships = OrganizationMember.query.filter_by(
        user_id=user.id, role=OrganizationRole.OWNER, deleted_at=None,
    ).all()

    transfer_needed = []
    auto_delete = []

    for membership in owned_memberships:
        org = membership.organization
        if org.deleted_at is not None:
            continue
        if org.get_member_count() > 1:
            transfer_needed.append(org.name)
        else:
            auto_delete.append(org)

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

    for org in auto_delete:
        OrganizationService.force_delete_organization(org, user_id=user.id)

    UserService.delete_user(user, soft=True)
    return api_response(message="Account deleted successfully")


@api_v1_bp.route("/users/me/password", methods=["POST"])
@login_required
@full_access_required
def change_password():
    try:
        schema = ChangePasswordSchema()
        data = schema.load(request.json)

        if data["new_password"] != data["new_password_confirm"]:
            return api_response(
                success=False, message="New passwords do not match", status=400,
                error_type="VALIDATION_ERROR",
                error_details={"new_password_confirm": ["Passwords do not match"]},
            )

        AuthService.change_password(
            user=g.current_user,
            current_password=data["current_password"],
            new_password=data["new_password"],
        )
        return api_response(message="Password changed successfully")
    except ValidationError as e:
        return api_response(success=False, message="Validation failed", status=400, error_type="VALIDATION_ERROR", error_details=e.messages)


@api_v1_bp.route("/users/me/organizations", methods=["GET"])
@login_required
@full_access_required
def get_my_organizations():
    from gatehouse_app.models.organization.organization_member import OrganizationMember

    user = g.current_user
    memberships = OrganizationMember.query.filter_by(user_id=user.id, deleted_at=None).all()

    orgs = []
    for membership in memberships:
        org = membership.organization
        if not org or org.deleted_at is not None:
            continue
        org_dict = org.to_dict()
        org_dict["role"] = membership.role.value if hasattr(membership.role, "value") else str(membership.role)
        orgs.append(org_dict)

    return api_response(data={"organizations": orgs, "count": len(orgs)}, message="Organizations retrieved successfully")


@api_v1_bp.route("/users/me/principals", methods=["GET"])
@login_required
@full_access_required
def get_my_principals():
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.models.organization.principal import Principal, PrincipalMembership
    from gatehouse_app.models.organization.department import DepartmentMembership, DepartmentPrincipal
    from gatehouse_app.utils.constants import OrganizationRole

    user = g.current_user
    user_id = user.id

    memberships = OrganizationMember.query.filter_by(user_id=user_id, deleted_at=None).all()

    orgs_result = []
    for membership in memberships:
        org = membership.organization
        if not org or org.deleted_at is not None:
            continue

        role = membership.role
        is_admin = role in (OrganizationRole.ADMIN, OrganizationRole.OWNER)

        direct_principal_ids = set()
        via_dept_principal_ids = set()

        for pm in PrincipalMembership.query.filter_by(user_id=user_id, deleted_at=None).all():
            if pm.principal and pm.principal.organization_id == org.id and pm.principal.deleted_at is None:
                direct_principal_ids.add(pm.principal_id)

        for dm in DepartmentMembership.query.filter_by(user_id=user_id, deleted_at=None).all():
            if dm.department and dm.department.organization_id == org.id and dm.department.deleted_at is None:
                for dp in DepartmentPrincipal.query.filter_by(department_id=dm.department_id, deleted_at=None).all():
                    if dp.principal and dp.principal.deleted_at is None:
                        via_dept_principal_ids.add(dp.principal_id)

        effective_principal_ids = direct_principal_ids | via_dept_principal_ids

        my_principals = []
        if effective_principal_ids:
            for p in Principal.query.filter(
                Principal.id.in_(list(effective_principal_ids)),
                Principal.deleted_at == None,
            ).all():
                my_principals.append({
                    "id": p.id, "name": p.name, "description": p.description,
                    "direct": p.id in direct_principal_ids,
                })

        all_principals = []
        if is_admin:
            for p in Principal.query.filter_by(organization_id=org.id, deleted_at=None).all():
                all_principals.append({"id": p.id, "name": p.name, "description": p.description})

        orgs_result.append({
            "org_id": org.id, "org_name": org.name,
            "role": role.value if hasattr(role, "value") else role,
            "is_admin": is_admin,
            "my_principals": my_principals,
            "all_principals": all_principals,
        })

    return api_response(data={"orgs": orgs_result}, message="Principals retrieved successfully")


@api_v1_bp.route("/users/me/invites", methods=["GET"])
@login_required
def get_my_pending_invites():
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
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.models.organization.department import DepartmentMembership, DepartmentPrincipal, Department
    from gatehouse_app.models.organization.principal import Principal, PrincipalMembership

    user = g.current_user

    memberships = OrganizationMember.query.filter_by(user_id=user.id, deleted_at=None).all()

    orgs_result = []
    for membership in memberships:
        org = membership.organization
        if not org or org.deleted_at is not None:
            continue

        dept_memberships = DepartmentMembership.query.filter_by(user_id=user.id, deleted_at=None).all()
        user_depts = [
            dm.department for dm in dept_memberships
            if dm.department
            and dm.department.organization_id == org.id
            and dm.department.deleted_at is None
        ]

        direct_pm = PrincipalMembership.query.filter_by(user_id=user.id, deleted_at=None).all()
        direct_principal_ids = {
            pm.principal_id for pm in direct_pm
            if pm.principal and pm.principal.organization_id == org.id and pm.principal.deleted_at is None
        }

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
                    "id": str(p.id), "name": p.name, "description": p.description,
                    "via_department": p.id not in direct_principal_ids,
                })

        role = membership.role
        orgs_result.append({
            "org_id": str(org.id), "org_name": org.name,
            "role": role.value if hasattr(role, "value") else role,
            "departments": [{"id": str(d.id), "name": d.name, "description": d.description} for d in user_depts],
            "principals": principals_list,
        })

    return api_response(data={"orgs": orgs_result}, message="Memberships retrieved")
