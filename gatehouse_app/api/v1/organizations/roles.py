"""Organization role management endpoints."""
from flask import g, request
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.utils.decorators import login_required, require_admin, full_access_required
from gatehouse_app.utils.constants import OrganizationRole
from gatehouse_app.extensions import db


@api_v1_bp.route("/organizations/<org_id>/roles", methods=["GET"])
@login_required
def list_organization_roles(org_id):
    from gatehouse_app.models.organization.organization import Organization
    from gatehouse_app.models.organization.organization_member import OrganizationMember

    org = Organization.query.filter_by(id=org_id, deleted_at=None).first()
    if not org:
        return api_response(success=False, message="Organization not found", status=404, error_type="NOT_FOUND")

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
        {"role": r.value, "member_count": len(by_role[r.value]), "members": by_role[r.value]}
        for r in OrganizationRole
    ]
    return api_response(data={"roles": roles, "organization_id": org_id}, message="Roles retrieved")


@api_v1_bp.route("/organizations/<org_id>/roles/<role_name>/members", methods=["POST"])
@login_required
@require_admin
def assign_role_to_member(org_id, role_name):
    from gatehouse_app.models.organization.organization_member import OrganizationMember

    try:
        new_role = OrganizationRole(role_name.lower())
    except ValueError:
        valid = [r.value for r in OrganizationRole]
        return api_response(success=False, message=f"Invalid role. Must be one of: {valid}", status=400, error_type="VALIDATION_ERROR")

    data = request.get_json() or {}
    target_user_id = data.get("user_id")
    if not target_user_id:
        return api_response(success=False, message="user_id is required", status=400, error_type="VALIDATION_ERROR")

    membership = OrganizationMember.query.filter_by(organization_id=org_id, user_id=target_user_id, deleted_at=None).first()
    if not membership:
        return api_response(success=False, message="Member not found in this organization", status=404, error_type="NOT_FOUND")

    membership.role = new_role
    db.session.commit()
    return api_response(data={"user_id": target_user_id, "role": new_role.value}, message=f"Role updated to {new_role.value}")


@api_v1_bp.route("/organizations/<org_id>/roles/<role_name>/members/<user_id>", methods=["DELETE"])
@login_required
@require_admin
@full_access_required
def remove_role_from_member(org_id, role_name, user_id):
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.services.organization_service import OrganizationService

    try:
        OrganizationRole(role_name.lower())
    except ValueError:
        valid = [r.value for r in OrganizationRole]
        return api_response(success=False, message=f"Invalid role. Must be one of: {valid}", status=400, error_type="VALIDATION_ERROR")

    membership = OrganizationMember.query.filter_by(organization_id=org_id, user_id=user_id, deleted_at=None).first()
    if not membership:
        return api_response(success=False, message="Member not found in this organization", status=404, error_type="NOT_FOUND")

    org = OrganizationService.get_organization_by_id(org_id)
    OrganizationService.remove_member(org=org, user_id=user_id, remover_id=g.current_user.id)
    return api_response(data={"user_id": user_id}, message="Member removed from organization")
