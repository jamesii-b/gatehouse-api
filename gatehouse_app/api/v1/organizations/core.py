"""Organization core CRUD endpoints."""
from flask import g, request
from marshmallow import ValidationError
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.utils.decorators import login_required, require_admin, full_access_required
from gatehouse_app.schemas.organization_schema import OrganizationCreateSchema, OrganizationUpdateSchema
from gatehouse_app.services.organization_service import OrganizationService


@api_v1_bp.route("/organizations", methods=["POST"])
@login_required
@full_access_required
def create_organization():
    try:
        schema = OrganizationCreateSchema()
        data = schema.load(request.json)
        org = OrganizationService.create_organization(
            name=data["name"],
            slug=data["slug"],
            owner_user_id=g.current_user.id,
            description=data.get("description"),
            logo_url=data.get("logo_url"),
        )
        return api_response(data={"organization": org.to_dict()}, message="Organization created successfully", status=201)
    except ValidationError as e:
        return api_response(success=False, message="Validation failed", status=400, error_type="VALIDATION_ERROR", error_details=e.messages)


@api_v1_bp.route("/organizations/<org_id>", methods=["GET"])
@login_required
@full_access_required
def get_organization(org_id):
    org = OrganizationService.get_organization_by_id(org_id)
    if not org.is_member(g.current_user.id):
        return api_response(success=False, message="You are not a member of this organization", status=403, error_type="AUTHORIZATION_ERROR")
    return api_response(
        data={"organization": org.to_dict(), "member_count": org.get_member_count()},
        message="Organization retrieved successfully",
    )


@api_v1_bp.route("/organizations/<org_id>", methods=["PATCH"])
@login_required
@require_admin
@full_access_required
def update_organization(org_id):
    try:
        schema = OrganizationUpdateSchema()
        data = schema.load(request.json)
        org = OrganizationService.get_organization_by_id(org_id)
        org = OrganizationService.update_organization(org=org, user_id=g.current_user.id, **data)
        return api_response(data={"organization": org.to_dict()}, message="Organization updated successfully")
    except ValidationError as e:
        return api_response(success=False, message="Validation failed", status=400, error_type="VALIDATION_ERROR", error_details=e.messages)


@api_v1_bp.route("/organizations/<org_id>", methods=["DELETE"])
@login_required
@full_access_required
def delete_organization(org_id):
    from gatehouse_app.models.organization.organization_member import OrganizationMember as _OrgMember
    from gatehouse_app.utils.constants import OrganizationRole as _OrgRole

    caller = g.current_user
    org = OrganizationService.get_organization_by_id(org_id)

    caller_membership = _OrgMember.query.filter_by(user_id=caller.id, organization_id=org.id, deleted_at=None).first()
    if not caller_membership or caller_membership.role != _OrgRole.OWNER:
        return api_response(success=False, message="Only the organization owner can delete the organization.", status=403, error_type="AUTHORIZATION_ERROR")

    active_member_count = org.get_member_count()
    if active_member_count > 1:
        data = request.get_json(silent=True) or {}
        if not data.get("confirm"):
            return api_response(
                success=False,
                message=(f"This organization has {active_member_count} active members. Deleting it will remove all members and their data. Send {{\"confirm\": true}} to confirm."),
                status=400,
                error_type="CONFIRMATION_REQUIRED",
                error_details={"member_count": active_member_count},
            )

    OrganizationService.force_delete_organization(org=org, user_id=caller.id)
    return api_response(message="Organization deleted successfully")
