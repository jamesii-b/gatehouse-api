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

########jb- need to implement departs, principals
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
