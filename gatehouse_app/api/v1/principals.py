"""Principal endpoints."""
from flask import g, request
from marshmallow import Schema, fields, validate, ValidationError

from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.utils.decorators import login_required, require_admin, full_access_required
from gatehouse_app.models import Principal, PrincipalMembership, Department, DepartmentPrincipal
from gatehouse_app.services.organization_service import OrganizationService
from gatehouse_app.services.user_service import UserService
from gatehouse_app.exceptions import OrganizationNotFoundError
from gatehouse_app.extensions import db


class PrincipalCreateSchema(Schema):
    """Schema for creating a principal."""
    name = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    description = fields.Str(allow_none=True, validate=validate.Length(max=2000))


class PrincipalUpdateSchema(Schema):
    """Schema for updating a principal."""
    name = fields.Str(validate=validate.Length(min=1, max=255))
    description = fields.Str(allow_none=True, validate=validate.Length(max=2000))


class AddPrincipalMemberSchema(Schema):
    """Schema for adding a member to a principal."""
    email = fields.Email(required=True)


class LinkPrincipalSchema(Schema):
    """Schema for linking principal to department."""
    department_id = fields.Str(required=True)


@api_v1_bp.route("/organizations/<org_id>/principals", methods=["GET"])
@login_required
@full_access_required
def list_principals(org_id):
    """
    List all principals in an organization.

    Args:
        org_id: Organization ID

    Returns:
        200: List of principals
        401: Not authenticated
        403: Not a member
        404: Organization not found
    """
    org = OrganizationService.get_organization_by_id(org_id)

    if not org.is_member(g.current_user.id):
        return api_response(
            success=False,
            message="You are not a member of this organization",
            status=403,
            error_type="AUTHORIZATION_ERROR",
        )

    principals = Principal.query.filter_by(
        organization_id=org_id,
        deleted_at=None
    ).all()

    return api_response(
        data={
            "principals": [p.to_dict() for p in principals],
            "count": len(principals),
        },
        message="Principals retrieved successfully",
    )


@api_v1_bp.route("/organizations/<org_id>/principals", methods=["POST"])
@login_required
@require_admin
@full_access_required
def create_principal(org_id):
    """
    Create a new principal.

    Args:
        org_id: Organization ID

    Request body:
        name: Principal name (required)
        description: Optional description

    Returns:
        201: Principal created successfully
        400: Validation error
        401: Not authenticated
        403: Not an admin
        404: Organization not found
        409: Principal name already exists
    """
    try:
        org = OrganizationService.get_organization_by_id(org_id)

        schema = PrincipalCreateSchema()
        data = schema.load(request.json or {})

        # Check if principal name already exists
        existing = Principal.query.filter_by(
            organization_id=org_id,
            name=data["name"],
            deleted_at=None
        ).first()

        if existing:
            return api_response(
                success=False,
                message=f"Principal '{data['name']}' already exists",
                status=409,
                error_type="CONFLICT",
            )

        # Create principal
        principal = Principal(
            organization_id=org_id,
            name=data["name"],
            description=data.get("description"),
        )
        db.session.add(principal)
        db.session.commit()

        return api_response(
            data={"principal": principal.to_dict()},
            message="Principal created successfully",
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


@api_v1_bp.route("/organizations/<org_id>/principals/<principal_id>", methods=["GET"])
@login_required
@full_access_required
def get_principal(org_id, principal_id):
    """
    Get a specific principal.

    Args:
        org_id: Organization ID
        principal_id: Principal ID

    Returns:
        200: Principal data
        401: Not authenticated
        403: Not a member
        404: Organization or principal not found
    """
    org = OrganizationService.get_organization_by_id(org_id)

    if not org.is_member(g.current_user.id):
        return api_response(
            success=False,
            message="You are not a member of this organization",
            status=403,
            error_type="AUTHORIZATION_ERROR",
        )

    principal = Principal.query.filter_by(
        id=principal_id,
        organization_id=org_id,
        deleted_at=None
    ).first()

    if not principal:
        return api_response(
            success=False,
            message="Principal not found",
            status=404,
            error_type="NOT_FOUND",
        )

    return api_response(
        data={"principal": principal.to_dict()},
        message="Principal retrieved successfully",
    )


@api_v1_bp.route("/organizations/<org_id>/principals/<principal_id>", methods=["PATCH"])
@login_required
@require_admin
@full_access_required
def update_principal(org_id, principal_id):
    """
    Update a principal.

    Args:
        org_id: Organization ID
        principal_id: Principal ID

    Request body:
        name: Optional new name
        description: Optional new description

    Returns:
        200: Principal updated successfully
        400: Validation error
        401: Not authenticated
        403: Not an admin
        404: Organization or principal not found
        409: Name already exists
    """
    try:
        org = OrganizationService.get_organization_by_id(org_id)

        principal = Principal.query.filter_by(
            id=principal_id,
            organization_id=org_id,
            deleted_at=None
        ).first()

        if not principal:
            return api_response(
                success=False,
                message="Principal not found",
                status=404,
                error_type="NOT_FOUND",
            )

        schema = PrincipalUpdateSchema()
        data = schema.load(request.json or {})

        # Check if new name already exists
        if "name" in data and data["name"] != principal.name:
            existing = Principal.query.filter_by(
                organization_id=org_id,
                name=data["name"],
                deleted_at=None
            ).first()
            if existing:
                return api_response(
                    success=False,
                    message=f"Principal '{data['name']}' already exists",
                    status=409,
                    error_type="CONFLICT",
                )

        # Update fields
        for key, value in data.items():
            setattr(principal, key, value)

        db.session.commit()

        return api_response(
            data={"principal": principal.to_dict()},
            message="Principal updated successfully",
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )


@api_v1_bp.route("/organizations/<org_id>/principals/<principal_id>", methods=["DELETE"])
@login_required
@require_admin
@full_access_required
def delete_principal(org_id, principal_id):
    """
    Delete a principal (soft delete).

    Args:
        org_id: Organization ID
        principal_id: Principal ID

    Returns:
        200: Principal deleted successfully
        401: Not authenticated
        403: Not an admin
        404: Organization or principal not found
    """
    org = OrganizationService.get_organization_by_id(org_id)

    principal = Principal.query.filter_by(
        id=principal_id,
        organization_id=org_id,
        deleted_at=None
    ).first()

    if not principal:
        return api_response(
            success=False,
            message="Principal not found",
            status=404,
            error_type="NOT_FOUND",
        )

    # Soft delete
    principal.deleted_at = db.func.now()
    db.session.commit()

    return api_response(
        message="Principal deleted successfully",
    )


@api_v1_bp.route("/organizations/<org_id>/principals/<principal_id>/members", methods=["GET"])
@login_required
@full_access_required
def get_principal_members(org_id, principal_id):
    """
    Get all members (direct + via department) with access to a principal.

    Args:
        org_id: Organization ID
        principal_id: Principal ID

    Returns:
        200: List of members
        401: Not authenticated
        403: Not a member
        404: Organization or principal not found
    """
    org = OrganizationService.get_organization_by_id(org_id)

    if not org.is_member(g.current_user.id):
        return api_response(
            success=False,
            message="You are not a member of this organization",
            status=403,
            error_type="AUTHORIZATION_ERROR",
        )

    principal = Principal.query.filter_by(
        id=principal_id,
        organization_id=org_id,
        deleted_at=None
    ).first()

    if not principal:
        return api_response(
            success=False,
            message="Principal not found",
            status=404,
            error_type="NOT_FOUND",
        )

    # Get direct members
    direct_members = PrincipalMembership.query.filter_by(
        principal_id=principal_id,
        deleted_at=None
    ).all()

    all_users = set()
    for membership in direct_members:
        if membership.user.deleted_at is None:
            all_users.add(membership.user)

    # Get members via departments
    dept_links = DepartmentPrincipal.query.filter_by(
        principal_id=principal_id,
        deleted_at=None
    ).all()

    for link in dept_links:
        dept = link.department
        if dept.deleted_at is None:
            dept_members = dept.get_members(active_only=True)
            for dept_member in dept_members:
                if dept_member.user.deleted_at is None:
                    all_users.add(dept_member.user)

    users_data = [u.to_dict() for u in all_users]

    return api_response(
        data={
            "members": users_data,
            "count": len(users_data),
        },
        message="Members retrieved successfully",
    )


@api_v1_bp.route("/organizations/<org_id>/principals/<principal_id>/members", methods=["POST"])
@login_required
@require_admin
@full_access_required
def add_principal_member(org_id, principal_id):
    """
    Add a direct member to a principal.

    Args:
        org_id: Organization ID
        principal_id: Principal ID

    Request body:
        email: User email to add

    Returns:
        201: Member added successfully
        400: Validation error
        401: Not authenticated
        403: Not an admin
        404: Organization, principal, or user not found
        409: User already a member
    """
    try:
        org = OrganizationService.get_organization_by_id(org_id)

        principal = Principal.query.filter_by(
            id=principal_id,
            organization_id=org_id,
            deleted_at=None
        ).first()

        if not principal:
            return api_response(
                success=False,
                message="Principal not found",
                status=404,
                error_type="NOT_FOUND",
            )

        schema = AddPrincipalMemberSchema()
        data = schema.load(request.json or {})

        # Find user by email
        user = UserService.get_user_by_email(data["email"])
        if not user:
            return api_response(
                success=False,
                message="User not found",
                status=404,
                error_type="NOT_FOUND",
            )

        # Check if already a member
        existing = PrincipalMembership.query.filter_by(
            user_id=user.id,
            principal_id=principal_id,
            deleted_at=None
        ).first()

        if existing:
            return api_response(
                success=False,
                message="User is already a member of this principal",
                status=409,
                error_type="CONFLICT",
            )

        soft_deleted = PrincipalMembership.query.filter(
            PrincipalMembership.user_id == user.id,
            PrincipalMembership.principal_id == principal_id,
            PrincipalMembership.deleted_at.isnot(None)
        ).first()

        if soft_deleted:
            soft_deleted.deleted_at = None
            membership = soft_deleted
        else:
            membership = PrincipalMembership(
                user_id=user.id,
                principal_id=principal_id,
            )
            db.session.add(membership)

        db.session.commit()

        member_dict = membership.to_dict()
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


@api_v1_bp.route("/organizations/<org_id>/principals/<principal_id>/members/<user_id>", methods=["DELETE"])
@login_required
@require_admin
@full_access_required
def remove_principal_member(org_id, principal_id, user_id):
    """
    Remove a direct member from a principal.

    Args:
        org_id: Organization ID
        principal_id: Principal ID
        user_id: User ID to remove

    Returns:
        200: Member removed successfully
        401: Not authenticated
        403: Not an admin
        404: Organization, principal, or member not found
    """
    org = OrganizationService.get_organization_by_id(org_id)

    principal = Principal.query.filter_by(
        id=principal_id,
        organization_id=org_id,
        deleted_at=None
    ).first()

    if not principal:
        return api_response(
            success=False,
            message="Principal not found",
            status=404,
            error_type="NOT_FOUND",
        )

    membership = PrincipalMembership.query.filter_by(
        user_id=user_id,
        principal_id=principal_id,
        deleted_at=None
    ).first()

    if not membership:
        return api_response(
            success=False,
            message="User is not a member of this principal",
            status=404,
            error_type="NOT_FOUND",
        )

    # Soft delete
    membership.deleted_at = db.func.now()
    db.session.commit()

    return api_response(
        message="Member removed successfully",
    )


@api_v1_bp.route("/organizations/<org_id>/principals/<principal_id>/departments", methods=["GET"])
@login_required
@full_access_required
def get_principal_departments(org_id, principal_id):
    """
    Get all departments this principal is assigned to.

    Args:
        org_id: Organization ID
        principal_id: Principal ID

    Returns:
        200: List of departments
        401: Not authenticated
        403: Not a member
        404: Organization or principal not found
    """
    org = OrganizationService.get_organization_by_id(org_id)

    if not org.is_member(g.current_user.id):
        return api_response(
            success=False,
            message="You are not a member of this organization",
            status=403,
            error_type="AUTHORIZATION_ERROR",
        )

    principal = Principal.query.filter_by(
        id=principal_id,
        organization_id=org_id,
        deleted_at=None
    ).first()

    if not principal:
        return api_response(
            success=False,
            message="Principal not found",
            status=404,
            error_type="NOT_FOUND",
        )

    depts = principal.get_departments(active_only=True)

    return api_response(
        data={
            "departments": [d.to_dict() for d in depts],
            "count": len(depts),
        },
        message="Departments retrieved successfully",
    )


@api_v1_bp.route("/organizations/<org_id>/principals/<principal_id>/departments/<dept_id>", methods=["POST"])
@login_required
@require_admin
@full_access_required
def link_principal_to_department(org_id, principal_id, dept_id):
    """
    Link a principal to a department.

    Args:
        org_id: Organization ID
        principal_id: Principal ID
        dept_id: Department ID

    Returns:
        201: Principal linked successfully
        401: Not authenticated
        403: Not an admin
        404: Organization, principal, or department not found
        409: Already linked
    """
    try:
        org = OrganizationService.get_organization_by_id(org_id)
    except OrganizationNotFoundError:
        return api_response(success=False, message="Organization not found", status=404, error_type="NOT_FOUND")

    principal = Principal.query.filter_by(
        id=principal_id,
        organization_id=org_id,
        deleted_at=None
    ).first()

    if not principal:
        return api_response(
            success=False,
            message="Principal not found",
            status=404,
            error_type="NOT_FOUND",
        )

    dept = Department.query.filter_by(
        id=dept_id,
        organization_id=org_id,
        deleted_at=None
    ).first()

    if not dept:
        return api_response(
            success=False,
            message="Department not found",
            status=404,
            error_type="NOT_FOUND",
        )

    existing = DepartmentPrincipal.query.filter_by(
        department_id=dept_id,
        principal_id=principal_id,
        deleted_at=None
    ).first()

    if existing:
        return api_response(
            success=False,
            message="Principal is already linked to this department",
            status=409,
            error_type="CONFLICT",
        )

    soft_deleted = DepartmentPrincipal.query.filter(
        DepartmentPrincipal.department_id == dept_id,
        DepartmentPrincipal.principal_id == principal_id,
        DepartmentPrincipal.deleted_at.isnot(None),
    ).first()

    try:
        if soft_deleted:
            soft_deleted.deleted_at = None
        else:
            link = DepartmentPrincipal(
                department_id=dept_id,
                principal_id=principal_id,
            )
            db.session.add(link)
        db.session.commit()
    except Exception:
        db.session.rollback()
        return api_response(
            success=False,
            message="Failed to link principal to department",
            status=500,
            error_type="SERVER_ERROR",
        )

    return api_response(
        data={
            "principal": principal.to_dict(),
            "department": dept.to_dict(),
        },
        message="Principal linked to department successfully",
        status=201,
    )


@api_v1_bp.route("/organizations/<org_id>/principals/<principal_id>/departments/<dept_id>", methods=["DELETE"])
@login_required
@require_admin
@full_access_required
def unlink_principal_from_department(org_id, principal_id, dept_id):
    """
    Unlink a principal from a department.

    Args:
        org_id: Organization ID
        principal_id: Principal ID
        dept_id: Department ID

    Returns:
        200: Principal unlinked successfully
        401: Not authenticated
        403: Not an admin
        404: Organization, principal, department, or link not found
    """
    org = OrganizationService.get_organization_by_id(org_id)

    principal = Principal.query.filter_by(
        id=principal_id,
        organization_id=org_id,
        deleted_at=None
    ).first()

    if not principal:
        return api_response(
            success=False,
            message="Principal not found",
            status=404,
            error_type="NOT_FOUND",
        )

    dept = Department.query.filter_by(
        id=dept_id,
        organization_id=org_id,
        deleted_at=None
    ).first()

    if not dept:
        return api_response(
            success=False,
            message="Department not found",
            status=404,
            error_type="NOT_FOUND",
        )

    link = DepartmentPrincipal.query.filter_by(
        department_id=dept_id,
        principal_id=principal_id,
        deleted_at=None
    ).first()

    if not link:
        return api_response(
            success=False,
            message="Principal is not linked to this department",
            status=404,
            error_type="NOT_FOUND",
        )

    # Soft delete
    link.deleted_at = db.func.now()
    db.session.commit()

    return api_response(
        message="Principal unlinked from department successfully",
    )
