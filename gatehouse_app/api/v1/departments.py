"""Department endpoints."""
from flask import g, request
from marshmallow import Schema, fields, validate, ValidationError

from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.utils.decorators import login_required, require_admin, full_access_required
from gatehouse_app.models import Department, DepartmentMembership
from gatehouse_app.services.organization_service import OrganizationService
from gatehouse_app.services.user_service import UserService
from gatehouse_app.extensions import db


class DepartmentCreateSchema(Schema):
    """Schema for creating a department."""
    name = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    description = fields.Str(allow_none=True, validate=validate.Length(max=2000))


class DepartmentUpdateSchema(Schema):
    """Schema for updating a department."""
    name = fields.Str(validate=validate.Length(min=1, max=255))
    description = fields.Str(allow_none=True, validate=validate.Length(max=2000))


class AddDepartmentMemberSchema(Schema):
    """Schema for adding a member to a department."""
    email = fields.Email(required=True)


@api_v1_bp.route("/organizations/<org_id>/departments", methods=["GET"])
@login_required
@full_access_required
def list_departments(org_id):
    """
    List all departments in an organization.

    Args:
        org_id: Organization ID

    Returns:
        200: List of departments
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

    departments = Department.query.filter_by(
        organization_id=org_id,
        deleted_at=None
    ).all()

    return api_response(
        data={
            "departments": [d.to_dict() for d in departments],
            "count": len(departments),
        },
        message="Departments retrieved successfully",
    )


@api_v1_bp.route("/organizations/<org_id>/departments", methods=["POST"])
@login_required
@require_admin
@full_access_required
def create_department(org_id):
    """
    Create a new department.

    Args:
        org_id: Organization ID

    Request body:
        name: Department name (required)
        description: Optional description

    Returns:
        201: Department created successfully
        400: Validation error
        401: Not authenticated
        403: Not an admin
        404: Organization not found
        409: Department name already exists in org
    """
    try:
        org = OrganizationService.get_organization_by_id(org_id)

        schema = DepartmentCreateSchema()
        data = schema.load(request.json or {})

        # Check if department name already exists
        existing = Department.query.filter_by(
            organization_id=org_id,
            name=data["name"],
            deleted_at=None
        ).first()

        if existing:
            return api_response(
                success=False,
                message=f"Department '{data['name']}' already exists in this organization",
                status=409,
                error_type="CONFLICT",
            )

        # Create department
        dept = Department(
            organization_id=org_id,
            name=data["name"],
            description=data.get("description"),
        )
        db.session.add(dept)
        db.session.commit()

        return api_response(
            data={"department": dept.to_dict()},
            message="Department created successfully",
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


@api_v1_bp.route("/organizations/<org_id>/departments/<dept_id>", methods=["GET"])
@login_required
@full_access_required
def get_department(org_id, dept_id):
    """
    Get a specific department.

    Args:
        org_id: Organization ID
        dept_id: Department ID

    Returns:
        200: Department data
        401: Not authenticated
        403: Not a member
        404: Organization or department not found
    """
    org = OrganizationService.get_organization_by_id(org_id)

    if not org.is_member(g.current_user.id):
        return api_response(
            success=False,
            message="You are not a member of this organization",
            status=403,
            error_type="AUTHORIZATION_ERROR",
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

    return api_response(
        data={"department": dept.to_dict()},
        message="Department retrieved successfully",
    )


@api_v1_bp.route("/organizations/<org_id>/departments/<dept_id>", methods=["PATCH"])
@login_required
@require_admin
@full_access_required
def update_department(org_id, dept_id):
    """
    Update a department.

    Args:
        org_id: Organization ID
        dept_id: Department ID

    Request body:
        name: Optional new name
        description: Optional new description

    Returns:
        200: Department updated successfully
        400: Validation error
        401: Not authenticated
        403: Not an admin
        404: Organization or department not found
        409: Name already exists
    """
    try:
        org = OrganizationService.get_organization_by_id(org_id)

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

        schema = DepartmentUpdateSchema()
        data = schema.load(request.json or {})

        # Check if new name already exists
        if "name" in data and data["name"] != dept.name:
            existing = Department.query.filter_by(
                organization_id=org_id,
                name=data["name"],
                deleted_at=None
            ).first()
            if existing:
                return api_response(
                    success=False,
                    message=f"Department '{data['name']}' already exists",
                    status=409,
                    error_type="CONFLICT",
                )

        # Update fields
        for key, value in data.items():
            setattr(dept, key, value)

        db.session.commit()

        return api_response(
            data={"department": dept.to_dict()},
            message="Department updated successfully",
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )


@api_v1_bp.route("/organizations/<org_id>/departments/<dept_id>", methods=["DELETE"])
@login_required
@require_admin
@full_access_required
def delete_department(org_id, dept_id):
    """
    Delete a department (soft delete).

    Args:
        org_id: Organization ID
        dept_id: Department ID

    Returns:
        200: Department deleted successfully
        401: Not authenticated
        403: Not an admin
        404: Organization or department not found
    """
    org = OrganizationService.get_organization_by_id(org_id)

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

    # Soft delete
    dept.deleted_at = db.func.now()
    db.session.commit()

    return api_response(
        message="Department deleted successfully",
    )


@api_v1_bp.route("/organizations/<org_id>/departments/<dept_id>/members", methods=["GET"])
@login_required
@full_access_required
def get_department_members(org_id, dept_id):
    """
    Get all members of a department.

    Args:
        org_id: Organization ID
        dept_id: Department ID

    Returns:
        200: List of members
        401: Not authenticated
        403: Not a member
        404: Organization or department not found
    """
    org = OrganizationService.get_organization_by_id(org_id)

    if not org.is_member(g.current_user.id):
        return api_response(
            success=False,
            message="You are not a member of this organization",
            status=403,
            error_type="AUTHORIZATION_ERROR",
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

    members = DepartmentMembership.query.filter_by(
        department_id=dept_id,
        deleted_at=None
    ).all()

    members_data = []
    for member in members:
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


@api_v1_bp.route("/organizations/<org_id>/departments/<dept_id>/members", methods=["POST"])
@login_required
@require_admin
@full_access_required
def add_department_member(org_id, dept_id):
    """
    Add a member to a department.

    Args:
        org_id: Organization ID
        dept_id: Department ID

    Request body:
        email: User email to add

    Returns:
        201: Member added successfully
        400: Validation error
        401: Not authenticated
        403: Not an admin
        404: Organization, department, or user not found
        409: User already a member
    """
    try:
        org = OrganizationService.get_organization_by_id(org_id)

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

        schema = AddDepartmentMemberSchema()
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
        existing = DepartmentMembership.query.filter_by(
            user_id=user.id,
            department_id=dept_id,
            deleted_at=None
        ).first()

        if existing:
            return api_response(
                success=False,
                message="User is already a member of this department",
                status=409,
                error_type="CONFLICT",
            )

        # Add member
        membership = DepartmentMembership(
            user_id=user.id,
            department_id=dept_id,
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


@api_v1_bp.route("/organizations/<org_id>/departments/<dept_id>/members/<user_id>", methods=["DELETE"])
@login_required
@require_admin
@full_access_required
def remove_department_member(org_id, dept_id, user_id):
    """
    Remove a member from a department.

    Args:
        org_id: Organization ID
        dept_id: Department ID
        user_id: User ID to remove

    Returns:
        200: Member removed successfully
        401: Not authenticated
        403: Not an admin
        404: Organization, department, or member not found
    """
    org = OrganizationService.get_organization_by_id(org_id)

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

    membership = DepartmentMembership.query.filter_by(
        user_id=user_id,
        department_id=dept_id,
        deleted_at=None
    ).first()

    if not membership:
        return api_response(
            success=False,
            message="User is not a member of this department",
            status=404,
            error_type="NOT_FOUND",
        )

    # Soft delete
    membership.deleted_at = db.func.now()
    db.session.commit()

    return api_response(
        message="Member removed successfully",
    )


@api_v1_bp.route("/organizations/<org_id>/departments/<dept_id>/principals", methods=["GET"])
@login_required
@full_access_required
def get_department_principals(org_id, dept_id):
    """Get all principals linked to a department."""
    org = OrganizationService.get_organization_by_id(org_id)

    if not org.is_member(g.current_user.id):
        return api_response(
            success=False,
            message="You are not a member of this organization",
            status=403,
            error_type="AUTHORIZATION_ERROR",
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

    principals = dept.get_principals(active_only=True)

    return api_response(
        data={
            "principals": [p.to_dict() for p in principals],
            "count": len(principals),
        },
        message="Principals retrieved successfully",
    )
