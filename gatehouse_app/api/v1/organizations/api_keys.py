"""Organization API Key management endpoints."""
from flask import g, request
from marshmallow import Schema, fields, validate, ValidationError

from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.utils.decorators import login_required, require_admin, full_access_required
from gatehouse_app.models.organization import OrganizationApiKey
from gatehouse_app.services.organization_service import OrganizationService
from gatehouse_app.extensions import db


class ApiKeyCreateSchema(Schema):
    """Schema for creating an API key."""
    name = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    description = fields.Str(allow_none=True, validate=validate.Length(max=2000))


class ApiKeyUpdateSchema(Schema):
    """Schema for updating an API key."""
    name = fields.Str(validate=validate.Length(min=1, max=255))
    description = fields.Str(allow_none=True, validate=validate.Length(max=2000))


@api_v1_bp.route("/organizations/<org_id>/api-keys", methods=["GET"])
@login_required
@require_admin
@full_access_required
def list_api_keys(org_id):
    """
    List all API keys for an organization.
    
    Only accessible by organization admins.
    
    Args:
        org_id: Organization ID
    
    Returns:
        200: List of API keys (without key values)
        401: Not authenticated
        403: Not an admin
        404: Organization not found
    """
    org = OrganizationService.get_organization_by_id(org_id)
    
    # Check if user is an admin
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.utils.constants import OrganizationRole
    
    membership = OrganizationMember.query.filter_by(
        user_id=g.current_user.id,
        organization_id=org_id,
        deleted_at=None
    ).first()
    
    if not membership or membership.role not in [OrganizationRole.OWNER, OrganizationRole.ADMIN]:
        return api_response(
            success=False,
            message="You do not have permission to manage API keys",
            status=403,
            error_type="AUTHORIZATION_ERROR",
        )
    
    api_keys = OrganizationApiKey.query.filter_by(
        organization_id=org_id,
        deleted_at=None
    ).all()
    
    return api_response(
        data={
            "api_keys": [k.to_dict() for k in api_keys],
            "count": len(api_keys),
        },
        message="API keys retrieved successfully",
    )


@api_v1_bp.route("/organizations/<org_id>/api-keys", methods=["POST"])
@login_required
@require_admin
@full_access_required
def create_api_key(org_id):
    """
    Create a new API key for an organization.
    
    Only accessible by organization admins.
    The plain text key is returned only on creation and should be stored securely.
    
    Args:
        org_id: Organization ID
    
    Request body:
        name: API key name (required)
        description: Optional description
    
    Returns:
        201: API key created successfully
        400: Validation error
        401: Not authenticated
        403: Not an admin
        404: Organization not found
    """
    try:
        org = OrganizationService.get_organization_by_id(org_id)
        
        # Check if user is an admin
        from gatehouse_app.models.organization.organization_member import OrganizationMember
        from gatehouse_app.utils.constants import OrganizationRole
        
        membership = OrganizationMember.query.filter_by(
            user_id=g.current_user.id,
            organization_id=org_id,
            deleted_at=None
        ).first()
        
        if not membership or membership.role not in [OrganizationRole.OWNER, OrganizationRole.ADMIN]:
            return api_response(
                success=False,
                message="You do not have permission to create API keys",
                status=403,
                error_type="AUTHORIZATION_ERROR",
            )
        
        schema = ApiKeyCreateSchema()
        data = schema.load(request.json or {})
        
        # Create the API key
        api_key, plain_key = OrganizationApiKey.create_key(
            organization_id=org_id,
            name=data["name"],
            description=data.get("description"),
        )
        
        # Return the key data with the plain text key (only on creation)
        key_dict = api_key.to_dict()
        key_dict["key"] = plain_key  # Include plain text only on creation
        
        return api_response(
            data={"api_key": key_dict},
            message="API key created successfully. Store the key value securely - it cannot be retrieved later.",
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


@api_v1_bp.route("/organizations/<org_id>/api-keys/<key_id>", methods=["PATCH"])
@login_required
@require_admin
@full_access_required
def update_api_key(org_id, key_id):
    """
    Update an API key.
    
    Only accessible by organization admins.
    
    Args:
        org_id: Organization ID
        key_id: API Key ID
    
    Request body:
        name: New name (optional)
        description: New description (optional)
    
    Returns:
        200: API key updated successfully
        400: Validation error
        401: Not authenticated
        403: Not an admin
        404: Organization or API key not found
    """
    try:
        org = OrganizationService.get_organization_by_id(org_id)
        
        # Check if user is an admin
        from gatehouse_app.models.organization.organization_member import OrganizationMember
        from gatehouse_app.utils.constants import OrganizationRole
        
        membership = OrganizationMember.query.filter_by(
            user_id=g.current_user.id,
            organization_id=org_id,
            deleted_at=None
        ).first()
        
        if not membership or membership.role not in [OrganizationRole.OWNER, OrganizationRole.ADMIN]:
            return api_response(
                success=False,
                message="You do not have permission to update API keys",
                status=403,
                error_type="AUTHORIZATION_ERROR",
            )
        
        api_key = OrganizationApiKey.query.filter_by(
            id=key_id,
            organization_id=org_id,
            deleted_at=None
        ).first()
        
        if not api_key:
            return api_response(
                success=False,
                message="API key not found",
                status=404,
                error_type="NOT_FOUND",
            )
        
        schema = ApiKeyUpdateSchema()
        data = schema.load(request.json or {})
        
        # Update fields
        if "name" in data:
            api_key.name = data["name"]
        if "description" in data:
            api_key.description = data["description"]
        
        api_key.save()
        
        return api_response(
            data={"api_key": api_key.to_dict()},
            message="API key updated successfully",
        )
    
    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )


@api_v1_bp.route("/organizations/<org_id>/api-keys/<key_id>", methods=["DELETE"])
@login_required
@require_admin
@full_access_required
def delete_api_key(org_id, key_id):
    """
    Delete/revoke an API key.
    
    Only accessible by organization admins.
    
    Args:
        org_id: Organization ID
        key_id: API Key ID
    
    Returns:
        200: API key deleted successfully
        401: Not authenticated
        403: Not an admin
        404: Organization or API key not found
    """
    org = OrganizationService.get_organization_by_id(org_id)
    
    # Check if user is an admin
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.utils.constants import OrganizationRole
    
    membership = OrganizationMember.query.filter_by(
        user_id=g.current_user.id,
        organization_id=org_id,
        deleted_at=None
    ).first()
    
    if not membership or membership.role not in [OrganizationRole.OWNER, OrganizationRole.ADMIN]:
        return api_response(
            success=False,
            message="You do not have permission to delete API keys",
            status=403,
            error_type="AUTHORIZATION_ERROR",
        )
    
    api_key = OrganizationApiKey.query.filter_by(
        id=key_id,
        organization_id=org_id,
        deleted_at=None
    ).first()
    
    if not api_key:
        return api_response(
            success=False,
            message="API key not found",
            status=404,
            error_type="NOT_FOUND",
        )
    
    # Soft delete the API key
    api_key.delete(soft=True)
    
    return api_response(
        message="API key deleted successfully",
    )
