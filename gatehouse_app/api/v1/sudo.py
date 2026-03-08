"""Sudoer check and sudo-related endpoints."""
from flask import request
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.models.organization import OrganizationApiKey
from gatehouse_app.models.ssh_ca.ssh_certificate import SSHCertificate
from gatehouse_app.models.organization import Department, DepartmentMembership


@api_v1_bp.route("/sudo/check", methods=["POST"])
def check_sudoer():
    """
    Check if a user with a given certificate can sudo.
    
    This endpoint validates an API key for an organization, retrieves the certificate
    by serial ID, finds the user and their departments, and checks if any of their
    departments have sudo capability.
    
    Request body:
        api_key: Organization API key (required)
        certificate_serial: Certificate serial ID (required)
    
    Returns:
        200: Sudoer status returned
        400: Invalid request body
        401: Invalid API key
        403: Certificate not found or user not found
        404: Organization or certificate not found
    """
    try:
        data = request.get_json()
        
        if not data:
            return api_response(
                success=False,
                message="Request body is required",
                status=400,
                error_type="INVALID_REQUEST",
            )
        
        api_key = data.get("api_key")
        certificate_serial = data.get("certificate_serial")
        
        if not api_key or certificate_serial is None:
            return api_response(
                success=False,
                message="api_key and certificate_serial are required",
                status=400,
                error_type="MISSING_REQUIRED_FIELDS",
            )
        
        # Find the certificate by serial
        certificate = SSHCertificate.query.filter_by(
            serial=certificate_serial,
            deleted_at=None
        ).first()
        
        if not certificate:
            return api_response(
                success=False,
                message="Certificate not found",
                status=404,
                error_type="NOT_FOUND",
            )
        
        # Get the CA and organization
        ca = certificate.ca
        if not ca:
            return api_response(
                success=False,
                message="Certificate CA not found",
                status=404,
                error_type="NOT_FOUND",
            )
        
        org_id = ca.organization_id
        
        # Verify the API key for this organization
        org_api_key = OrganizationApiKey.verify_key(org_id, api_key)
        
        if not org_api_key:
            return api_response(
                success=False,
                message="Invalid API key for organization",
                status=401,
                error_type="UNAUTHORIZED",
            )
        
        # Get the user from the certificate
        user = certificate.user
        if not user:
            return api_response(
                success=False,
                message="Certificate user not found",
                status=404,
                error_type="NOT_FOUND",
            )
        
        # Get all departments the user belongs to
        user_departments = DepartmentMembership.query.filter_by(
            user_id=user.id,
            deleted_at=None
        ).all()
        
        # Check if any of the user's departments have sudo capability
        can_sudo = False
        sudoer_departments = []
        
        for dept_membership in user_departments:
            dept = dept_membership.department
            if dept and dept.can_sudo and dept.deleted_at is None:
                can_sudo = True
                sudoer_departments.append({
                    "id": dept.id,
                    "name": dept.name,
                })
        
        return api_response(
            data={
                "can_sudo": can_sudo,
                "user_id": user.id,
                "user_email": user.email,
                "certificate_serial": certificate.serial,
                "sudoer_departments": sudoer_departments,
                "all_departments_count": len(user_departments),
            },
            message="Sudoer status retrieved successfully",
            status=200,
        )
    
    except Exception as e:
        return api_response(
            success=False,
            message=f"An error occurred: {str(e)}",
            status=500,
            error_type="INTERNAL_ERROR",
        )
