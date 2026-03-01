"""Security policy endpoints."""
from flask import g, request
from marshmallow import Schema, fields, validate, ValidationError
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.utils.decorators import login_required, require_admin, full_access_required
from gatehouse_app.services.mfa_policy_service import MfaPolicyService
from gatehouse_app.services.organization_service import OrganizationService
from gatehouse_app.services.audit_service import AuditService
from gatehouse_app.utils.constants import MfaPolicyMode, MfaRequirementOverride, MfaComplianceStatus, AuditAction


class UpdateOrgPolicySchema(Schema):
    """Schema for updating organization security policy."""
    mfa_policy_mode = fields.String(
        required=False,
        validate=validate.OneOf([m.value for m in MfaPolicyMode])
    )
    mfa_grace_period_days = fields.Integer(
        required=False,
        validate=validate.Range(min=0, max=365)
    )
    notify_days_before = fields.Integer(
        required=False,
        validate=validate.Range(min=0, max=30)
    )


class UpdateUserPolicySchema(Schema):
    """Schema for updating user security policy override."""
    mfa_override_mode = fields.String(
        required=True,
        validate=validate.OneOf([m.value for m in MfaRequirementOverride])
    )
    force_totp = fields.Boolean(required=False, load_default=False)
    force_webauthn = fields.Boolean(required=False, load_default=False)


class ComplianceListQuerySchema(Schema):
    """Schema for compliance list query parameters."""
    status = fields.String(required=False)
    limit = fields.Integer(required=False, load_default=100)
    offset = fields.Integer(required=False, load_default=0)


@api_v1_bp.route("/organizations/<org_id>/security-policy", methods=["GET"])
@login_required
def get_org_security_policy(org_id):
    """
    Get organization security policy.

    Args:
        org_id: Organization ID

    Returns:
        200: Organization security policy
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

    policy_dto = MfaPolicyService.get_org_policy(org_id)

    if policy_dto:
        data = {
            "organization_id": policy_dto.organization_id,
            "mfa_policy_mode": policy_dto.mfa_policy_mode,
            "mfa_grace_period_days": policy_dto.mfa_grace_period_days,
            "notify_days_before": policy_dto.notify_days_before,
            "policy_version": policy_dto.policy_version,
        }
    else:
        # Return default policy if none exists
        data = {
            "organization_id": org_id,
            "mfa_policy_mode": MfaPolicyMode.OPTIONAL.value,
            "mfa_grace_period_days": 14,
            "notify_days_before": 7,
            "policy_version": 0,
        }

    return api_response(
        data={"security_policy": data},
        message="Security policy retrieved successfully",
    )


@api_v1_bp.route("/organizations/<org_id>/security-policy", methods=["PUT"])
@login_required
@require_admin
@full_access_required
def update_org_security_policy(org_id):
    """
    Update organization security policy.

    Args:
        org_id: Organization ID

    Request body:
        mfa_policy_mode: MFA policy mode (disabled, optional, require_totp, require_webauthn, require_totp_or_webauthn)
        mfa_grace_period_days: Grace period in days (0-365)
        notify_days_before: Days before deadline to notify (0-30)

    Returns:
        200: Security policy updated successfully
        400: Validation error
        401: Not authenticated
        403: Not an admin
        404: Organization not found
    """
    try:
        schema = UpdateOrgPolicySchema()
        data = schema.load(request.json)

        org = OrganizationService.get_organization_by_id(org_id)

        # Update policy
        policy = MfaPolicyService.create_org_policy(
            organization_id=org_id,
            mfa_policy_mode=MfaPolicyMode(data.get("mfa_policy_mode", MfaPolicyMode.OPTIONAL.value)),
            mfa_grace_period_days=data.get("mfa_grace_period_days", 14),
            notify_days_before=data.get("notify_days_before", 7),
            updated_by_user_id=g.current_user.id,
        )

        return api_response(
            data={
                "security_policy": {
                    "organization_id": policy.organization_id,
                    "mfa_policy_mode": policy.mfa_policy_mode.value,
                    "mfa_grace_period_days": policy.mfa_grace_period_days,
                    "notify_days_before": policy.notify_days_before,
                    "policy_version": policy.policy_version,
                }
            },
            message="Security policy updated successfully",
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )


@api_v1_bp.route("/organizations/<org_id>/mfa-compliance", methods=["GET"])
@login_required
@require_admin
@full_access_required
def get_org_mfa_compliance(org_id):
    """
    Get MFA compliance list for an organization.

    Args:
        org_id: Organization ID

    Query params:
        status: Optional status filter (not_applicable, pending, in_grace, compliant, past_due, suspended)
        limit: Maximum records to return (default 100)
        offset: Offset for pagination (default 0)

    Returns:
        200: List of compliance records
        401: Not authenticated
        403: Not an admin
        404: Organization not found
    """
    org = OrganizationService.get_organization_by_id(org_id)

    # Parse query params
    status = None
    if request.args.get("status"):
        try:
            status = MfaComplianceStatus(request.args.get("status"))
        except ValueError:
            return api_response(
                success=False,
                message="Invalid status value",
                status=400,
                error_type="VALIDATION_ERROR",
            )

    limit = min(int(request.args.get("limit", 100)), 100)
    offset = int(request.args.get("offset", 0))
    page = int(request.args.get("page", 1))
    page_size = min(int(request.args.get("page_size", limit)), 100)

    effective_offset = offset if request.args.get("offset") else (page - 1) * page_size

    compliance_list = MfaPolicyService.get_org_compliance_list(
        organization_id=org_id,
        status=status,
        limit=page_size,
        offset=effective_offset,
    )

    def format_member(c):
        """Normalize compliance record to UI-expected shape."""
        if isinstance(c, dict):
            return {
                "user_id": c.get("user_id"),
                "user_email": c.get("email"),
                "user_name": c.get("full_name"),
                "status": c.get("status"),
                "deadline_at": c.get("deadline_at"),
                "compliant_at": c.get("compliant_at"),
                "last_notified_at": c.get("notified_at"),
            }
        return {
            "user_id": getattr(c, "user_id", None),
            "user_email": getattr(c, "email", None),
            "user_name": getattr(c, "full_name", None),
            "status": getattr(c, "status", None),
            "deadline_at": getattr(c, "deadline_at", None),
            "compliant_at": getattr(c, "compliant_at", None),
            "last_notified_at": getattr(c, "notified_at", None),
        }

    return api_response(
        data={
            "members": [format_member(c) for c in compliance_list],
            "count": len(compliance_list),
            "page": page,
            "page_size": page_size,
        },
        message="Compliance records retrieved successfully",
    )


@api_v1_bp.route(
    "/organizations/<org_id>/users/<user_id>/security-policy", methods=["PATCH"]
)
@login_required
@require_admin
@full_access_required
def update_user_security_policy(org_id, user_id):
    """
    Update user security policy override.

    Args:
        org_id: Organization ID
        user_id: User ID

    Request body:
        mfa_override_mode: Override mode (inherit, required, exempt)
        force_totp: Force TOTP requirement (default false)
        force_webauthn: Force WebAuthn requirement (default false)

    Returns:
        200: User policy updated successfully
        400: Validation error
        401: Not authenticated
        403: Not an admin
        404: Organization or user not found
    """
    try:
        schema = UpdateUserPolicySchema()
        data = schema.load(request.json)

        org = OrganizationService.get_organization_by_id(org_id)

        # Check if user is a member of the organization
        if not org.is_member(user_id):
            return api_response(
                success=False,
                message="User is not a member of this organization",
                status=404,
                error_type="NOT_FOUND",
            )

        # Update user policy
        policy = MfaPolicyService.set_user_override(
            user_id=user_id,
            organization_id=org_id,
            mfa_override_mode=MfaRequirementOverride(data["mfa_override_mode"]),
            force_totp=data.get("force_totp", False),
            force_webauthn=data.get("force_webauthn", False),
            updated_by_user_id=g.current_user.id,
        )

        # Log the override change with details
        AuditService.log_action(
            action=AuditAction.USER_SECURITY_POLICY_OVERRIDE_UPDATE,
            user_id=g.current_user.id,
            organization_id=org_id,
            resource_type="user",
            resource_id=user_id,
            description=f"User security policy override changed to {data['mfa_override_mode']} for user {user_id}",
        )

        return api_response(
            data={
                "user_security_policy": {
                    "user_id": policy.user_id,
                    "organization_id": policy.organization_id,
                    "mfa_override_mode": policy.mfa_override_mode.value,
                    "force_totp": policy.force_totp,
                    "force_webauthn": policy.force_webauthn,
                }
            },
            message="User security policy updated successfully",
        )

    except ValidationError as e:
        return api_response(
            success=False,
            message="Validation failed",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details=e.messages,
        )


@api_v1_bp.route("/users/me/mfa-compliance", methods=["GET"])
@login_required
def get_my_mfa_compliance():
    """
    Get current user's MFA compliance across all organizations.

    Returns:
        200: MFA compliance summary
        401: Not authenticated
    """
    user = g.current_user

    compliance_summary = MfaPolicyService.evaluate_user_mfa_state(user)

    orgs = []
    for org_state in compliance_summary.orgs:
        orgs.append({
            "organization_id": org_state.organization_id,
            "organization_name": org_state.organization_name,
            "status": org_state.status,
            "effective_mode": org_state.effective_mode,
            "deadline_at": org_state.deadline_at,
            "applied_at": org_state.applied_at,
        })

    return api_response(
        data={
            "overall_status": compliance_summary.overall_status,
            "missing_methods": compliance_summary.missing_methods,
            "deadline_at": compliance_summary.deadline_at,
            "orgs": orgs,
        },
        message="MFA compliance retrieved successfully",
    )