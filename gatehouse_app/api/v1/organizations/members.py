"""Organization member management endpoints."""
from flask import g, request
from marshmallow import ValidationError
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.utils.decorators import login_required, require_admin, full_access_required
from gatehouse_app.schemas.organization_schema import InviteMemberSchema, UpdateMemberRoleSchema
from gatehouse_app.services.organization_service import OrganizationService
from gatehouse_app.services.user_service import UserService
from gatehouse_app.utils.constants import OrganizationRole


@api_v1_bp.route("/organizations/<org_id>/members", methods=["GET"])
@login_required
@full_access_required
def get_organization_members(org_id):
    org = OrganizationService.get_organization_by_id(org_id)
    if not org.is_member(g.current_user.id):
        return api_response(success=False, message="You are not a member of this organization", status=403, error_type="AUTHORIZATION_ERROR")

    members_data = []
    for member in org.members:
        if member.deleted_at is None:
            member_dict = member.to_dict()
            member_dict["user"] = member.user.to_dict()
            members_data.append(member_dict)

    return api_response(data={"members": members_data, "count": len(members_data)}, message="Members retrieved successfully")


@api_v1_bp.route("/organizations/<org_id>/members", methods=["POST"])
@login_required
@require_admin
@full_access_required
def add_organization_member(org_id):
    try:
        schema = InviteMemberSchema()
        data = schema.load(request.json)
        org = OrganizationService.get_organization_by_id(org_id)
        user = UserService.get_user_by_email(data["email"])
        if not user:
            return api_response(success=False, message="User not found", status=404, error_type="NOT_FOUND")

        role = OrganizationRole(data["role"])
        member = OrganizationService.add_member(org=org, user_id=user.id, role=role, inviter_id=g.current_user.id)
        member_dict = member.to_dict()
        member_dict["user"] = user.to_dict()
        return api_response(data={"member": member_dict}, message="Member added successfully", status=201)
    except ValidationError as e:
        return api_response(success=False, message="Validation failed", status=400, error_type="VALIDATION_ERROR", error_details=e.messages)


@api_v1_bp.route("/organizations/<org_id>/members/<user_id>", methods=["DELETE"])
@login_required
@require_admin
@full_access_required
def remove_organization_member(org_id, user_id):
    org = OrganizationService.get_organization_by_id(org_id)
    OrganizationService.remove_member(org=org, user_id=user_id, remover_id=g.current_user.id)
    return api_response(message="Member removed successfully")


@api_v1_bp.route("/organizations/<org_id>/members/<user_id>/role", methods=["PATCH"])
@login_required
@require_admin
@full_access_required
def update_member_role(org_id, user_id):
    try:
        schema = UpdateMemberRoleSchema()
        data = schema.load(request.json)
        org = OrganizationService.get_organization_by_id(org_id)
        new_role = OrganizationRole(data["role"])
        member = OrganizationService.update_member_role(org=org, user_id=user_id, new_role=new_role, updater_id=g.current_user.id)
        member_dict = member.to_dict()
        member_dict["user"] = member.user.to_dict()
        return api_response(data={"member": member_dict}, message="Member role updated successfully")
    except ValidationError as e:
        return api_response(success=False, message="Validation failed", status=400, error_type="VALIDATION_ERROR", error_details=e.messages)


@api_v1_bp.route("/organizations/<org_id>/transfer-ownership", methods=["POST"])
@login_required
@full_access_required
def transfer_organization_ownership(org_id):
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.utils.constants import AuditAction
    from gatehouse_app.services.audit_service import AuditService

    caller = g.current_user
    data = request.get_json() or {}
    new_owner_user_id = data.get("new_owner_user_id")

    if not new_owner_user_id:
        return api_response(success=False, message="new_owner_user_id is required", status=400, error_type="VALIDATION_ERROR")

    if str(new_owner_user_id) == str(caller.id):
        return api_response(success=False, message="You are already the owner of this organization.", status=409, error_type="CONFLICT")

    org = OrganizationService.get_organization_by_id(org_id)

    caller_membership = OrganizationMember.query.filter_by(organization_id=org.id, user_id=caller.id, deleted_at=None).first()
    if not caller_membership or caller_membership.role != OrganizationRole.OWNER:
        return api_response(success=False, message="Only the organization owner can transfer ownership.", status=403, error_type="AUTHORIZATION_ERROR")

    target_membership = OrganizationMember.query.filter_by(organization_id=org.id, user_id=new_owner_user_id, deleted_at=None).first()
    if not target_membership:
        return api_response(success=False, message="Target user is not a member of this organization.", status=404, error_type="NOT_FOUND")

    if target_membership.role == OrganizationRole.OWNER:
        return api_response(success=False, message="Target user is already the owner.", status=409, error_type="CONFLICT")

    try:
        demoted = OrganizationService.update_member_role(org=org, user_id=str(caller.id), new_role=OrganizationRole.ADMIN, updater_id=str(caller.id))
        promoted = OrganizationService.update_member_role(org=org, user_id=str(new_owner_user_id), new_role=OrganizationRole.OWNER, updater_id=str(caller.id))
    except Exception as exc:
        from gatehouse_app.extensions import db as _db
        _db.session.rollback()
        return api_response(success=False, message=f"Failed to transfer ownership: {exc}", status=500, error_type="SERVER_ERROR")

    AuditService.log_action(
        action=AuditAction.ORG_OWNERSHIP_TRANSFERRED,
        user_id=caller.id,
        organization_id=org.id,
        resource_type="organization",
        resource_id=str(org.id),
        description=(f"Ownership of '{org.name}' transferred from {caller.email} to {target_membership.user.email if target_membership.user else new_owner_user_id}"),
        metadata={
            "previous_owner_id": str(caller.id),
            "previous_owner_email": caller.email,
            "new_owner_id": str(new_owner_user_id),
            "new_owner_email": target_membership.user.email if target_membership.user else None,
        },
    )

    def _member_dict(m):
        d = m.to_dict()
        if m.user:
            d["user"] = m.user.to_dict()
        return d

    return api_response(
        data={"previous_owner": _member_dict(demoted), "new_owner": _member_dict(promoted)},
        message=(f"Ownership of '{org.name}' successfully transferred to {target_membership.user.email if target_membership.user else new_owner_user_id}."),
    )


@api_v1_bp.route("/organizations/<org_id>/members/<user_id>/send-mfa-reminder", methods=["POST"])
@login_required
@require_admin
def send_mfa_reminder(org_id, user_id):
    from gatehouse_app.models import User, MfaPolicyCompliance, OrganizationSecurityPolicy
    from gatehouse_app.services.notification_service import NotificationService

    user = User.query.filter_by(id=user_id, deleted_at=None).first()
    if not user:
        return api_response(success=False, message="User not found", status=404)

    compliance = MfaPolicyCompliance.query.filter_by(user_id=user_id, organization_id=org_id).first()
    policy = OrganizationSecurityPolicy.query.filter_by(organization_id=org_id).first()

    if compliance and policy and compliance.deadline_at:
        NotificationService.send_mfa_deadline_reminder(user, compliance, policy)
    else:
        NotificationService._send_email(
            to_address=user.email,
            subject="Reminder: Set up multi-factor authentication",
            body=(
                f"Hi {user.full_name or user.email},\n\n"
                "Your organization administrator has asked you to set up "
                "multi-factor authentication (MFA) on your Gatehouse account.\n\n"
                "Please log in and configure MFA as soon as possible.\n\n"
                "Gatehouse Security Team"
            ),
        )

    return api_response(data={}, message="Reminder sent successfully")
