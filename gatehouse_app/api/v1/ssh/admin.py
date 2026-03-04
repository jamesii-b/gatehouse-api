"""SSH CA permissions admin endpoints."""
from flask import request, g
from gatehouse_app.api.v1.ssh._helpers import ssh_bp
from gatehouse_app.utils.constants import AuditAction, OrganizationRole
from gatehouse_app.models import AuditLog
from gatehouse_app.utils.decorators import login_required
from gatehouse_app.utils.response import api_response


@ssh_bp.route('/ca/<ca_id>/permissions', methods=['GET'])
@login_required
def list_ca_permissions(ca_id):
    from gatehouse_app.models.ssh_ca.ca import CA, CAPermission
    from gatehouse_app.models.organization.organization_member import OrganizationMember

    user = g.current_user
    ca = CA.query.filter_by(id=ca_id, deleted_at=None).first()
    if not ca:
        return api_response(success=False, message="CA not found", status=404, error_type="NOT_FOUND")

    if ca.organization_id:
        membership = OrganizationMember.query.filter_by(organization_id=ca.organization_id, user_id=user.id, deleted_at=None).first()
        if not membership or membership.role not in (OrganizationRole.ADMIN, OrganizationRole.OWNER):
            return api_response(success=False, message="Admin access required", status=403, error_type="FORBIDDEN")

    perms = CAPermission.query.filter_by(ca_id=ca_id, deleted_at=None).all()
    perm_list = []
    for p in perms:
        d = p.to_dict()
        d["user_email"] = p.user.email if p.user else None
        perm_list.append(d)

    return api_response(data={"ca_id": ca_id, "permissions": perm_list, "open_to_all": len(perms) == 0}, message="CA permissions retrieved")


@ssh_bp.route('/ca/<ca_id>/permissions', methods=['POST'])
@login_required
def add_ca_permission(ca_id):
    from gatehouse_app.models.ssh_ca.ca import CA, CAPermission
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.models.user import User
    from gatehouse_app.extensions import db

    user = g.current_user
    ca = CA.query.filter_by(id=ca_id, deleted_at=None).first()
    if not ca:
        return api_response(success=False, message="CA not found", status=404, error_type="NOT_FOUND")

    if ca.organization_id:
        membership = OrganizationMember.query.filter_by(organization_id=ca.organization_id, user_id=user.id, deleted_at=None).first()
        if not membership or membership.role not in (OrganizationRole.ADMIN, OrganizationRole.OWNER):
            return api_response(success=False, message="Admin access required", status=403, error_type="FORBIDDEN")

    data = request.get_json() or {}
    target_user_id = (data.get("user_id") or "").strip()
    permission = data.get("permission", "sign")

    if not target_user_id:
        return api_response(success=False, message="user_id is required", status=400, error_type="VALIDATION_ERROR")
    if permission not in ("sign", "admin"):
        return api_response(success=False, message="permission must be 'sign' or 'admin'", status=400, error_type="VALIDATION_ERROR")

    target_user = User.query.filter_by(id=target_user_id, deleted_at=None).first()
    if not target_user:
        return api_response(success=False, message="User not found", status=404, error_type="NOT_FOUND")

    existing = CAPermission.query.filter_by(ca_id=ca_id, user_id=target_user_id, deleted_at=None).first()
    if existing:
        if existing.permission != permission:
            existing.permission = permission
            db.session.commit()
            d = existing.to_dict()
            d["user_email"] = target_user.email
            return api_response(data={"message": "Permission updated", "permission": d}, message="Permission updated")
        return api_response(success=False, message="User already has this permission on the CA", status=409, error_type="DUPLICATE")

    perm = CAPermission(ca_id=ca_id, user_id=target_user_id, permission=permission)
    db.session.add(perm)
    db.session.commit()

    AuditLog.log(action=AuditAction.CA_UPDATED, user_id=user.id, resource_type="CAPermission", resource_id=perm.id, ip_address=request.remote_addr, description=f"Granted '{permission}' on CA '{ca.name}' to user {target_user.email}")

    d = perm.to_dict()
    d["user_email"] = target_user.email
    return api_response(data={"message": "Permission granted", "permission": d}, message="Permission granted", status=201)


@ssh_bp.route('/ca/<ca_id>/permissions/<target_user_id>', methods=['DELETE'])
@login_required
def remove_ca_permission(ca_id, target_user_id):
    from gatehouse_app.models.ssh_ca.ca import CA, CAPermission
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.extensions import db

    user = g.current_user
    ca = CA.query.filter_by(id=ca_id, deleted_at=None).first()
    if not ca:
        return api_response(success=False, message="CA not found", status=404, error_type="NOT_FOUND")

    if ca.organization_id:
        membership = OrganizationMember.query.filter_by(organization_id=ca.organization_id, user_id=user.id, deleted_at=None).first()
        if not membership or membership.role not in (OrganizationRole.ADMIN, OrganizationRole.OWNER):
            return api_response(success=False, message="Admin access required", status=403, error_type="FORBIDDEN")

    perm = CAPermission.query.filter_by(ca_id=ca_id, user_id=target_user_id, deleted_at=None).first()
    if not perm:
        return api_response(success=False, message="Permission not found", status=404, error_type="NOT_FOUND")

    perm.delete(soft=True)
    AuditLog.log(action=AuditAction.CA_UPDATED, user_id=user.id, resource_type="CAPermission", resource_id=perm.id, ip_address=request.remote_addr, description=f"Revoked permission on CA '{ca.name}' from user {target_user_id}")
    return api_response(data={}, message="Permission revoked")
