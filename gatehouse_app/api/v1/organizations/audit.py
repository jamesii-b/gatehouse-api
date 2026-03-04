"""Organization audit log endpoints."""
from flask import g, request
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.utils.decorators import login_required, require_admin, full_access_required
from gatehouse_app.services.organization_service import OrganizationService


def _audit_log_to_dict(log):
    action = log.action
    return {
        "id": log.id,
        "action": action.value if hasattr(action, "value") else action,
        "user_id": log.user_id,
        "user": (
            {"id": log.user.id, "email": log.user.email, "full_name": log.user.full_name}
            if log.user else None
        ),
        "organization_id": log.organization_id,
        "resource_type": log.resource_type,
        "resource_id": log.resource_id,
        "ip_address": log.ip_address,
        "user_agent": log.user_agent,
        "request_id": log.request_id,
        "description": log.description,
        "success": log.success,
        "error_message": log.error_message,
        "metadata": log.extra_data,
        "created_at": log.created_at.isoformat() if log.created_at else None,
        "updated_at": log.updated_at.isoformat() if log.updated_at else None,
    }


@api_v1_bp.route("/organizations/<org_id>/audit-logs", methods=["GET"])
@login_required
@require_admin
@full_access_required
def get_organization_audit_logs(org_id):
    from gatehouse_app.models.auth.audit_log import AuditLog

    OrganizationService.get_organization_by_id(org_id)

    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 50)), 200)
    action_filter = request.args.get("action")

    query = AuditLog.query.filter_by(organization_id=org_id)
    if action_filter:
        query = query.filter_by(action=action_filter)

    query = query.order_by(AuditLog.created_at.desc())
    total = query.count()
    logs = query.offset((page - 1) * per_page).limit(per_page).all()

    def log_to_dict(log):
        action = log.action
        return {
            "id": log.id,
            "action": action.value if hasattr(action, "value") else action,
            "user_id": log.user_id,
            "user_email": log.user.email if log.user else None,
            "user": {"id": log.user.id, "email": log.user.email, "full_name": log.user.full_name} if log.user else None,
            "organization_id": log.organization_id,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "request_id": log.request_id,
            "description": log.description,
            "success": log.success,
            "error_message": log.error_message,
            "metadata": log.extra_data,
            "created_at": log.created_at.isoformat() if log.created_at else None,
            "updated_at": log.updated_at.isoformat() if log.updated_at else None,
        }

    return api_response(
        data={
            "audit_logs": [log_to_dict(log) for log in logs],
            "count": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
        },
        message="Audit logs retrieved successfully",
    )


@api_v1_bp.route("/audit-logs", methods=["GET"])
@login_required
def get_system_audit_logs():
    from gatehouse_app.models.auth.audit_log import AuditLog
    from gatehouse_app.models.organization.organization_member import OrganizationMember

    current_user = g.current_user
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(int(request.args.get("per_page", 50)), 200)

    is_admin = OrganizationMember.query.filter(
        OrganizationMember.user_id == current_user.id,
        OrganizationMember.role.in_(["OWNER", "ADMIN"]),
        OrganizationMember.deleted_at == None,
    ).first() is not None

    query = AuditLog.query

    if not is_admin:
        query = query.filter(AuditLog.user_id == current_user.id)

    action_filter = request.args.get("action")
    if action_filter:
        query = query.filter(AuditLog.action == action_filter)

    user_id_filter = request.args.get("user_id")
    if user_id_filter:
        query = query.filter(AuditLog.user_id == user_id_filter)

    resource_type_filter = request.args.get("resource_type")
    if resource_type_filter:
        query = query.filter(AuditLog.resource_type == resource_type_filter)

    success_filter = request.args.get("success")
    if success_filter is not None:
        query = query.filter(AuditLog.success == (success_filter.lower() == "true"))

    q = request.args.get("q", "").strip()
    if q:
        query = query.filter(AuditLog.description.ilike(f"%{q}%"))

    query = query.order_by(AuditLog.created_at.desc())
    total = query.count()
    logs = query.offset((page - 1) * per_page).limit(per_page).all()

    return api_response(
        data={
            "audit_logs": [_audit_log_to_dict(log) for log in logs],
            "count": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
            "is_admin_view": is_admin,
        },
        message="Audit logs retrieved",
    )


@api_v1_bp.route("/auth/audit-logs", methods=["GET"])
@login_required
def get_my_audit_logs():
    from gatehouse_app.models.auth.audit_log import AuditLog

    current_user = g.current_user
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(int(request.args.get("per_page", 50)), 200)

    query = AuditLog.query.filter(AuditLog.user_id == current_user.id)

    action_filter = request.args.get("action")
    if action_filter:
        query = query.filter(AuditLog.action == action_filter)

    query = query.order_by(AuditLog.created_at.desc())
    total = query.count()
    logs = query.offset((page - 1) * per_page).limit(per_page).all()

    return api_response(
        data={
            "audit_logs": [_audit_log_to_dict(log) for log in logs],
            "count": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
        },
        message="Activity retrieved",
    )
