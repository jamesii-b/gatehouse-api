"""Admin user management endpoints."""
import logging
from datetime import datetime, timezone
from flask import g, request
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.utils.decorators import login_required, full_access_required

_logger = logging.getLogger(__name__)


def _get_admin_access(caller, target):
    """Return the first OrganizationMember row where caller is OWNER/ADMIN in a shared org with target, or None.

    Works even when the target user has been soft-deleted, as long as the
    OrganizationMember row is still active (deleted_at IS NULL).
    """
    from gatehouse_app.models.organization.organization_member import OrganizationMember

    # Query directly — don't rely on the ORM relationship which may be stale
    # when the user row is soft-deleted.
    target_memberships = OrganizationMember.query.filter_by(
        user_id=target.id, deleted_at=None
    ).all()
    target_org_ids = {m.organization_id for m in target_memberships}
    if not target_org_ids:
        return None
    return OrganizationMember.query.filter(
        OrganizationMember.user_id == caller.id,
        OrganizationMember.organization_id.in_(target_org_ids),
        OrganizationMember.role.in_(["OWNER", "ADMIN"]),
        OrganizationMember.deleted_at == None,
    ).first()


def _find_user_for_admin(user_id):
    """Look up a user by ID for admin use.

    Returns the User row whether or not it has been soft-deleted, so that
    admins can manage accounts that the user themselves deleted but that still
    have an active org membership.
    """
    from gatehouse_app.models.user.user import User as _User
    return _User.query.filter_by(id=user_id).first()


@api_v1_bp.route("/admin/users", methods=["GET"])
@login_required
@full_access_required
def admin_list_users():
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.models.user.user import User as _User
    from sqlalchemy import or_

    caller = g.current_user

    admin_memberships = OrganizationMember.query.filter(
        OrganizationMember.user_id == caller.id,
        OrganizationMember.role.in_(["OWNER", "ADMIN"]),
        OrganizationMember.deleted_at == None,
    ).all()

    if not admin_memberships:
        return api_response(success=False, message="Admin or owner role required", status=403, error_type="AUTHORIZATION_ERROR")

    admin_org_ids = [m.organization_id for m in admin_memberships]

    member_rows = OrganizationMember.query.filter(
        OrganizationMember.organization_id.in_(admin_org_ids),
        OrganizationMember.deleted_at == None,
    ).all()
    visible_user_ids = list({row.user_id for row in member_rows})

    q = request.args.get("q", "").strip()
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(200, max(1, int(request.args.get("per_page", 50))))
    except ValueError:
        page, per_page = 1, 50

    query = _User.query.filter(_User.id.in_(visible_user_ids))
    if q:
        like = f"%{q}%"
        query = query.filter(or_(_User.email.ilike(like), _User.full_name.ilike(like)))

    total = query.count()
    users = query.order_by(_User.email).offset((page - 1) * per_page).limit(per_page).all()

    member_lookup = {}
    for row in member_rows:
        if row.user_id not in member_lookup:
            member_lookup[row.user_id] = {
                "organization_id": row.organization_id,
                "role": row.role.value if hasattr(row.role, "value") else row.role,
            }

    users_data = []
    for u in users:
        d = u.to_dict()
        m = member_lookup.get(u.id, {})
        d["org_role"] = m.get("role", "member")
        d["org_id"] = m.get("organization_id")
        d["is_deleted"] = u.deleted_at is not None
        users_data.append(d)

    return api_response(
        data={
            "users": users_data, "count": total,
            "page": page, "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
        },
        message="Users retrieved successfully",
    )


@api_v1_bp.route("/admin/users/<user_id>", methods=["GET"])
@login_required
@full_access_required
def admin_get_user(user_id):
    from gatehouse_app.models.ssh_ca.ssh_key import SSHKey
    from gatehouse_app.models.auth.authentication_method import AuthenticationMethod
    from gatehouse_app.utils.constants import AuthMethodType

    caller = g.current_user
    target = _find_user_for_admin(user_id)
    if not target:
        return api_response(success=False, message="User not found", status=404, error_type="NOT_FOUND")

    if not _get_admin_access(caller, target):
        return api_response(success=False, message="Access denied", status=403, error_type="AUTHORIZATION_ERROR")

    OAUTH_TYPES = {
        AuthMethodType.GOOGLE, AuthMethodType.GITHUB,
        AuthMethodType.MICROSOFT, AuthMethodType.OIDC,
    }
    auth_methods = AuthenticationMethod.query.filter_by(user_id=user_id, deleted_at=None).all()

    has_password = any(
        m.method_type == AuthMethodType.PASSWORD and m.password_hash
        for m in auth_methods
    )
    totp_method = next(
        (m for m in auth_methods if m.method_type == AuthMethodType.TOTP and m.verified),
        None,
    )
    totp_enabled = totp_method is not None
    linked_providers = [
        {
            "provider": m.method_type.value,
            "email": (m.provider_data or {}).get("email"),
            "name": (m.provider_data or {}).get("name"),
            "connected_since": m.created_at.isoformat() if m.created_at else None,
        }
        for m in auth_methods if m.method_type in OAUTH_TYPES
    ]

    user_dict = target.to_dict()
    user_dict["has_password"] = has_password
    user_dict["totp_enabled"] = totp_enabled
    user_dict["totp_enabled_at"] = (
        totp_method.totp_verified_at.isoformat()
        if totp_method and totp_method.totp_verified_at
        else (totp_method.created_at.isoformat() if totp_method and totp_method.created_at else None)
    )
    user_dict["linked_providers"] = linked_providers
    user_dict["is_deleted"] = target.deleted_at is not None

    ssh_keys = SSHKey.query.filter_by(user_id=user_id, deleted_at=None).all()
    return api_response(
        data={"user": user_dict, "ssh_keys": [k.to_dict() for k in ssh_keys]},
        message="User retrieved",
    )


@api_v1_bp.route("/admin/users/<user_id>/suspend", methods=["POST"])
@login_required
@full_access_required
def admin_suspend_user(user_id):
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.extensions import db as _db
    from gatehouse_app.utils.constants import UserStatus, AuditAction, OrganizationRole
    from gatehouse_app.services.audit_service import AuditService

    caller = g.current_user
    target = _find_user_for_admin(user_id)
    if not target:
        return api_response(success=False, message="User not found", status=404, error_type="NOT_FOUND")

    if target.id == caller.id:
        return api_response(success=False, message="Cannot suspend yourself", status=400, error_type="BAD_REQUEST")

    admin_in_shared_org = _get_admin_access(caller, target)
    if not admin_in_shared_org:
        return api_response(success=False, message="Access denied", status=403, error_type="AUTHORIZATION_ERROR")

    owner_memberships = OrganizationMember.query.filter(
        OrganizationMember.user_id == target.id,
        OrganizationMember.role == OrganizationRole.OWNER,
        OrganizationMember.deleted_at == None,
    ).all()
    if owner_memberships:
        org_names = [m.organization.name for m in owner_memberships if m.organization and not m.organization.deleted_at]
        return api_response(
            success=False,
            message=(
                f"Cannot suspend an organization owner. {target.email} is the owner of: {', '.join(org_names)}. "
                "Transfer ownership to another member first."
            ),
            status=403, error_type="OWNER_PROTECTION",
        )

    if target.status in (UserStatus.SUSPENDED, UserStatus.COMPLIANCE_SUSPENDED):
        return api_response(success=False, message="User is already suspended", status=409, error_type="CONFLICT")

    target.status = UserStatus.SUSPENDED
    _db.session.commit()

    AuditService.log_action(
        action=AuditAction.USER_SUSPEND,
        user_id=caller.id,
        organization_id=admin_in_shared_org.organization_id,
        resource_type="user", resource_id=str(target.id),
        description=f"Admin suspended user {target.email}",
        metadata={"target_user_id": str(target.id), "target_email": target.email},
    )
    return api_response(data={"user": target.to_dict()}, message="User suspended successfully")


@api_v1_bp.route("/admin/users/<user_id>/unsuspend", methods=["POST"])
@login_required
@full_access_required
def admin_unsuspend_user(user_id):
    from gatehouse_app.extensions import db as _db
    from gatehouse_app.utils.constants import UserStatus, AuditAction
    from gatehouse_app.services.audit_service import AuditService

    caller = g.current_user
    target = _find_user_for_admin(user_id)
    if not target:
        return api_response(success=False, message="User not found", status=404, error_type="NOT_FOUND")

    admin_in_shared_org = _get_admin_access(caller, target)
    if not admin_in_shared_org:
        return api_response(success=False, message="Access denied", status=403, error_type="AUTHORIZATION_ERROR")

    if target.status not in (UserStatus.SUSPENDED, UserStatus.COMPLIANCE_SUSPENDED):
        return api_response(success=False, message="User is not suspended", status=409, error_type="CONFLICT")

    target.status = UserStatus.ACTIVE
    _db.session.commit()

    AuditService.log_action(
        action=AuditAction.USER_UNSUSPEND,
        user_id=caller.id,
        organization_id=admin_in_shared_org.organization_id,
        resource_type="user", resource_id=str(target.id),
        description=f"Admin unsuspended user {target.email}",
        metadata={"target_user_id": str(target.id), "target_email": target.email},
    )
    return api_response(data={"user": target.to_dict()}, message="User unsuspended successfully")


@api_v1_bp.route("/admin/users/<user_id>/verify-email", methods=["POST"])
@login_required
@full_access_required
def admin_verify_user_email(user_id):
    from gatehouse_app.models.auth.email_verification_token import EmailVerificationToken
    from gatehouse_app.extensions import db as _db
    from gatehouse_app.utils.constants import UserStatus, AuditAction
    from gatehouse_app.services.audit_service import AuditService

    caller = g.current_user
    target = _find_user_for_admin(user_id)
    if not target:
        return api_response(success=False, message="User not found", status=404, error_type="NOT_FOUND")

    admin_in_shared_org = _get_admin_access(caller, target)
    if not admin_in_shared_org:
        return api_response(success=False, message="Access denied", status=403, error_type="AUTHORIZATION_ERROR")

    target.email_verified = True
    was_inactive = target.status == UserStatus.INACTIVE
    if was_inactive:
        target.status = UserStatus.ACTIVE

    EmailVerificationToken.query.filter_by(user_id=target.id, used_at=None).delete()
    _db.session.commit()

    AuditService.log_action(
        action=AuditAction.ADMIN_EMAIL_VERIFY,
        user_id=caller.id,
        organization_id=admin_in_shared_org.organization_id,
        resource_type="user", resource_id=str(target.id),
        description=f"Admin force-verified email for {target.email}",
        metadata={"target_user_id": str(target.id), "target_email": target.email, "was_inactive": was_inactive},
    )
    return api_response(data={"user": target.to_dict()}, message="Email verified and account activated successfully")


@api_v1_bp.route("/admin/users/<user_id>/delete", methods=["POST"])
@login_required
@full_access_required
def admin_hard_delete_user(user_id):
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.models.user.user import User as _User
    from gatehouse_app.models.ssh_ca.ssh_key import SSHKey
    from gatehouse_app.models.ssh_ca.ssh_certificate import SSHCertificate
    from gatehouse_app.models.ssh_ca.certificate_audit_log import CertificateAuditLog
    from gatehouse_app.models.auth.authentication_method import OAuthState
    from gatehouse_app.models.security.organization_security_policy import OrganizationSecurityPolicy
    from gatehouse_app.extensions import db as _db
    from gatehouse_app.utils.constants import AuditAction, OrganizationRole
    from gatehouse_app.services.audit_service import AuditService

    caller = g.current_user
    data = request.get_json() or {}

    if not data.get("confirm"):
        return api_response(
            success=False,
            message='Deletion requires explicit confirmation. Send {"confirm": true} to proceed.',
            status=400, error_type="CONFIRMATION_REQUIRED",
        )

    target = _User.query.filter_by(id=user_id).first()
    if not target:
        return api_response(success=False, message="User not found", status=404, error_type="NOT_FOUND")

    if target.id == caller.id:
        return api_response(success=False, message="Cannot delete your own account via this endpoint.", status=400, error_type="BAD_REQUEST")

    target_org_ids = {m.organization_id for m in target.organization_memberships}
    admin_in_shared_org = OrganizationMember.query.filter(
        OrganizationMember.user_id == caller.id,
        OrganizationMember.organization_id.in_(target_org_ids),
        OrganizationMember.role.in_(["OWNER", "ADMIN"]),
        OrganizationMember.deleted_at == None,
    ).first()
    if not admin_in_shared_org:
        return api_response(success=False, message="Access denied", status=403, error_type="AUTHORIZATION_ERROR")

    owner_memberships = OrganizationMember.query.filter(
        OrganizationMember.user_id == target.id,
        OrganizationMember.role == OrganizationRole.OWNER,
        OrganizationMember.deleted_at == None,
    ).all()
    if owner_memberships:
        org_names = [m.organization.name for m in owner_memberships if m.organization and not m.organization.deleted_at]
        return api_response(
            success=False,
            message=(
                f"Cannot delete an organization owner. {target.email} is the owner of: {', '.join(org_names)}. "
                "Transfer ownership to another member first."
            ),
            status=403, error_type="OWNER_PROTECTION",
        )

    ssh_key_count = SSHKey.query.filter_by(user_id=target.id, deleted_at=None).count()
    active_certs = SSHCertificate.query.filter_by(user_id=target.id, revoked=False).filter(SSHCertificate.deleted_at == None).all()
    active_cert_count = len(active_certs)

    for cert in active_certs:
        try:
            cert.revoke("account_deleted")
        except Exception:
            pass

    if active_certs:
        try:
            _db.session.flush()
        except Exception:
            pass

    target_email = target.email
    target_id_str = str(target.id)

    try:
        # NULL out FK references that don't cascade on delete so the
        # session.delete() below doesn't hit FK constraint violations.

        # org_invite_tokens.invited_by_id — SET NULL is already on the FK column,
        # but OrganizationMember.invited_by_id has no ondelete clause.
        _db.session.execute(
            _db.text("UPDATE organization_members SET invited_by_id = NULL WHERE invited_by_id = :uid"),
            {"uid": target_id_str},
        )

        # certificate_audit_logs.user_id — nullable, no ondelete clause.
        CertificateAuditLog.query.filter_by(user_id=target_id_str).update(
            {"user_id": None}, synchronize_session=False
        )

        # organization_security_policies.updated_by_user_id — nullable, no ondelete.
        OrganizationSecurityPolicy.query.filter_by(updated_by_user_id=target_id_str).update(
            {"updated_by_user_id": None}, synchronize_session=False
        )

        # oauth_states.user_id — nullable, no ondelete.
        OAuthState.query.filter_by(user_id=target_id_str).delete(synchronize_session=False)

        _db.session.delete(target)
        _db.session.flush()
    except Exception as exc:
        _db.session.rollback()
        _logger.error(f"Hard delete failed for {target_id_str}: {exc}")
        return api_response(success=False, message="Failed to delete user account. Please try again.", status=500, error_type="SERVER_ERROR")

    AuditService.log_action(
        action=AuditAction.USER_HARD_DELETE,
        user_id=caller.id,
        organization_id=admin_in_shared_org.organization_id,
        resource_type="user", resource_id=target_id_str,
        description=f"Admin permanently deleted user account: {target_email}",
        metadata={
            "deleted_user_id": target_id_str, "deleted_user_email": target_email,
            "ssh_keys_deleted": ssh_key_count, "certs_revoked": active_cert_count,
        },
    )

    _db.session.commit()
    return api_response(
        message=f"User account {target_email} has been permanently deleted.",
        data={"deleted_user_id": target_id_str, "deleted_user_email": target_email,
              "ssh_keys_deleted": ssh_key_count, "certs_revoked": active_cert_count},
    )


@api_v1_bp.route("/admin/users/<user_id>/restore", methods=["POST"])
@login_required
@full_access_required
def admin_restore_user(user_id):
    """Restore a soft-deleted user account.

    A user who self-deleted but still has an active org membership (and active
    auth methods) can be restored by an admin.  Clearing ``deleted_at`` makes
    the account usable again without touching any auth methods.
    """
    from gatehouse_app.extensions import db as _db
    from gatehouse_app.utils.constants import UserStatus, AuditAction
    from gatehouse_app.services.audit_service import AuditService

    caller = g.current_user
    target = _find_user_for_admin(user_id)
    if not target:
        return api_response(success=False, message="User not found", status=404, error_type="NOT_FOUND")

    if not _get_admin_access(caller, target):
        return api_response(success=False, message="Access denied", status=403, error_type="AUTHORIZATION_ERROR")

    if target.deleted_at is None:
        return api_response(
            success=False, message="User account is not deleted — nothing to restore.",
            status=409, error_type="CONFLICT",
        )

    target.deleted_at = None
    if target.status not in (UserStatus.ACTIVE, UserStatus.INACTIVE):
        target.status = UserStatus.ACTIVE
    _db.session.commit()

    AuditService.log_action(
        action=AuditAction.USER_UNSUSPEND,   # closest existing action
        user_id=caller.id,
        organization_id=_get_admin_access(caller, target).organization_id,
        resource_type="user", resource_id=str(target.id),
        description=f"Admin restored soft-deleted user account {target.email}",
        metadata={"target_user_id": str(target.id), "target_email": target.email, "admin_email": caller.email},
    )
    return api_response(
        data={"user": target.to_dict()},
        message=f"User account {target.email} has been restored successfully.",
    )


@api_v1_bp.route("/admin/users/<user_id>/mfa", methods=["GET"])
@login_required
@full_access_required
def admin_get_user_mfa(user_id):
    from gatehouse_app.models.auth.authentication_method import AuthenticationMethod
    from gatehouse_app.utils.constants import AuthMethodType

    caller = g.current_user
    target = _find_user_for_admin(user_id)
    if not target:
        return api_response(success=False, message="User not found", status=404, error_type="NOT_FOUND")

    if not _get_admin_access(caller, target):
        return api_response(success=False, message="Access denied", status=403, error_type="AUTHORIZATION_ERROR")

    mfa_methods = []

    totp_method = AuthenticationMethod.query.filter_by(
        user_id=user_id, method_type=AuthMethodType.TOTP, verified=True, deleted_at=None,
    ).first()
    if totp_method:
        enabled_at = (
            totp_method.totp_verified_at.isoformat()
            if totp_method.totp_verified_at
            else (totp_method.created_at.isoformat() if totp_method.created_at else None)
        )
        mfa_methods.append({
            "id": str(totp_method.id),
            "type": "totp",
            "name": "Authenticator app (TOTP)",
            "verified": totp_method.verified,
            "enabled_at": enabled_at,
            "created_at": totp_method.created_at.isoformat() if totp_method.created_at else None,
            "last_used_at": totp_method.last_used_at.isoformat() if totp_method.last_used_at else None,
        })

    webauthn_method = AuthenticationMethod.query.filter_by(
        user_id=user_id, method_type=AuthMethodType.WEBAUTHN, deleted_at=None,
    ).first()
    if webauthn_method and webauthn_method.provider_data:
        for cred in webauthn_method.provider_data.get("credentials", []):
            if not cred.get("deleted_at"):
                mfa_methods.append({
                    "id": cred.get("id") or cred.get("credential_id"),
                    "type": "webauthn",
                    "name": cred.get("name") or cred.get("device_type") or "Passkey",
                    "device_type": cred.get("device_type", ""),
                    "transports": cred.get("transports", []),
                    "verified": True,
                    "created_at": cred.get("created_at"),
                    "last_used_at": cred.get("last_used_at"),
                })

    return api_response(
        data={"user": {"id": str(target.id), "email": target.email, "full_name": target.full_name}, "mfa_methods": mfa_methods},
        message="MFA methods retrieved",
    )


@api_v1_bp.route("/admin/users/<user_id>/mfa/<method_type>", methods=["DELETE"])
@login_required
@full_access_required
def admin_remove_user_mfa(user_id, method_type):
    from sqlalchemy.orm.attributes import flag_modified
    from gatehouse_app.models.auth.authentication_method import AuthenticationMethod
    from gatehouse_app.models.security.mfa_policy_compliance import MfaPolicyCompliance
    from gatehouse_app.models.security.organization_security_policy import OrganizationSecurityPolicy
    from gatehouse_app.extensions import db as _db
    from gatehouse_app.utils.constants import AuthMethodType, AuditAction, MfaComplianceStatus, UserStatus as _UserStatus
    from gatehouse_app.services.audit_service import AuditService
    from datetime import timedelta

    caller = g.current_user
    now = datetime.now(timezone.utc)

    VALID_TYPES = {"totp", "webauthn", "all"}
    method_type = method_type.lower().strip()
    if method_type not in VALID_TYPES:
        return api_response(
            success=False,
            message=f"Invalid method_type '{method_type}'. Must be one of: {', '.join(sorted(VALID_TYPES))}",
            status=400, error_type="VALIDATION_ERROR",
        )

    target = _find_user_for_admin(user_id)
    if not target:
        return api_response(success=False, message="User not found", status=404, error_type="NOT_FOUND")

    if target.id == caller.id:
        return api_response(success=False, message="Use the regular MFA management endpoints to modify your own MFA methods.", status=400, error_type="BAD_REQUEST")

    admin_in_shared_org = _get_admin_access(caller, target)
    if not admin_in_shared_org:
        return api_response(success=False, message="Access denied", status=403, error_type="AUTHORIZATION_ERROR")

    removed = []

    if method_type in ("totp", "all"):
        totp_methods = AuthenticationMethod.query.filter_by(user_id=user_id, method_type=AuthMethodType.TOTP, deleted_at=None).all()
        if totp_methods:
            for totp_method in totp_methods:
                totp_method.deleted_at = now
                totp_method.totp_secret = None
                totp_method.totp_backup_codes = None
                totp_method.totp_verified_at = None
                _db.session.add(totp_method)
            removed.append("totp")
        elif method_type == "totp":
            return api_response(success=False, message="User does not have TOTP configured", status=404, error_type="NOT_FOUND")

    if method_type in ("webauthn", "all"):
        webauthn_method = AuthenticationMethod.query.filter_by(user_id=user_id, method_type=AuthMethodType.WEBAUTHN, deleted_at=None).first()
        if webauthn_method:
            credential_id = request.args.get("credential_id")
            if credential_id:
                credentials = (webauthn_method.provider_data or {}).get("credentials", [])
                found = False
                new_credentials = []
                for cred in credentials:
                    cid = cred.get("id") or cred.get("credential_id")
                    if cid == credential_id and not cred.get("deleted_at"):
                        cred["deleted_at"] = now.isoformat()
                        found = True
                        removed.append(f"webauthn:{credential_id[:16]}")
                    new_credentials.append(cred)
                if not found:
                    return api_response(success=False, message=f"WebAuthn credential '{credential_id}' not found", status=404, error_type="NOT_FOUND")
                active_remaining = sum(1 for c in new_credentials if not c.get("deleted_at"))
                if active_remaining == 0:
                    webauthn_method.deleted_at = now
                else:
                    if webauthn_method.provider_data is None:
                        webauthn_method.provider_data = {}
                    webauthn_method.provider_data["credentials"] = new_credentials
                    flag_modified(webauthn_method, "provider_data")
                _db.session.add(webauthn_method)
            else:
                webauthn_method.deleted_at = now
                if webauthn_method.provider_data:
                    for cred in webauthn_method.provider_data.get("credentials", []):
                        cred["deleted_at"] = now.isoformat()
                    flag_modified(webauthn_method, "provider_data")
                _db.session.add(webauthn_method)
                removed.append("webauthn")
        elif method_type == "webauthn":
            return api_response(success=False, message="User does not have any WebAuthn passkeys configured", status=404, error_type="NOT_FOUND")

    if not removed:
        return api_response(success=False, message="No MFA methods found to remove", status=404, error_type="NOT_FOUND")

    compliance_records = MfaPolicyCompliance.query.filter_by(user_id=user_id).filter(MfaPolicyCompliance.deleted_at == None).all()
    for record in compliance_records:
        if record.status in (MfaComplianceStatus.COMPLIANT, MfaComplianceStatus.PAST_DUE, MfaComplianceStatus.SUSPENDED):
            record.status = MfaComplianceStatus.IN_GRACE
            record.compliant_at = None
            record.suspended_at = None
            org_policy = OrganizationSecurityPolicy.query.filter_by(organization_id=record.organization_id, deleted_at=None).first()
            grace_days = org_policy.mfa_grace_period_days if org_policy else 14
            record.deadline_at = now + timedelta(days=grace_days)
            record.applied_at = now
            record.notification_count = 0
            record.last_notified_at = None

    if target.status == _UserStatus.COMPLIANCE_SUSPENDED:
        target.status = _UserStatus.ACTIVE
        _db.session.add(target)

    _db.session.commit()

    AuditService.log_action(
        action=AuditAction.ADMIN_MFA_REMOVE,
        user_id=caller.id,
        organization_id=admin_in_shared_org.organization_id,
        resource_type="user", resource_id=str(target.id),
        description=f"Admin removed MFA method(s) [{', '.join(removed)}] for user {target.email}",
        metadata={"target_user_id": str(target.id), "target_user_email": target.email, "removed_methods": removed, "admin_email": caller.email},
    )

    return api_response(
        data={"removed_methods": removed, "removed_count": len(removed), "user": {"id": str(target.id), "email": target.email}},
        message=f"Removed {len(removed)} MFA method(s) for {target.email}",
    )


@api_v1_bp.route("/admin/users/<user_id>/password", methods=["POST"])
@login_required
@full_access_required
def admin_set_user_password(user_id):
    from flask_bcrypt import Bcrypt
    from gatehouse_app.models.auth.authentication_method import AuthenticationMethod
    from gatehouse_app.extensions import db as _db
    from gatehouse_app.utils.constants import AuthMethodType, AuditAction
    from gatehouse_app.services.audit_service import AuditService

    caller = g.current_user
    data = request.get_json() or {}
    new_password = data.get("password", "").strip()

    if len(new_password) < 8:
        return api_response(success=False, message="Password must be at least 8 characters", status=400, error_type="VALIDATION_ERROR")

    target = _find_user_for_admin(user_id)
    if not target:
        return api_response(success=False, message="User not found", status=404, error_type="NOT_FOUND")

    if target.id == caller.id:
        return api_response(success=False, message="Use the regular password change endpoint to update your own password.", status=400, error_type="BAD_REQUEST")

    admin_in_shared_org = _get_admin_access(caller, target)
    if not admin_in_shared_org:
        return api_response(success=False, message="Access denied", status=403, error_type="AUTHORIZATION_ERROR")

    bcrypt = Bcrypt()
    password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
    now = datetime.now(timezone.utc)

    pw_method = AuthenticationMethod.query.filter_by(user_id=user_id, method_type=AuthMethodType.PASSWORD, deleted_at=None).first()
    method_was_created = False
    if pw_method:
        pw_method.password_hash = password_hash
        pw_method.updated_at = now
        _db.session.add(pw_method)
        action_description = f"Admin reset password for user {target.email}"
    else:
        method_was_created = True
        pw_method = AuthenticationMethod(
            user_id=user_id, method_type=AuthMethodType.PASSWORD,
            password_hash=password_hash, verified=True, created_at=now,
        )
        _db.session.add(pw_method)
        action_description = f"Admin set password for user {target.email} (new method created)"

    _db.session.commit()

    AuditService.log_action(
        action=AuditAction.ADMIN_PASSWORD_SET,
        user_id=caller.id,
        organization_id=admin_in_shared_org.organization_id,
        resource_type="user", resource_id=str(target.id),
        description=action_description,
        metadata={"target_user_id": str(target.id), "target_user_email": target.email, "admin_email": caller.email, "method_created": method_was_created},
    )
    return api_response(data={"user": {"id": str(target.id), "email": target.email}}, message=f"Password updated for {target.email}")


@api_v1_bp.route("/admin/users/<user_id>/linked-accounts", methods=["GET"])
@login_required
@full_access_required
def admin_get_user_linked_accounts(user_id):
    from gatehouse_app.models.auth.authentication_method import AuthenticationMethod
    from gatehouse_app.utils.constants import AuthMethodType

    caller = g.current_user
    target = _find_user_for_admin(user_id)
    if not target:
        return api_response(success=False, message="User not found", status=404, error_type="NOT_FOUND")

    if not _get_admin_access(caller, target):
        return api_response(success=False, message="Access denied", status=403, error_type="AUTHORIZATION_ERROR")

    OAUTH_TYPES = {AuthMethodType.GOOGLE, AuthMethodType.GITHUB, AuthMethodType.MICROSOFT, AuthMethodType.OIDC}

    oauth_methods = AuthenticationMethod.query.filter(
        AuthenticationMethod.user_id == user_id,
        AuthenticationMethod.method_type.in_(OAUTH_TYPES),
        AuthenticationMethod.deleted_at == None,
    ).all()

    linked_accounts = []
    for method in oauth_methods:
        pd = method.provider_data or {}
        connected_since = method.created_at.isoformat() if method.created_at else None
        linked_accounts.append({
            "id": str(method.id),
            "provider_type": method.method_type.value,
            "email": pd.get("email"),
            "name": pd.get("name"),
            "provider_user_id": method.provider_user_id,
            # both names so old and new clients both work
            "linked_at": connected_since,
            "connected_since": connected_since,
            "verified": method.verified,
        })

    all_active_methods = AuthenticationMethod.query.filter_by(user_id=user_id, deleted_at=None).count()

    return api_response(
        data={
            "user": {"id": str(target.id), "email": target.email, "full_name": target.full_name},
            "linked_accounts": linked_accounts,
            "total_auth_methods": all_active_methods,
        },
        message="Linked accounts retrieved",
    )


@api_v1_bp.route("/admin/users/<user_id>/linked-accounts/<provider>", methods=["DELETE"])
@login_required
@full_access_required
def admin_unlink_user_provider(user_id, provider):
    from gatehouse_app.models.auth.authentication_method import AuthenticationMethod
    from gatehouse_app.extensions import db as _db
    from gatehouse_app.utils.constants import AuthMethodType, AuditAction
    from gatehouse_app.services.audit_service import AuditService

    caller = g.current_user

    OAUTH_TYPES = {AuthMethodType.GOOGLE, AuthMethodType.GITHUB, AuthMethodType.MICROSOFT, AuthMethodType.OIDC}
    PROVIDER_MAP = {t.value: t for t in OAUTH_TYPES}

    target = _find_user_for_admin(user_id)
    if not target:
        return api_response(success=False, message="User not found", status=404, error_type="NOT_FOUND")

    if target.id == caller.id:
        return api_response(success=False, message="Use the regular account settings to unlink your own providers.", status=400, error_type="BAD_REQUEST")

    admin_in_shared_org = _get_admin_access(caller, target)
    if not admin_in_shared_org:
        return api_response(success=False, message="Access denied", status=403, error_type="AUTHORIZATION_ERROR")

    provider_lower = provider.lower().strip()
    method_to_unlink = None
    if provider_lower in PROVIDER_MAP:
        method_to_unlink = AuthenticationMethod.query.filter_by(
            user_id=user_id, method_type=PROVIDER_MAP[provider_lower], deleted_at=None,
        ).first()
    else:
        method_to_unlink = AuthenticationMethod.query.filter(
            AuthenticationMethod.id == provider,
            AuthenticationMethod.user_id == user_id,
            AuthenticationMethod.method_type.in_(OAUTH_TYPES),
            AuthenticationMethod.deleted_at == None,
        ).first()

    if not method_to_unlink:
        return api_response(success=False, message=f"Provider '{provider}' is not linked to this user's account", status=404, error_type="NOT_FOUND")

    all_active = AuthenticationMethod.query.filter_by(user_id=user_id, deleted_at=None).all()
    remaining = [m for m in all_active if m.id != method_to_unlink.id]
    has_password_remaining = any(m.method_type == AuthMethodType.PASSWORD and m.password_hash for m in remaining)
    has_other_oauth_remaining = any(m.method_type in OAUTH_TYPES for m in remaining)

    if not has_password_remaining and not has_other_oauth_remaining:
        return api_response(
            success=False,
            message="Cannot unlink this provider — it is the user's only sign-in method. Ensure the user has a password or another linked provider before unlinking.",
            status=400, error_type="VALIDATION_ERROR",
        )

    now = datetime.now(timezone.utc)
    provider_name = method_to_unlink.method_type.value
    method_to_unlink.deleted_at = now
    _db.session.add(method_to_unlink)
    _db.session.commit()

    AuditService.log_action(
        action=AuditAction.ADMIN_OAUTH_UNLINK,
        user_id=caller.id,
        organization_id=admin_in_shared_org.organization_id,
        resource_type="user", resource_id=str(target.id),
        description=f"Admin unlinked {provider_name} OAuth provider from user {target.email}",
        metadata={"target_user_id": str(target.id), "target_user_email": target.email, "provider": provider_name, "admin_email": caller.email},
    )
    return api_response(
        data={"provider": provider_name, "user": {"id": str(target.id), "email": target.email}},
        message=f"Successfully unlinked {provider_name} from {target.email}",
    )
