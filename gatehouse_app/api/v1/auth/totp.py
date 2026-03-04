"""TOTP authentication endpoints."""
from flask import request, session, g, current_app
from marshmallow import ValidationError
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.extensions import limiter
from gatehouse_app.utils.response import api_response
from gatehouse_app.schemas.auth_schema import (
    TOTPVerifyEnrollmentSchema,
    TOTPVerifySchema,
    TOTPDisableSchema,
    TOTPRegenerateBackupCodesSchema,
)
from gatehouse_app.services.auth_service import AuthService
from gatehouse_app.services.mfa_policy_service import MfaPolicyService
from gatehouse_app.utils.decorators import login_required
from gatehouse_app.exceptions.auth_exceptions import InvalidCredentialsError
from gatehouse_app.exceptions.validation_exceptions import ConflictError


@api_v1_bp.route("/auth/totp/enroll", methods=["POST"])
@login_required
def enroll_totp():
    try:
        result = AuthService.enroll_totp(g.current_user)
        return api_response(
            data={
                "secret": result["secret"],
                "provisioning_uri": result["provisioning_uri"],
                "qr_code": result["qr_code"],
                "backup_codes": result["backup_codes"],
            },
            message="TOTP enrollment initiated. Please verify with your authenticator app.",
            status=201,
        )
    except ConflictError as e:
        return api_response(success=False, message=e.message, status=e.status_code, error_type=e.error_type)


@api_v1_bp.route("/auth/totp/verify-enrollment", methods=["POST"])
@login_required
def verify_totp_enrollment():
    try:
        schema = TOTPVerifyEnrollmentSchema()
        data = schema.load(request.json)
        AuthService.verify_totp_enrollment(g.current_user, data["code"], client_utc_timestamp=data.get("client_timestamp"))
        return api_response(message="TOTP enrollment completed successfully")
    except ValidationError as e:
        return api_response(success=False, message="Validation failed", status=400, error_type="VALIDATION_ERROR", error_details=e.messages)
    except InvalidCredentialsError as e:
        return api_response(success=False, message=e.message, status=e.status_code, error_type=e.error_type)


@api_v1_bp.route("/auth/totp/verify", methods=["POST"])
@limiter.limit(lambda: current_app.config["RATELIMIT_AUTH_TOTP_VERIFY"])
def verify_totp():
    try:
        schema = TOTPVerifySchema()
        data = schema.load(request.json)

        user_id = session.get("totp_pending_user_id") or session.get("webauthn_pending_user_id")
        if not user_id:
            return api_response(success=False, message="No pending TOTP verification. Please login first.", status=401, error_type="AUTHENTICATION_ERROR")

        from gatehouse_app.models.user.user import User
        user = User.query.get(user_id)
        if not user:
            return api_response(success=False, message="User not found", status=401, error_type="AUTHENTICATION_ERROR")

        from gatehouse_app.utils.constants import UserStatus
        if user.status in (UserStatus.SUSPENDED, UserStatus.COMPLIANCE_SUSPENDED):
            session.pop("totp_pending_user_id", None)
            session.pop("webauthn_pending_user_id", None)
            return api_response(success=False, message="Account is suspended. Contact an administrator.", status=403, error_type="ACCOUNT_SUSPENDED")

        AuthService.authenticate_with_totp(user, data["code"], data.get("is_backup_code", False), client_utc_timestamp=data.get("client_timestamp"))

        policy_result = MfaPolicyService.after_primary_auth_success(user, remember_me=False)
        is_compliance_only = policy_result.create_compliance_only_session
        user_session = AuthService.create_session(user, is_compliance_only=is_compliance_only)

        session.pop("totp_pending_user_id", None)
        session.pop("webauthn_pending_user_id", None)

        response_data = {
            "user": user.to_dict(),
            "token": user_session.token,
            "expires_at": user_session.expires_at.isoformat() + "Z" if user_session.expires_at.isoformat()[-1] != "Z" else user_session.expires_at.isoformat(),
        }

        if policy_result.compliance_summary:
            response_data["mfa_compliance"] = {
                "overall_status": policy_result.compliance_summary.overall_status,
                "missing_methods": policy_result.compliance_summary.missing_methods,
                "deadline_at": policy_result.compliance_summary.deadline_at,
                "orgs": [
                    {
                        "organization_id": org.organization_id,
                        "organization_name": org.organization_name,
                        "status": org.status,
                        "effective_mode": org.effective_mode,
                        "deadline_at": org.deadline_at,
                        "applied_at": org.applied_at,
                    }
                    for org in policy_result.compliance_summary.orgs
                ],
            }

        if is_compliance_only:
            response_data["requires_mfa_enrollment"] = True

        return api_response(data=response_data, message="TOTP verification successful")
    except ValidationError as e:
        return api_response(success=False, message="Validation failed", status=400, error_type="VALIDATION_ERROR", error_details=e.messages)
    except InvalidCredentialsError as e:
        return api_response(success=False, message=e.message, status=e.status_code, error_type=e.error_type)


@api_v1_bp.route("/auth/totp/disable", methods=["DELETE"])
@login_required
def disable_totp():
    try:
        schema = TOTPDisableSchema()
        data = schema.load(request.json)
        AuthService.disable_totp(g.current_user, data["password"])
        return api_response(message="TOTP disabled successfully")
    except ValidationError as e:
        return api_response(success=False, message="Validation failed", status=400, error_type="VALIDATION_ERROR", error_details=e.messages)
    except InvalidCredentialsError as e:
        return api_response(success=False, message=e.message, status=e.status_code, error_type=e.error_type)


@api_v1_bp.route("/auth/totp/status", methods=["GET"])
@login_required
def get_totp_status():
    from gatehouse_app.models.auth.authentication_method import AuthenticationMethod
    from gatehouse_app.utils.constants import AuthMethodType
    from gatehouse_app.extensions import db as _db
    from datetime import datetime, timezone

    user = g.current_user

    stale = AuthenticationMethod.query.filter_by(user_id=user.id, method_type=AuthMethodType.TOTP, verified=False, deleted_at=None).all()
    for s in stale:
        secret = (s.provider_data or {}).get("secret") if s.provider_data else None
        if not secret:
            s.deleted_at = datetime.now(timezone.utc)
            _db.session.add(s)
    if stale:
        _db.session.commit()

    totp_enabled = user.has_totp_enabled()
    backup_codes_remaining = 0
    verified_at = None

    if totp_enabled:
        totp_method = AuthenticationMethod.query.filter_by(
            user_id=user.id, method_type=AuthMethodType.TOTP, verified=True, deleted_at=None
        ).order_by(AuthenticationMethod.created_at.desc()).first()

        if totp_method and totp_method.provider_data:
            backup_codes_remaining = len(totp_method.provider_data.get("backup_codes", []))
        if totp_method and totp_method.totp_verified_at:
            ts = totp_method.totp_verified_at.isoformat()
            verified_at = ts if ts.endswith("Z") else ts + "Z"

    return api_response(
        data={"totp_enabled": totp_enabled, "verified_at": verified_at, "backup_codes_remaining": backup_codes_remaining},
        message="TOTP status retrieved successfully",
    )


@api_v1_bp.route("/auth/totp/regenerate-backup-codes", methods=["POST"])
@login_required
def regenerate_totp_backup_codes():
    try:
        schema = TOTPRegenerateBackupCodesSchema()
        data = schema.load(request.json)
        backup_codes = AuthService.regenerate_totp_backup_codes(g.current_user, data["password"])
        return api_response(data={"backup_codes": backup_codes}, message="Backup codes regenerated successfully")
    except ValidationError as e:
        return api_response(success=False, message="Validation failed", status=400, error_type="VALIDATION_ERROR", error_details=e.messages)
    except InvalidCredentialsError as e:
        return api_response(success=False, message=e.message, status=e.status_code, error_type=e.error_type)
