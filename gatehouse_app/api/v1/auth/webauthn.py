"""WebAuthn passkey authentication endpoints."""
import json
import base64
import logging
from flask import request, session, g, jsonify
from marshmallow import ValidationError
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.schemas.webauthn_schema import (
    WebAuthnRegistrationBeginSchema,
    WebAuthnRegistrationCompleteSchema,
    WebAuthnLoginBeginSchema,
    WebAuthnLoginCompleteSchema,
    WebAuthnCredentialRenameSchema,
)
from gatehouse_app.services.auth_service import AuthService
from gatehouse_app.services.webauthn_service import WebAuthnService
from gatehouse_app.services.mfa_policy_service import MfaPolicyService
from gatehouse_app.utils.decorators import login_required
from gatehouse_app.exceptions.auth_exceptions import InvalidCredentialsError

logger = logging.getLogger(__name__)


@api_v1_bp.route("/auth/webauthn/register/begin", methods=["POST"])
@login_required
def begin_webauthn_registration():
    options = WebAuthnService.generate_registration_challenge(g.current_user)
    return jsonify(options), 200


@api_v1_bp.route("/auth/webauthn/register/complete", methods=["POST"])
@login_required
def complete_webauthn_registration():
    user_email = g.current_user.email
    logger.info(f"WebAuthn registration completion started for user: {user_email}")

    try:
        schema = WebAuthnRegistrationCompleteSchema()
        data = schema.load(request.json)

        client_data_json_b64 = data.get("response", {}).get("clientDataJSON", "")
        if not client_data_json_b64:
            return api_response(success=False, message="Missing clientDataJSON in response", status=400, error_type="VALIDATION_ERROR")

        try:
            padding = 4 - (len(client_data_json_b64) % 4)
            padded = client_data_json_b64 + ("=" * padding if padding != 4 else "")
            client_data_dict = json.loads(base64.urlsafe_b64decode(padded))
        except Exception as e:
            return api_response(success=False, message=f"Failed to decode client data JSON: {str(e)}", status=400, error_type="VALIDATION_ERROR")

        challenge = client_data_dict.get("challenge")
        if not challenge:
            return api_response(success=False, message="Invalid challenge in client data", status=400, error_type="VALIDATION_ERROR")

        auth_method = WebAuthnService.verify_registration_response(g.current_user, data, challenge)
        logger.info(f"WebAuthn registration completed successfully for user: {user_email}")
        return api_response(data={"credential": auth_method.to_webauthn_dict()}, message="Passkey registered successfully", status=201)
    except ValidationError as e:
        return api_response(success=False, message="Validation failed", status=400, error_type="VALIDATION_ERROR", error_details=e.messages)
    except InvalidCredentialsError as e:
        return api_response(success=False, message=e.message, status=e.status_code, error_type=e.error_type)
    except Exception as e:
        logger.exception(f"WebAuthn registration unexpected error for user {user_email}: {e}")
        return api_response(success=False, message="An unexpected error occurred during registration", status=500, error_type="INTERNAL_ERROR")


@api_v1_bp.route("/auth/webauthn/login/begin", methods=["POST"])
def begin_webauthn_login():
    try:
        schema = WebAuthnLoginBeginSchema()
        data = schema.load(request.json)

        from gatehouse_app.models.user.user import User
        user = User.query.filter_by(email=data["email"].lower(), deleted_at=None).first()
        if not user:
            return api_response(success=False, message="User not found", status=404, error_type="NOT_FOUND")

        from gatehouse_app.utils.constants import UserStatus
        if user.status in (UserStatus.SUSPENDED, UserStatus.COMPLIANCE_SUSPENDED):
            return api_response(success=False, message="Account is suspended. Contact an administrator.", status=403, error_type="ACCOUNT_SUSPENDED")

        if not user.has_webauthn_enabled():
            return api_response(success=False, message="No passkeys found for this account", status=404, error_type="NOT_FOUND")

        options = WebAuthnService.generate_authentication_challenge(user)
        session["webauthn_pending_user_id"] = user.id
        return jsonify(options), 200
    except ValidationError as e:
        return api_response(success=False, message="Validation failed", status=400, error_type="VALIDATION_ERROR", error_details=e.messages)
    except Exception as e:
        logger.exception(f"WebAuthn login begin unexpected error: {e}")
        raise


@api_v1_bp.route("/auth/webauthn/login/complete", methods=["POST"])
def complete_webauthn_login():
    try:
        user_id = session.get("webauthn_pending_user_id")
        if not user_id:
            return api_response(success=False, message="No pending WebAuthn verification. Please initiate login first.", status=401, error_type="AUTHENTICATION_ERROR")

        schema = WebAuthnLoginCompleteSchema()
        data = schema.load(request.json)

        from gatehouse_app.models.user.user import User
        user = User.query.get(user_id)
        if not user:
            return api_response(success=False, message="User not found", status=401, error_type="AUTHENTICATION_ERROR")

        from gatehouse_app.utils.constants import UserStatus
        if user.status in (UserStatus.SUSPENDED, UserStatus.COMPLIANCE_SUSPENDED):
            session.pop("webauthn_pending_user_id", None)
            return api_response(success=False, message="Account is suspended. Contact an administrator.", status=403, error_type="ACCOUNT_SUSPENDED")

        client_data = data.get("response", {}).get("clientDataJSON", "")
        client_data_dict = json.loads(base64.urlsafe_b64decode(client_data + "=="))
        challenge = client_data_dict.get("challenge")

        if not challenge:
            return api_response(success=False, message="Invalid challenge in client data", status=400, error_type="VALIDATION_ERROR")

        WebAuthnService.verify_authentication_response(user, data, challenge)

        policy_result = MfaPolicyService.after_primary_auth_success(user, remember_me=False)
        is_compliance_only = policy_result.create_compliance_only_session
        user_session = AuthService.create_session(user, is_compliance_only=is_compliance_only)
        session.pop("webauthn_pending_user_id", None)

        logger.info(f"WebAuthn login completed successfully for user: {user.email}")

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

        return api_response(data=response_data, message="Login successful")
    except ValidationError as e:
        return api_response(success=False, message="Validation failed", status=400, error_type="VALIDATION_ERROR", error_details=e.messages)
    except InvalidCredentialsError as e:
        return api_response(success=False, message=e.message, status=e.status_code, error_type=e.error_type)
    except Exception as e:
        logger.exception(f"WebAuthn login complete unexpected error: {e}")
        raise


@api_v1_bp.route("/auth/webauthn/credentials", methods=["GET"])
@login_required
def list_webauthn_credentials():
    credentials = WebAuthnService.get_user_credentials(g.current_user)
    return api_response(data={"credentials": [c.to_webauthn_dict() for c in credentials], "count": len(credentials)}, message="Credentials retrieved successfully")


@api_v1_bp.route("/auth/webauthn/credentials/<credential_id>", methods=["DELETE"])
@login_required
def delete_webauthn_credential(credential_id):
    user = g.current_user

    if not WebAuthnService.credential_belongs_to_user(credential_id, user):
        return api_response(success=False, message="Credential not found", status=404, error_type="NOT_FOUND")

    if user.get_webauthn_credential_count() <= 1:
        return api_response(success=False, message="Cannot delete the last passkey. Add another passkey first.", status=400, error_type="BAD_REQUEST")

    if not WebAuthnService.delete_credential(credential_id, user):
        return api_response(success=False, message="Credential not found", status=404, error_type="NOT_FOUND")

    return api_response(message="Passkey deleted successfully")


@api_v1_bp.route("/auth/webauthn/credentials/<credential_id>", methods=["PATCH"])
@login_required
def rename_webauthn_credential(credential_id):
    try:
        schema = WebAuthnCredentialRenameSchema()
        data = schema.load(request.json)

        if not WebAuthnService.rename_credential(credential_id, g.current_user, data["name"]):
            return api_response(success=False, message="Credential not found", status=404, error_type="NOT_FOUND")

        credential = WebAuthnService.get_credential_by_id(credential_id, g.current_user)
        return api_response(data={"credential": credential.to_webauthn_dict() if credential else None}, message="Passkey renamed successfully")
    except ValidationError as e:
        return api_response(success=False, message="Validation failed", status=400, error_type="VALIDATION_ERROR", error_details=e.messages)


@api_v1_bp.route("/auth/webauthn/status", methods=["GET"])
@login_required
def get_webauthn_status():
    user = g.current_user
    return api_response(
        data={"webauthn_enabled": user.has_webauthn_enabled(), "credential_count": user.get_webauthn_credential_count()},
        message="WebAuthn status retrieved successfully",
    )
