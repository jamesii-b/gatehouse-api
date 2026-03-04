"""OAuth authorization and callback endpoints."""
import json
import logging
from urllib.parse import urlencode
from flask import request, current_app, redirect as flask_redirect
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.services.external_auth.models import ExternalAuthError
from gatehouse_app.services.oauth_flow import OAuthFlowService, OAuthFlowError
from gatehouse_app.services.audit_service import AuditService
from gatehouse_app.api.v1.external_auth._helpers import (
    get_provider_type, _store_oidc_bridge, _pop_oidc_bridge, _pop_cli_redirect,
)

logger = logging.getLogger(__name__)


@api_v1_bp.route("/auth/external/<provider>/authorize", methods=["GET"])
def initiate_oauth_authorize(provider: str):
    flow = request.args.get("flow", "login")
    redirect_uri = request.args.get("redirect_uri")
    organization_id = request.args.get("organization_id")
    oidc_session_id = request.args.get("oidc_session_id")

    if flow not in ["login", "register"]:
        return api_response(success=False, message="Invalid flow type. Must be 'login' or 'register'", status=400, error_type="VALIDATION_ERROR")

    try:
        provider_type = get_provider_type(provider)
        if flow == "login":
            auth_url, state = OAuthFlowService.initiate_login_flow(
                provider_type=provider_type, organization_id=organization_id, redirect_uri=redirect_uri,
            )
        else:
            auth_url, state = OAuthFlowService.initiate_register_flow(
                provider_type=provider_type, organization_id=organization_id, redirect_uri=redirect_uri,
            )

        if oidc_session_id:
            _store_oidc_bridge(state, oidc_session_id)

        return api_response(data={"authorization_url": auth_url, "state": state}, message=f"OAuth {flow} flow initiated")

    except OAuthFlowError as e:
        return api_response(success=False, message=e.message, status=e.status_code, error_type=e.error_type)
    except ExternalAuthError as e:
        return api_response(success=False, message=e.message, status=e.status_code, error_type=e.error_type)


@api_v1_bp.route("/auth/external/<provider>/callback", methods=["GET"])
def handle_oauth_callback(provider: str):
    provider_type = get_provider_type(provider)

    state = request.args.get("state")
    authorization_code = request.args.get("code")
    error = request.args.get("error")
    error_description = request.args.get("error_description")

    frontend_url = current_app.config.get("FRONTEND_URL", "http://localhost:8080")
    frontend_callback = f"{frontend_url}/oauth/callback"

    cli_redirect_url = _pop_cli_redirect(state) if state else None

    def redirect_error(message: str, error_type: str = "OAUTH_ERROR"):
        if cli_redirect_url:
            from flask import make_response
            return make_response(
                f"<html><body><h2>Authentication Error</h2><p>{message}</p>"
                f"<p>You may close this window.</p></body></html>", 400,
            )
        params = {"error": message, "error_type": error_type}
        if state:
            params["state"] = state
        return flask_redirect(f"{frontend_callback}?{urlencode(params)}", code=302)

    if error:
        msg = error_description or f"Authorization failed: {error}"
        return redirect_error(msg, error.upper())

    if not authorization_code or not state:
        return redirect_error("Missing authorization code or state parameter.")

    try:
        result = OAuthFlowService.handle_callback(
            provider_type=provider_type,
            authorization_code=authorization_code,
            state=state,
            redirect_uri=None,
            error=None,
            error_description=None,
        )

        if not result.get("success"):
            return redirect_error("Authentication failed.", "AUTH_FAILED")

        flow_type = result.get("flow_type", "login")

        if flow_type == "link":
            params = {"flow": "link", "provider": provider, "linked": "1"}
            return flask_redirect(f"{frontend_url}/linked-accounts?{urlencode(params)}", code=302)

        oidc_session_id = _pop_oidc_bridge(state)

        if result.get("requires_org_selection") and not cli_redirect_url:
            orgs = json.dumps(result.get("available_organizations", []))
            params = {"requires_org_selection": "1", "state": result["state"], "provider": provider, "flow": flow_type, "orgs": orgs}
            if oidc_session_id:
                params["oidc_session_id"] = oidc_session_id
            return flask_redirect(f"{frontend_callback}?{urlencode(params)}", code=302)

        if result.get("requires_org_creation") and not cli_redirect_url:
            import json as _json
            session_data = result.get("session", {})
            token = session_data.get("token", "")
            expires_in = session_data.get("expires_in", 86400)
            pending_invites = result.get("pending_invites", [])
            params = {
                "requires_org_creation": "1", "state": result["state"], "provider": provider,
                "flow": flow_type, "token": token, "expires_in": str(expires_in),
                "pending_invites": _json.dumps(pending_invites),
            }
            if oidc_session_id:
                params["oidc_session_id"] = oidc_session_id
            return flask_redirect(f"{frontend_callback}?{urlencode(params)}", code=302)

        session_data = result.get("session", {})
        token = session_data.get("token")
        expires_in = session_data.get("expires_in", 86400)

        if not token:
            return redirect_error("No session token returned by server.", "NO_TOKEN")

        params = {"token": token, "expires_in": str(expires_in), "flow": flow_type, "provider": provider, "state": state}
        user_info = result.get("user", {})
        if user_info.get("email"):
            params["email"] = user_info["email"]

        if cli_redirect_url:
            cli_final_url = cli_redirect_url + token
            logger.info(f"CLI token_please success: provider={provider}, user={user_info.get('email')}, redirecting to CLI callback")
            return flask_redirect(cli_final_url, code=302)

        if oidc_session_id:
            params["oidc_session_id"] = oidc_session_id

        logger.info(f"OAuth callback success: provider={provider}, flow={flow_type}, user={user_info.get('email')}, redirecting to frontend")
        return flask_redirect(f"{frontend_callback}?{urlencode(params)}", code=302)

    except OAuthFlowError as e:
        logger.warning(f"OAuth callback OAuthFlowError: {e.message}")
        return redirect_error(e.message, e.error_type)
    except Exception as e:
        logger.error(f"OAuth callback unexpected error: {str(e)}", exc_info=True)
        return redirect_error("An unexpected error occurred. Please try again.", "INTERNAL_ERROR")


@api_v1_bp.route("/auth/external/select-organization", methods=["POST"])
def select_organization():
    from gatehouse_app.utils.constants import AuthMethodType as _AuthMethodType
    from gatehouse_app.models import User, AuthenticationMethod, Organization, OrganizationMember

    data = request.json or {}
    state_token = data.get("state")
    organization_id = data.get("organization_id")

    if not state_token:
        return api_response(success=False, message="state is required", status=400, error_type="VALIDATION_ERROR")
    if not organization_id:
        return api_response(success=False, message="organization_id is required", status=400, error_type="VALIDATION_ERROR")

    try:
        state_record = OAuthFlowService.validate_state(state_token)
        if not state_record or state_record.used:
            return api_response(success=False, message="Invalid or expired state token", status=400, error_type="INVALID_STATE")

        auth_method = AuthenticationMethod.query.filter_by(
            method_type=state_record.provider_type,
        ).order_by(AuthenticationMethod.created_at.desc()).first()

        if not auth_method:
            return api_response(success=False, message="Authentication session not found", status=400, error_type="SESSION_NOT_FOUND")

        user = auth_method.user

        org = Organization.query.get(organization_id)
        if not org:
            return api_response(success=False, message="Organization not found", status=404, error_type="NOT_FOUND")

        member = OrganizationMember.query.filter_by(user_id=user.id, organization_id=organization_id).first()
        if not member:
            return api_response(success=False, message="You are not a member of this organization", status=403, error_type="FORBIDDEN")

        from gatehouse_app.services.session_service import SessionService
        session = SessionService.create_session(user=user, organization_id=organization_id)
        state_record.mark_used()

        provider_type_val = state_record.provider_type.value if isinstance(state_record.provider_type, _AuthMethodType) else state_record.provider_type
        AuditService.log_external_auth_login(
            user_id=user.id, organization_id=organization_id, provider_type=provider_type_val,
            provider_user_id=auth_method.provider_user_id,
            auth_method_id=auth_method.id, session_id=session.id,
        )

        return api_response(
            data={
                "token": session.token, "expires_in": session.lifetime_seconds, "token_type": "Bearer",
                "user": {"id": user.id, "email": user.email, "full_name": user.full_name, "organization_id": organization_id},
            },
            message="Organization selected and session created successfully",
        )
    except Exception as e:
        logger.error(f"Error in select_organization: {str(e)}", exc_info=True)
        return api_response(success=False, message="An error occurred while selecting organization", status=500, error_type="INTERNAL_ERROR")


@api_v1_bp.route("/auth/external/token", methods=["POST"])
def exchange_authorization_code():
    if request.is_json:
        data = request.json or {}
    else:
        data = request.form or {}

    grant_type = data.get("grant_type")
    code = data.get("code")
    redirect_uri = data.get("redirect_uri")
    client_id = data.get("client_id", "external-app")

    if grant_type and grant_type != "authorization_code":
        return api_response(success=False, message="Invalid grant_type. Must be 'authorization_code'", status=400, error_type="INVALID_GRANT_TYPE")
    if not code:
        return api_response(success=False, message="code is required", status=400, error_type="VALIDATION_ERROR")
    if not redirect_uri:
        return api_response(success=False, message="redirect_uri is required", status=400, error_type="VALIDATION_ERROR")

    try:
        result = OAuthFlowService.exchange_authorization_code(
            code=code, client_id=client_id, redirect_uri=redirect_uri, ip_address=request.remote_addr,
        )
        return api_response(
            data={"token": result["token"], "expires_in": result["expires_in"], "token_type": result["token_type"], "user": result["user"]},
            message="Token exchanged successfully",
        )
    except OAuthFlowError as e:
        return api_response(success=False, message=e.message, status=e.status_code, error_type=e.error_type)
