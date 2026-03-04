"""OIDC (OpenID Connect) API endpoints - Root level blueprint."""
import base64
import json
import logging
import secrets
from datetime import datetime, timezone
from urllib.parse import urlencode, urlparse, parse_qs

import bcrypt
from flask import Blueprint, request, redirect, jsonify, session, g, current_app, Response

logger = logging.getLogger(__name__)

from gatehouse_app.utils.response import api_response
from gatehouse_app.services.oidc import (
    OIDCService, InvalidClientError, InvalidGrantError, InvalidRequestError
)
from gatehouse_app.services.auth_service import AuthService
from gatehouse_app.services.mfa_policy_service import MfaPolicyService
from gatehouse_app.extensions import db
from gatehouse_app.extensions import bcrypt as flask_bcrypt
from gatehouse_app.extensions import redis_client as _redis_client_ref  # may be None until app init
from gatehouse_app.models import User, OIDCClient
from gatehouse_app.models.organization.organization import Organization
from gatehouse_app.exceptions.auth_exceptions import (
    InvalidCredentialsError,
    AccountSuspendedError,
    AccountInactiveError,
)

# ---------------------------------------------------------------------------
# Helpers for Redis-backed OIDC pending state
# (avoids Flask session / cookie dependency for cross-origin /oidc/complete)
# ---------------------------------------------------------------------------

_OIDC_PENDING_TTL = 600  # 10 minutes


def _oidc_redis():
    """Return the shared Redis client, or None if not yet initialised."""
    import gatehouse_app.extensions as _ext
    return _ext.redis_client


def _stash_oidc_params(oidc_session_id: str, params: dict) -> None:
    """Store OIDC params in Redis with a TTL.  Falls back to Flask session."""
    rc = _oidc_redis()
    key = f"oidc_pending:{oidc_session_id}"
    if rc is not None:
        rc.setex(key, _OIDC_PENDING_TTL, json.dumps(params))
    else:
        session[f"oidc_pending_{oidc_session_id}"] = params


def _fetch_oidc_params(oidc_session_id: str, *, consume: bool = False) -> dict | None:
    """Retrieve (and optionally delete) OIDC params from Redis / Flask session."""
    rc = _oidc_redis()
    key = f"oidc_pending:{oidc_session_id}"
    if rc is not None:
        raw = rc.get(key)
        if raw is None:
            return None
        params = json.loads(raw)
        if consume:
            rc.delete(key)
        return params
    else:
        params = session.get(f"oidc_pending_{oidc_session_id}")
        if params and consume:
            session.pop(f"oidc_pending_{oidc_session_id}", None)
        return params


# Create OIDC blueprint registered at root level
oidc_bp = Blueprint("oidc", __name__)


# ============================================================================
# Helper Functions
# ============================================================================

def get_oidc_config():
    """Get OIDC configuration from app config."""
    base_url = current_app.config.get("OIDC_ISSUER_URL", "http://localhost:5000")
    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oidc/authorize",
        "token_endpoint": f"{base_url}/oidc/token",
        "userinfo_endpoint": f"{base_url}/oidc/userinfo",
        "jwks_uri": f"{base_url}/oidc/jwks",
        "registration_endpoint": f"{base_url}/oidc/register",
        "revocation_endpoint": f"{base_url}/oidc/revoke",
        "introspection_endpoint": f"{base_url}/oidc/introspect",
        "scopes_supported": ["openid", "profile", "email", "roles"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "claims_supported": ["sub", "name", "email", "email_verified", "roles"],
    }


def authenticate_client(client_id, client_secret=None):
    """Authenticate an OIDC client.
    
    Args:
        client_id: The client ID
        client_secret: Optional client secret
    
    Returns:
        OIDCClient instance
    
    Raises:
        InvalidClientError: If authentication fails
    """
    # Debug logging for client validation (controlled by LOG_LEVEL)
    logger.debug(f"[OIDC] Client validation: client_id={client_id}, confidential={client_secret is not None}")
    
    client = OIDCClient.query.filter_by(client_id=client_id, is_active=True).first()
    if not client:
        logger.debug(f"[OIDC] Client validation: client_id={client_id}, exists=False")
        raise InvalidClientError("Invalid client")
    
    logger.debug(f"[OIDC] Client validation: client_id={client_id}, client_id_db={client.id}, exists=True")
    
    if client.is_confidential and client_secret:
        # Try Flask-Bcrypt first (new format)
        secret_match = _check_password_hash(client, client_secret)
        logger.debug(f"[OIDC] Client secret validation: client_id={client_id}, match={secret_match}")
        if not secret_match:
            raise InvalidClientError("Invalid client credentials")
    
    return client


def require_valid_token():
    """Validate Bearer token from Authorization header.
    
    Sets g.current_token and g.current_user on success.
    
    Raises:
        InvalidGrantError: If token is invalid
    """
    logger.debug("[OIDC USERINFO] ===========================================")
    logger.debug("[OIDC USERINFO] require_valid_token() called")
    logger.debug("[OIDC USERINFO] Request method: %s", request.method)
    logger.debug("[OIDC USERINFO] Request URL: %s", request.url)
    logger.debug("[OIDC USERINFO] Request headers: %s", dict(request.headers))
    
    auth_header = request.headers.get("Authorization", "")
    logger.debug("[OIDC USERINFO] Authorization header: %s", auth_header[:20] + "..." if len(auth_header) > 20 else auth_header)
    
    if not auth_header.startswith("Bearer "):
        logger.error("[OIDC USERINFO] Invalid Authorization header format - missing 'Bearer ' prefix")
        raise InvalidGrantError("Invalid token: Missing or invalid Authorization header")
    
    token = auth_header[7:]
    logger.debug("[OIDC USERINFO] Token extracted (first 50 chars): %s...", token[:50] if len(token) > 50 else token)
    logger.debug("[OIDC USERINFO] Token length: %d", len(token))
    
    try:
        logger.debug("[OIDC USERINFO] Calling OIDCService.validate_access_token()...")
        claims = OIDCService.validate_access_token(token)
        logger.debug("[OIDC USERINFO] Token validation successful")
        logger.debug("[OIDC USERINFO] Token claims: %s", claims)
    except Exception as e:
        logger.error("[OIDC USERINFO] Token validation failed: %s: %s", type(e).__name__, str(e))
        raise
    
    g.current_token = claims
    g.access_token = token  # Store the original access token for get_userinfo()
    logger.debug("[OIDC USERINFO] g.current_token set")
    
    user_id = claims.get("sub")
    logger.debug("[OIDC USERINFO] User ID from token: %s", user_id)
    
    user = User.query.get(user_id)
    logger.debug("[OIDC USERINFO] User query result: %s", user)
    
    if not user:
        logger.error("[OIDC USERINFO] User not found in database: user_id=%s", user_id)
        raise InvalidGrantError("Invalid token: User not found")
    
    g.current_user = user
    logger.debug("[OIDC USERINFO] g.current_user set: user_id=%s, email=%s", user.id, user.email)
    logger.debug("[OIDC USERINFO] require_valid_token() completed successfully")


def _check_password_hash(client, password):
    """Check password hash with backward compatibility for old bcrypt format.
    
    Tries Flask-Bcrypt first (new format), then falls back to raw bcrypt (old format).
    If old format matches, re-hashes with new format for migration.
    """
    pw_hash = client.client_secret_hash
    
    # Try Flask-Bcrypt first (new format)
    try:
        return flask_bcrypt.check_password_hash(pw_hash, password)
    except ValueError:
        # Invalid salt - try raw bcrypt (old format)
        pass
    
    # Try raw bcrypt (old format) as fallback
    try:
        match = bcrypt.checkpw(
            pw_hash.encode('utf-8') if isinstance(pw_hash, str) else pw_hash,
            password.encode('utf-8') if isinstance(password, str) else password
        )
        if match:
            # Migrate to new format
            new_hash = flask_bcrypt.generate_password_hash(
                password.decode('utf-8') if isinstance(password, bytes) else password
            ).decode('utf-8')
            client.client_secret_hash = new_hash
            db.session.commit()
            logger.info(f"[OIDC] Migrated client secret hash to new format: client_id={client.client_id}")
        return match
    except Exception:
        return False


def parse_basic_auth():
    """Parse Basic authentication from Authorization header.
    
    Returns:
        Tuple of (client_id, client_secret) or (None, None)
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Basic "):
        try:
            encoded = auth_header[6:]
            decoded = base64.b64decode(encoded).decode("utf-8")
            client_id, client_secret = decoded.split(":", 1)
            return client_id, client_secret
        except Exception:
            pass
    return None, None


# ============================================================================
# Discovery Endpoint
# ============================================================================

@oidc_bp.route("/.well-known/openid-configuration", methods=["GET"])
def oidc_discovery():
    """OpenID Connect Discovery endpoint.
    
    Returns the OIDC configuration as JSON.
    
    Cache-Control: max-age=86400
    No authentication required.
    
    Returns:
        200: OIDC discovery document (application/json)
    """
    config = get_oidc_config()
    
    # Return discovery document as application/json (per OpenID Connect Discovery 1.0)
    response = jsonify(config)
    response.headers["Cache-Control"] = "max-age=86400"
    return response, 200


# ============================================================================
# OIDC UI Bridge — lets the React frontend drive the OIDC login flow
# ============================================================================

@oidc_bp.route("/oidc/begin", methods=["POST"])
def oidc_begin():
    """Stash OIDC authorize params server-side, return a one-time session ID.

    Called by the React UI after being redirected from _show_login_page.
    The UI cannot hold OIDC params itself (XSS risk, URL length limits), so
    the backend stashes them in the server-side session store and hands back
    an opaque ID the UI passes along during login.

    Request body (JSON):
        oidc_session_id: ID previously issued by _show_login_page
    
    Returns:
        200: { oidc_session_id, client_name, scopes }  — context for the UI
        400: missing / expired session
    """
    data = request.get_json(silent=True) or {}
    oidc_session_id = data.get("oidc_session_id") or request.args.get("oidc_session_id")
    if not oidc_session_id:
        return api_response(success=False, message="oidc_session_id required", status=400)

    params = _fetch_oidc_params(oidc_session_id)
    if not params:
        return api_response(success=False, message="OIDC session expired or invalid", status=400)

    # Look up client name for display
    client = OIDCClient.query.filter_by(client_id=params.get("client_id"), is_active=True).first()
    client_name = client.name if client else params.get("client_id", "Unknown Application")

    return api_response(
        data={
            "oidc_session_id": oidc_session_id,
            "client_name": client_name,
            "scopes": params.get("scope", "").split(),
            "redirect_uri": params.get("redirect_uri"),
        },
        message="OIDC session found",
    )


@oidc_bp.route("/oidc/complete", methods=["POST"])
def oidc_complete():
    """Complete an OIDC authorization flow after the UI has authenticated the user.

    Called by the React UI after a successful login. The UI sends its Bearer
    token + the oidc_session_id. The backend:
      1. Validates the Bearer token → resolves the user
      2. Retrieves the stashed OIDC params
      3. Generates an authorization code
      4. Returns the redirect URL (client app redirect_uri + ?code=...&state=...)

    The UI then does window.location.href = redirect_url.

    Request body (JSON):
        oidc_session_id: ID from oidc_begin
        token: Gatehouse Bearer token (from /api/v1/auth/login response)

    Returns:
        200: { redirect_url }
        400: invalid request
        401: invalid token
    """
    from gatehouse_app.models.user.session import Session as GHSession
    from gatehouse_app.utils.constants import SessionStatus

    data = request.get_json(silent=True) or {}
    oidc_session_id = data.get("oidc_session_id")
    bearer_token = data.get("token")

    if not oidc_session_id or not bearer_token:
        return api_response(success=False, message="oidc_session_id and token required", status=400)

    # Validate the Bearer token
    gh_session = GHSession.query.filter_by(token=bearer_token, status=SessionStatus.ACTIVE).first()
    if not gh_session or gh_session.is_expired():
        return api_response(success=False, message="Invalid or expired token", status=401)

    user_id = str(gh_session.user_id)

    # Check the user is still active (not suspended after session was issued)
    from gatehouse_app.models.user.user import User as _User
    from gatehouse_app.utils.constants import UserStatus
    _complete_user = _User.query.filter_by(id=user_id, deleted_at=None).first()
    if not _complete_user or _complete_user.status in (
        UserStatus.SUSPENDED, UserStatus.COMPLIANCE_SUSPENDED, UserStatus.INACTIVE
    ):
        return api_response(
            success=False,
            message="Your account is not active or has been suspended.",
            status=403,
            error_type="ACCOUNT_SUSPENDED",
        )

    # Retrieve stashed OIDC params (consume = True removes from Redis atomically)
    params = _fetch_oidc_params(oidc_session_id, consume=True)
    if not params:
        return api_response(success=False, message="OIDC session expired or invalid", status=400)

    client_id = params["client_id"]
    redirect_uri = params["redirect_uri"]
    state = params.get("state", "")
    nonce = params.get("nonce", "")
    scope = params.get("scope", "openid")
    response_type = params.get("response_type", "code")

    # Validate client still exists
    client = OIDCClient.query.filter_by(client_id=client_id, is_active=True).first()
    if not client:
        return api_response(success=False, message="OIDC client not found", status=400)

    # Generate authorization code
    try:
        valid_scopes = [s for s in scope.split() if s in (client.scopes or [])]
        if not valid_scopes:
            valid_scopes = ["openid"]

        code = OIDCService.generate_authorization_code(
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scope=valid_scopes,
            state=state,
            nonce=nonce,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )
    except Exception as e:
        logger.error("[OIDC complete] Code generation failed: %s", str(e))
        return api_response(success=False, message=f"Failed to generate authorization code: {e}", status=500)

    redirect_params = {"code": code}
    if state:
        redirect_params["state"] = state
    redirect_url = f"{redirect_uri}?{urlencode(redirect_params)}"

    return api_response(data={"redirect_url": redirect_url}, message="Authorization complete")


# ============================================================================
# Authorization Endpoint
# ============================================================================

@oidc_bp.route("/oidc/authorize", methods=["GET", "POST"])
def oidc_authorize():
    """OpenID Connect Authorization endpoint.
    
    Initiates the OIDC authentication flow.
    
    GET Parameters:
        client_id: The client ID
        redirect_uri: The redirect URI
        response_type: Must be "code" for authorization code flow
        scope: Space-separated scopes (e.g., "openid profile email")
        state: Opaque state value for CSRF protection
        nonce: Nonce for ID token replay protection
        code_challenge: PKCE code challenge
        code_challenge_method: PKCE method ("S256" or "plain")
        prompt: "login", "consent", "select_account", "none"
        max_age: Maximum authentication age in seconds
        acr_values: Requested Authentication Context Class Reference
    
    POST Parameters:
        Same as GET, plus:
        email: User email
        password: User password
    
    Returns:
        302: Redirect with authorization code or error
        200: Login page (GET when not authenticated)
        400: Invalid request
    """
    logger.debug("[OIDC] ===========================================")
    logger.debug("[OIDC] oidc_authorize called")
    logger.debug("[OIDC] Current UTC time: %s", datetime.now(timezone.utc).isoformat() + "Z")
    logger.debug("[OIDC] Request method: %s", request.method)
    logger.debug("[OIDC] Request URL: %s", request.url)
    logger.debug("[OIDC] Remote address: %s", request.remote_addr)
    
    # Parse request parameters
    if request.method == "GET":
        params = request.args.to_dict()
    else:
        params = request.form.to_dict()
    
    logger.debug("[OIDC] Raw request params: %s", params)
    
    # Extract required parameters
    logger.debug("[OIDC] Extracting request parameters...")
    client_id = params.get("client_id")
    redirect_uri = params.get("redirect_uri")
    response_type = params.get("response_type")
    scope = params.get("scope", "")
    state = params.get("state", "")
    nonce = params.get("nonce", "")
    code_challenge = params.get("code_challenge")
    code_challenge_method = params.get("code_challenge_method")
    
    logger.debug("[OIDC] Extracted parameters: client_id=%s, redirect_uri=%s, response_type=%s", client_id, redirect_uri, response_type)
    logger.debug("[OIDC] Extracted parameters: scope=%s, state=%s, nonce=%s", scope, state, nonce)
    logger.debug("[OIDC] Extracted parameters: code_challenge=%s, code_challenge_method=%s", code_challenge, code_challenge_method)
    
    # Validate required parameters
    logger.debug("[OIDC] Validating required parameters...")
    errors = []
    if not client_id:
        errors.append("client_id is required")
    if not redirect_uri:
        errors.append("redirect_uri is required")
    if not response_type:
        errors.append("response_type is required")
    
    logger.debug("[OIDC] Parameter validation errors: %s", errors)
    if errors:
        logger.debug("[OIDC] Redirecting with error: invalid_request")
        return _redirect_with_error(redirect_uri, "invalid_request", "; ".join(errors), state)
    
    # Validate response_type
    logger.debug("[OIDC] Validating response_type: %s", response_type)
    if response_type != "code":
        logger.debug("[OIDC] Redirecting with error: unsupported_response_type")
        return _redirect_with_error(
            redirect_uri, "unsupported_response_type",
            "Only response_type=code is supported", state
        )
    logger.debug("[OIDC] response_type validation passed")
    
    # Validate client
    logger.debug("[OIDC] Validating client: client_id=%s", client_id)
    client = OIDCClient.query.filter_by(client_id=client_id, is_active=True).first()
    
    logger.debug("[OIDC] Client query result: client=%s", client)
    logger.debug("[OIDC] Client validation: client_id=%s, exists=%s, is_confidential=%s",
                 client_id, client is not None, client.is_confidential if client else None)
    
    if not client:
        logger.debug("[OIDC] Redirecting with error: unauthorized_client (client not found)")
        return _redirect_with_error(redirect_uri, "unauthorized_client", "Invalid client", state)
    logger.debug("[OIDC] Client validation passed")
    
    # Validate redirect URI
    logger.debug("[OIDC] Validating redirect_uri: %s", redirect_uri)
    logger.debug("[OIDC] Client allowed redirect_uris: %s", client.redirect_uris)
    is_redirect_allowed = client.is_redirect_uri_allowed(redirect_uri)
    logger.debug("[OIDC] Redirect URI validation result: %s", is_redirect_allowed)
    
    if not is_redirect_allowed:
        logger.debug("[OIDC] Redirecting with error: invalid_request (redirect_uri not allowed)")
        return _redirect_with_error(redirect_uri, "invalid_request", "Invalid redirect_uri", state)
    logger.debug("[OIDC] Redirect URI validation passed")
    
    # Validate scopes
    logger.debug("[OIDC] Validating scopes...")
    requested_scopes = scope.split() if scope else []
    allowed_scopes = client.scopes or []
    valid_scopes = [s for s in requested_scopes if s in allowed_scopes]
    
    logger.debug("[OIDC] Requested scopes: %s", requested_scopes)
    logger.debug("[OIDC] Allowed scopes: %s", allowed_scopes)
    logger.debug("[OIDC] Valid scopes: %s", valid_scopes)
    
    if not valid_scopes:
        logger.debug("[OIDC] Redirecting with error: invalid_scope (no valid scopes)")
        return _redirect_with_error(redirect_uri, "invalid_scope", "Invalid or no scopes requested", state)
    logger.debug("[OIDC] Scope validation passed")
    
    # Check if user is already authenticated via session
    logger.debug("[OIDC] Checking session for existing authentication...")
    user_id = session.get("oidc_user_id")
    logger.debug("[OIDC] Session oidc_user_id: %s", user_id)
    
    # Handle POST with credentials
    if request.method == "POST" and not user_id:
        logger.debug("[OIDC] POST request with credentials (user not authenticated)")
        email = params.get("email")
        password = params.get("password")
        
        logger.debug("[OIDC] Email provided: %s", email is not None)
        logger.debug("[OIDC] Password provided: %s", password is not None)
        
        if not email or not password:
            logger.debug("[OIDC] Showing login page: missing credentials")
            return _show_login_page(
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                state=state,
                nonce=nonce,
                response_type=response_type,
                error="Invalid credentials"
            )
        
        logger.debug("[OIDC] Attempting user authentication for email: %s", email)
        try:
            user = AuthService.authenticate(email, password)
            
            # Evaluate MFA policy after primary authentication
            policy_result = MfaPolicyService.after_primary_auth_success(user, remember_me=False)
            
            # Check if user can create full session
            if not policy_result.can_create_full_session:
                logger.debug("[OIDC] User cannot create full session due to MFA compliance: user_id=%s, email=%s", user.id, email)
                return _show_login_page(
                    client_id=client_id,
                    redirect_uri=redirect_uri,
                    scope=scope,
                    state=state,
                    nonce=nonce,
                    response_type=response_type,
                    error="Your account requires multi factor enrollment before using single sign on"
                )
            
            user_id = user.id
            session["oidc_user_id"] = user_id
            
            logger.debug("[OIDC] User authentication successful: user_id=%s, email=%s", user_id, email)
        except AccountSuspendedError:
            logger.debug("[OIDC] User authentication failed: account suspended for email=%s", email)
            return _show_login_page(
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                state=state,
                nonce=nonce,
                response_type=response_type,
                error="Your account has been suspended. Please contact an administrator.",
            )
        except AccountInactiveError:
            logger.debug("[OIDC] User authentication failed: account inactive for email=%s", email)
            return _show_login_page(
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                state=state,
                nonce=nonce,
                response_type=response_type,
                error="Your account is not active. Please verify your email.",
            )
        except InvalidCredentialsError:
            logger.debug("[OIDC] User authentication failed: invalid credentials for email=%s", email)
            return _show_login_page(
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                state=state,
                nonce=nonce,
                response_type=response_type,
                error="Invalid email or password"
            )
    
    # If no user, show login page
    if not user_id:
        logger.debug("[OIDC] No authenticated user, showing login page")
        return _show_login_page(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            nonce=nonce,
            response_type=response_type
        )
    
    logger.debug("[OIDC] User authenticated: user_id=%s", user_id)
    
    # User is authenticated, generate authorization code
    logger.debug("[OIDC] User is authenticated, fetching user from database...")
    logger.debug("[OIDC] Current UTC time before code generation: %s", datetime.now(timezone.utc).isoformat() + "Z")
    user = User.query.get(user_id)
    logger.debug("[OIDC] User query result: %s", user)
    
    if not user:
        logger.debug("[OIDC] Redirecting with error: server_error (user not found)")
        return _redirect_with_error(redirect_uri, "server_error", "User not found", state)

    # Check account is still active (user could have been suspended after session start)
    from gatehouse_app.utils.constants import UserStatus as _UserStatus
    if user.status in (_UserStatus.SUSPENDED, _UserStatus.COMPLIANCE_SUSPENDED):
        session.pop("oidc_user_id", None)  # clear stale session
        logger.debug("[OIDC] User is suspended, clearing session and showing login error: user_id=%s", user_id)
        return _show_login_page(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            nonce=nonce,
            response_type=response_type,
            error="Your account has been suspended. Please contact an administrator.",
        )
    if user.status == _UserStatus.INACTIVE:
        session.pop("oidc_user_id", None)
        logger.debug("[OIDC] User is inactive, clearing session and showing login error: user_id=%s", user_id)
        return _show_login_page(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            nonce=nonce,
            response_type=response_type,
            error="Your account is not active. Please verify your email.",
        )

    logger.debug("[OIDC] Generating authorization code...")
    logger.debug("[OIDC] Authorization code params: client_id=%s, user_id=%s, redirect_uri=%s", client_id, user_id, redirect_uri)
    logger.debug("[OIDC] Authorization code params: scopes=%s, state=%s, nonce=%s", valid_scopes, state, nonce)
    logger.debug("[OIDC] Authorization code params: code_challenge=%s, code_challenge_method=%s", code_challenge, code_challenge_method)
    
    try:
        code = OIDCService.generate_authorization_code(
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scope=valid_scopes,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )
        logger.debug("[OIDC] Authorization code generated successfully: %s...", code[:20] if code else None)
        logger.debug("[OIDC] Current UTC time after code generation: %s", datetime.now(timezone.utc).isoformat() + "Z")
    except Exception as e:
        logger.error("[OIDC] Authorization code generation failed: %s", str(e))
        logger.error("[OIDC] Current UTC time at failure: %s", datetime.now(timezone.utc).isoformat() + "Z")
        import traceback
        logger.error("[OIDC] Traceback: %s", traceback.format_exc())
        return _redirect_with_error(redirect_uri, "server_error", str(e), state)
    
    # Redirect with authorization code
    logger.debug("[OIDC] Redirecting with authorization code...")
    logger.debug("[OIDC] Current UTC time before redirect: %s", datetime.now(timezone.utc).isoformat() + "Z")
    redirect_params = {"code": code}
    if state:
        redirect_params["state"] = state
    
    redirect_url = f"{redirect_uri}?{urlencode(redirect_params)}"
    logger.debug("[OIDC] Redirect URL: %s...", redirect_url[:100] if redirect_url else None)
    logger.debug("[OIDC] oidc_authorize completed successfully")
    logger.debug("[OIDC] Final UTC time: %s", datetime.now(timezone.utc).isoformat() + "Z")
    logger.debug("[OIDC] ===========================================")
    
    return redirect(redirect_url)


def _redirect_with_error(redirect_uri, error, error_description, state=None):
    """Redirect to client with error parameters."""
    if not redirect_uri:
        return api_response(
            success=False,
            message=error_description,
            status=400,
            error_type=error.upper(),
            error_details={"error": error, "error_description": error_description},
        )
    
    params = {
        "error": error,
        "error_description": error_description,
    }
    if state:
        params["state"] = state
    
    return redirect(f"{redirect_uri}?{urlencode(params)}")


def _show_login_page(client_id, redirect_uri, scope, state, nonce, response_type, error=None):
    """Redirect to the Gatehouse React UI login page for a proper login experience.

    Stashes the OIDC params in the server-side session keyed by a random ID,
    then sends the browser to the React UI at /login?oidc_session_id=<id>.
    The UI logs the user in and calls /oidc/complete to finish the flow.
    """
    ui_base_url = current_app.config.get("OIDC_UI_URL", "http://localhost:8080")

    # Stash OIDC params in Redis (TTL 10 min) — cookie-free, cross-origin safe
    oidc_session_id = secrets.token_urlsafe(32)
    _stash_oidc_params(oidc_session_id, {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "nonce": nonce,
        "response_type": response_type,
    })

    params = {"oidc_session_id": oidc_session_id}
    if error:
        params["error"] = error

    # /oidc-login is the dedicated OIDC bridge UI (not the main /login page)
    return redirect(f"{ui_base_url}/oidc-login?{urlencode(params)}")


# ============================================================================
# Token Endpoint
# ============================================================================

@oidc_bp.route("/oidc/token", methods=["POST"])
def oidc_token():
    """OpenID Connect Token endpoint.
    
    Exchanges authorization code for tokens or refreshes tokens.
    
    Request body (application/x-www-form-urlencoded):
        grant_type: "authorization_code" or "refresh_token"
        
        For authorization_code:
            code: The authorization code
            redirect_uri: The redirect URI used in authorization
            client_id: The client ID
            client_secret: The client secret (optional if using Basic auth)
            code_verifier: PKCE code verifier (optional)
        
        For refresh_token:
            refresh_token: The refresh token
            scope: Optional scope override
            client_id: The client ID
            client_secret: The client secret (optional if using Basic auth)
    
    Authentication:
        - Basic auth with client_id:client_secret, or
        - client_id + client_secret in request body
    
    Returns:
        200: JSON with tokens
        400: Invalid request
        401: Invalid client
    """
    # Parse request body
    if request.content_type and "application/x-www-form-urlencoded" in request.content_type:
        data = request.form.to_dict()
    else:
        data = request.json or {}
    
    # Debug: Log all incoming request parameters
    logger.debug("[OIDC] oidc_token incoming request params:")
    logger.debug("[OIDC]   content_type: %s", request.content_type)
    logger.debug("[OIDC]   method: %s", request.method)
    logger.debug("[OIDC]   headers: %s", dict(request.headers))
    logger.debug("[OIDC]   data: %s", data)
    logger.debug("[OIDC]   raw_data: %s", request.get_data(as_text=True))
    
    grant_type = data.get("grant_type")
    
    # Debug: Log grant_type and client info
    logger.debug("[OIDC]   grant_type: %s", grant_type)
    
    # Validate grant_type
    if not grant_type:
        logger.error("[OIDC]   grant_type is required")
        # RFC 6749 Section 5.2: Error response for invalid request
        response = jsonify({
            "error": "invalid_request",
            "error_description": "grant_type is required"
        })
        return response, 400
    
    # Authenticate client
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    
    # Try Basic auth if client_id not in body
    if not client_id:
        client_id, client_secret = parse_basic_auth()
    
    if not client_id:
        # Return 401 with WWW-Authenticate header for Basic auth
        response = jsonify({
            "error": "invalid_client",
            "error_description": "Client authentication required"
        })
        response.headers["WWW-Authenticate"] = 'Basic realm="OIDC Token Endpoint"'
        return response, 401
    
    try:
        # Development-only debug logging for token endpoint client authentication
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Token endpoint client authentication: client_id={client_id}")
        
        client = authenticate_client(client_id, client_secret)
        
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Token endpoint client validation: client_id={client_id}, client_db_id={client.id}, success=True")
    except InvalidClientError:
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Token endpoint client validation: client_id={client_id}, success=False")
        response = jsonify({
            "error": "invalid_client",
            "error_description": "Invalid client credentials"
        })
        return response, 401
    
    # Handle authorization_code grant
    if grant_type == "authorization_code":
        logger.debug(f"[OIDC] Handling authorization_code")
        return _handle_authorization_code_grant(data, client)
    
    # Handle refresh_token grant
    elif grant_type == "refresh_token":
        return _handle_refresh_token_grant(data, client)
    
    # Unsupported grant type
    else:
        logger.error("[OIDC]   Unsupported grant_type")
        # RFC 6749 Section 5.2: Error response for unsupported grant type
        response = jsonify({
            "error": "unsupported_grant_type",
            "error_description": f"Grant type '{grant_type}' is not supported"
        })
        return response, 400


def _handle_authorization_code_grant(data, client):
    """Handle authorization_code grant type."""
    logger.debug("[OIDC] ===========================================")
    logger.debug("[OIDC] _handle_authorization_code_grant called")
    logger.debug("[OIDC] Current UTC time: %s", datetime.now(timezone.utc).isoformat() + "Z")
    
    code = data.get("code")
    redirect_uri = data.get("redirect_uri")
    code_verifier = data.get("code_verifier")
    
    logger.debug("[OIDC] Code provided: %s", bool(code))
    logger.debug("[OIDC] Redirect URI: %s", redirect_uri)
    logger.debug("[OIDC] Code verifier provided: %s", bool(code_verifier))
    
    if not code:
        logger.error("[OIDC]   code is required")
        # RFC 6749 Section 5.2: Error response for invalid request
        response = jsonify({
            "error": "invalid_request",
            "error_description": "code is required"
        })
        return response, 400
    
    if not redirect_uri:
        logger.error("[OIDC]   redirect_uri is required")
        response = jsonify({
            "error": "invalid_request",
            "error_description": "redirect_uri is required"
        })
        return response, 400
    
    try:
        # Development-only debug logging for authorization code validation
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Authorization code validation: client_id={client.client_id}, code_provided=True")
        
        logger.debug("[OIDC] Current UTC time before code validation: %s", datetime.now(timezone.utc).isoformat() + "Z")
        claims, user = OIDCService.validate_authorization_code(
            code=code,
            client_id=client.client_id,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )
    except InvalidGrantError as e:
        logger.error("[OIDC] INVALID_GRANT: %s", str(e))
        logger.error("[OIDC] Current UTC time at validation failure: %s", datetime.now(timezone.utc).isoformat() + "Z")
        # RFC 6749 Section 5.2: Error response for invalid grant
        response = jsonify({
            "error": "invalid_grant",
            "error_description": str(e)
        })
        return response, 400
    except Exception as e:
        logger.error("[OIDC] Authorization code validation error: %s: %s", type(e).__name__, str(e))
        logger.error("[OIDC] Current UTC time at validation error: %s", datetime.now(timezone.utc).isoformat() + "Z")
        response = jsonify({
            "error": "invalid_grant",
            "error_description": str(e)
        })
        return response, 400
    
    # Generate tokens
    try:
        # Development-only debug logging for token generation
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Token generation: client_id={client.client_id}, user_id={claims['user_id']}, scope={claims['scope']}")
        
        logger.debug("[OIDC] Current UTC time before token generation: %s", datetime.now(timezone.utc).isoformat() + "Z")
        
        tokens = OIDCService.generate_tokens(
            client_id=client.client_id,
            user_id=claims["user_id"],
            scope=claims["scope"],
            nonce=claims.get("nonce"),
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            auth_time=int(__import__("time").time()),
        )
    except Exception as e:
        logger.error("[OIDC] Failed to generate tokens: %s", str(e))
        logger.error("[OIDC] Current UTC time at token generation failure: %s", datetime.now(timezone.utc).isoformat() + "Z")
        response = jsonify({
            "error": "server_error",
            "error_description": str(e)
        })
        return response, 500
    
    # Return standard OAuth2/OIDC token response (application/json)
    # Per RFC 6749 Section 5.1 and OIDC Core 1.0
    logger.debug("[OIDC] Current UTC time after token generation: %s", datetime.now(timezone.utc).isoformat() + "Z")
    logger.debug("[OIDC] _handle_authorization_code_grant completed successfully")
    
    # Echo tokens to console for diagnostics
    print(f"[TOKEN DIAGNOSTICS] Authorization code exchange completed")
    print(f"[TOKEN DIAGNOSTICS] Access Token: {tokens.get('access_token', '')}..." if len(tokens.get('access_token', '')) > 50 else f"[TOKEN DIAGNOSTICS] Access Token: {tokens.get('access_token', '')}")
    print(f"[TOKEN DIAGNOSTICS] Token Type: {tokens.get('token_type', '')}")
    print(f"[TOKEN DIAGNOSTICS] Expires In: {tokens.get('expires_in', '')}")
    if 'id_token' in tokens:
        print(f"[TOKEN DIAGNOSTICS] ID Token: {tokens['id_token']}..." if len(tokens['id_token']) > 50 else f"[TOKEN DIAGNOSTICS] ID Token: {tokens['id_token']}")
    if 'refresh_token' in tokens:
        print(f"[TOKEN DIAGNOSTICS] Refresh Token: {tokens['refresh_token'][:50]}..." if len(tokens['refresh_token']) > 50 else f"[TOKEN DIAGNOSTICS] Refresh Token: {tokens['refresh_token']}")
    print(f"[TOKEN DIAGNOSTICS] Scope: {tokens.get('scope', '')}")
    print(f"[TOKEN DIAGNOSTICS] ===========================================")
    
    logger.debug("[OIDC] ===========================================")
    response = jsonify(tokens)
    print(tokens)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response, 200


def _handle_refresh_token_grant(data, client):
    """Handle refresh_token grant type."""
    logger.debug("[OIDC] ===========================================")
    logger.debug("[OIDC] _handle_refresh_token_grant called")
    logger.debug("[OIDC] Current UTC time: %s", datetime.now(timezone.utc).isoformat() + "Z")
    
    refresh_token = data.get("refresh_token")
    scope = data.get("scope")
    
    logger.debug("[OIDC] Refresh token provided: %s", bool(refresh_token))
    logger.debug("[OIDC] Scope: %s", scope)
    
    if not refresh_token:
        # RFC 6749 Section 5.2: Error response for invalid request
        response = jsonify({
            "error": "invalid_request",
            "error_description": "refresh_token is required"
        })
        return response, 400
    
    # Parse scope if provided
    scope_list = scope.split() if scope else None
    
    try:
        logger.debug("[OIDC] Current UTC time before token refresh: %s", datetime.now(timezone.utc).isoformat() + "Z")
        tokens = OIDCService.refresh_access_token(
            refresh_token=refresh_token,
            client_id=client.client_id,
            scope=scope_list,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )
    except InvalidGrantError as e:
        logger.error("[OIDC] Refresh token error: %s", str(e))
        logger.error("[OIDC] Current UTC time at refresh failure: %s", datetime.now(timezone.utc).isoformat() + "Z")
        # RFC 6749 Section 5.2: Error response for invalid grant
        response = jsonify({
            "error": "invalid_grant",
            "error_description": str(e)
        })
        return response, 400
    
    # Return standard OAuth2/OIDC token response (application/json)
    # Per RFC 6749 Section 5.1 and OIDC Core 1.0
    logger.debug("[OIDC] Current UTC time after token refresh: %s", datetime.now(timezone.utc).isoformat() + "Z")
    logger.debug("[OIDC] _handle_refresh_token_grant completed successfully")
    
    # Echo tokens to console for diagnostics
    print(f"[TOKEN DIAGNOSTICS] Token refresh completed")
    print(f"[TOKEN DIAGNOSTICS] Access Token: {tokens.get('access_token', '')[:50]}..." if len(tokens.get('access_token', '')) > 50 else f"[TOKEN DIAGNOSTICS] Access Token: {tokens.get('access_token', '')}")
    print(f"[TOKEN DIAGNOSTICS] Token Type: {tokens.get('token_type', '')}")
    print(f"[TOKEN DIAGNOSTICS] Expires In: {tokens.get('expires_in', '')}")
    if 'id_token' in tokens:
        print(f"[TOKEN DIAGNOSTICS] ID Token: {tokens['id_token'][:50]}..." if len(tokens['id_token']) > 50 else f"[TOKEN DIAGNOSTICS] ID Token: {tokens['id_token']}")
    if 'refresh_token' in tokens:
        print(f"[TOKEN DIAGNOSTICS] Refresh Token: {tokens['refresh_token'][:50]}..." if len(tokens['refresh_token']) > 50 else f"[TOKEN DIAGNOSTICS] Refresh Token: {tokens['refresh_token']}")
    print(f"[TOKEN DIAGNOSTICS] Scope: {tokens.get('scope', '')}")
    print(f"[TOKEN DIAGNOSTICS] ===========================================")
    
    logger.debug("[OIDC] ===========================================")
    response = jsonify(tokens)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response, 200


# ============================================================================
# UserInfo Endpoint
# ============================================================================

@oidc_bp.route("/oidc/userinfo", methods=["GET", "POST"])
def oidc_userinfo():
    """OpenID Connect UserInfo endpoint.
    
    Returns claims about the authenticated user.
    
    Authorization: Bearer {access_token}
    
    Returns claims based on granted scopes:
        - sub: User ID (always included)
        - name: User full name (if "profile" scope)
        - email: User email (if "email" scope)
        - email_verified: Email verification status (if "email" scope)
    
    Returns:
        200: User claims in JSON format (application/json)
        401: Invalid or missing token (with WWW-Authenticate header per RFC 6750)
    """
    logger.debug("[OIDC USERINFO] ===========================================")
    logger.debug("[OIDC USERINFO] oidc_userinfo() endpoint called")
    logger.debug("[OIDC USERINFO] Request method: %s", request.method)
    logger.debug("[OIDC USERINFO] Request URL: %s", request.url)
    logger.debug("[OIDC USERINFO] Request content_type: %s", request.content_type)
    logger.debug("[OIDC USERINFO] Request headers: %s", dict(request.headers))
    logger.debug("[OIDC USERINFO] Request args: %s", dict(request.args))
    logger.debug("[OIDC USERINFO] Request form: %s", dict(request.form))
    request_json = request.get_json(silent=True)
    logger.debug("[OIDC USERINFO] Request json: %s", request_json)
    logger.debug("[OIDC USERINFO] Request data length: %d bytes", len(request.get_data()))
    
    try:
        logger.debug("[OIDC USERINFO] Calling require_valid_token()...")
        require_valid_token()
        logger.debug("[OIDC USERINFO] Token validation successful")
    except InvalidGrantError as e:
        logger.error("[OIDC USERINFO] Token validation failed: %s", str(e))
        # RFC 6750 Section 3: Return 401 with WWW-Authenticate header for invalid tokens
        response = jsonify({
            "error": "invalid_token",
            "error_description": str(e)
        })
        response.headers["WWW-Authenticate"] = 'Bearer realm="OIDC UserInfo Endpoint", error="invalid_token", error_description="' + str(e) + '"'
        return response, 401
    except Exception as e:
        logger.error("[OIDC USERINFO] Unexpected error during token validation: %s: %s", type(e).__name__, str(e))
        response = jsonify({
            "error": "server_error",
            "error_description": str(e)
        })
        response.headers["WWW-Authenticate"] = 'Bearer realm="OIDC UserInfo Endpoint", error="server_error"'
        return response, 500
    
    logger.debug("[OIDC USERINFO] g.current_token: %s", g.current_token)
    logger.debug("[OIDC USERINFO] g.current_user: user_id=%s, email=%s", g.current_user.id, g.current_user.email)
    
    # Get userinfo using the original access token
    access_token = g.access_token
    logger.debug("[OIDC USERINFO] Access token from g.access_token: %s...", access_token[:50] if len(access_token) > 50 else access_token)
    
    try:
        logger.debug("[OIDC USERINFO] Calling OIDCService.get_userinfo()...")
        userinfo = OIDCService.get_userinfo(access_token)
        logger.debug("[OIDC USERINFO] Userinfo retrieved successfully: %s", userinfo)
    except Exception as e:
        logger.error("[OIDC USERINFO] Failed to get user info: %s: %s", type(e).__name__, str(e))
        import traceback
        logger.error("[OIDC USERINFO] Traceback: %s", traceback.format_exc())
        response = jsonify({
            "error": "server_error",
            "error_description": str(e)
        })
        return response, 500
    
    logger.debug("[OIDC USERINFO] Returning userinfo response")
    logger.debug("[OIDC USERINFO] ===========================================")
    
    # Return standard OIDC UserInfo response (application/json)
    # Per OpenID Connect Core 1.0 Section 5.3, response is a JSON object
    response = jsonify(userinfo)
    response.headers["Cache-Control"] = "no-cache, no-store"
    return response, 200


# ============================================================================
# JWKS Endpoint
# ============================================================================

@oidc_bp.route("/oidc/jwks", methods=["GET"])
def oidc_jwks():
    """OpenID Connect JSON Web Key Set endpoint.
    
    Returns the public keys used to sign tokens.
    
    Cache-Control: max-age=3600
    No authentication required.
    
    Returns:
        200: JWKS document (application/json)
    """
    try:
        jwks = OIDCService.get_jwks()
    except Exception as e:
        response = jsonify({
            "error": "server_error",
            "error_description": str(e)
        })
        return response, 500
    
    # Return JWKS as application/json (per OpenID Connect Discovery 1.0)
    response = jsonify(jwks)
    response.headers["Cache-Control"] = "max-age=3600"
    return response, 200


# ============================================================================
# Token Revocation Endpoint
# ============================================================================

@oidc_bp.route("/oidc/revoke", methods=["POST"])
def oidc_revoke():
    """OAuth2 Token Revocation endpoint.
    
    Revokes an access token or refresh token.
    
    Request body (application/x-www-form-urlencoded):
        token: The token to revoke
        token_type_hint: Optional hint ("access_token" or "refresh_token")
        client_id: The client ID
        client_secret: The client secret (optional if using Basic auth)
    
    Authentication:
        - Basic auth with client_id:client_secret, or
        - client_id + client_secret in request body
    
    Returns:
        200: Token revoked successfully
        400: Invalid request
        401: Invalid client
    """
    # Parse request body
    if request.content_type and "application/x-www-form-urlencoded" in request.content_type:
        data = request.form.to_dict()
    else:
        data = request.json or {}
    
    token = data.get("token")
    
    if not token:
        # RFC 7009 Section 2.1: Error response for invalid request
        response = jsonify({
            "error": "invalid_request",
            "error_description": "token is required"
        })
        return response, 400
    
    # Authenticate client
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    
    if not client_id:
        client_id, client_secret = parse_basic_auth()
    
    if not client_id:
        response = jsonify({
            "error": "invalid_client",
            "error_description": "Client authentication required"
        })
        response.headers["WWW-Authenticate"] = 'Basic realm="OIDC Revoke Endpoint"'
        return response, 401
    
    try:
        client = authenticate_client(client_id, client_secret)
    except InvalidClientError:
        response = jsonify({
            "error": "invalid_client",
            "error_description": "Invalid client credentials"
        })
        return response, 401
    
    token_type_hint = data.get("token_type_hint")
    
    try:
        OIDCService.revoke_token(
            token=token,
            client_id=client.client_id,
            token_type_hint=token_type_hint,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )
    except Exception as e:
        # Revocation should succeed even if token is invalid (RFC 7009)
        pass
    
    # RFC 7009 Section 2.2: Successful revocation returns empty body with 200
    return "", 200


# ============================================================================
# Token Introspection Endpoint
# ============================================================================

@oidc_bp.route("/oidc/introspect", methods=["POST"])
def oidc_introspect():
    """OAuth2 Token Introspection endpoint.
    
    Returns information about a token.
    
    Request body (application/x-www-form-urlencoded):
        token: The token to introspect
        token_type_hint: Optional hint ("access_token" or "refresh_token")
        client_id: The client ID
        client_secret: The client secret (optional if using Basic auth)
    
    Authentication:
        - Basic auth with client_id:client_secret, or
        - client_id + client_secret in request body
    
    Returns:
        200: Token status and claims
        400: Invalid request
        401: Invalid client
    """
    # Parse request body
    if request.content_type and "application/x-www-form-urlencoded" in request.content_type:
        data = request.form.to_dict()
    else:
        data = request.json or {}
    
    token = data.get("token")
    
    if not token:
        # RFC 7009 Section 2.1: Error response for invalid request
        response = jsonify({
            "error": "invalid_request",
            "error_description": "token is required"
        })
        return response, 400
    
    # Authenticate client
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    
    if not client_id:
        client_id, client_secret = parse_basic_auth()
    
    if not client_id:
        response = jsonify({
            "error": "invalid_client",
            "error_description": "Client authentication required"
        })
        response.headers["WWW-Authenticate"] = 'Basic realm="OIDC Introspect Endpoint"'
        return response, 401
    
    try:
        client = authenticate_client(client_id, client_secret)
    except InvalidClientError:
        response = jsonify({
            "error": "invalid_client",
            "error_description": "Invalid client credentials"
        })
        return response, 401
    
    token_type_hint = data.get("token_type_hint")
    
    try:
        result = OIDCService.introspect_token(
            token=token,
            client_id=client.client_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )
    except Exception as e:
        # RFC 7009 Section 2.2: Error response
        response = jsonify({
            "error": "server_error",
            "error_description": str(e)
        })
        return response, 500
    
    # RFC 7009 Section 2.3: Return introspection response (application/json)
    response = jsonify(result)
    response.headers["Cache-Control"] = "no-cache, no-store"
    return response, 200


# ============================================================================
# Client Registration Endpoint (Optional)
# ============================================================================

@oidc_bp.route("/oidc/register", methods=["POST"])
def oidc_register():
    """OpenID Connect Client Registration endpoint.
    
    Registers a new OIDC client.
    
    Request body (application/json):
        client_name: Name of the client
        redirect_uris: List of redirect URIs
        token_endpoint_auth_method: "client_secret_basic" or "client_secret_post"
        grant_types: List of grant types ["authorization_code", "refresh_token"]
        response_types: List of response types ["code"]
        scope: Space-separated scopes (default: "openid profile email")
    
    Returns:
        201: Client registered successfully
        400: Invalid request
    """
    data = request.json or {}
    
    # Validate required fields
    client_name = data.get("client_name")
    redirect_uris = data.get("redirect_uris", [])
    
    if not client_name:
        response = jsonify({
            "error": "invalid_request",
            "error_description": "client_name is required"
        })
        return response, 400
    
    if not redirect_uris:
        response = jsonify({
            "error": "invalid_request",
            "error_description": "redirect_uris is required"
        })
        return response, 400
    
    # Validate redirect_uris
    for uri in redirect_uris:
        try:
            parsed = urlparse(uri)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError(f"Invalid redirect URI: {uri}")
        except Exception:
            response = jsonify({
                "error": "invalid_request",
                "error_description": f"Invalid redirect_uri: {uri}"
            })
            return response, 400
    
    # Generate client credentials
    client_id = f"oidc_{secrets.token_urlsafe(16)}"
    client_secret = f"secret_{secrets.token_urlsafe(24)}"
    client_secret_hash = flask_bcrypt.generate_password_hash(client_secret).decode("utf-8")
    
    # Get organization from request or default
    org_id = data.get("organization_id")
    if org_id:
        organization = Organization.query.get(org_id)
    else:
        # Get first active organization or create a default one
        organization = Organization.query.filter_by(is_active=True).first()
    
    if not organization:
        # Create a default organization for the client
        organization = Organization(
            name=f"OIDC Clients",
            slug=f"oidc-clients-{secrets.token_urlsafe(8)}",
        )
        organization.save()
    
    # Create OIDC client
    client = OIDCClient(
        organization_id=organization.id,
        name=client_name,
        client_id=client_id,
        client_secret_hash=client_secret_hash,
        redirect_uris=redirect_uris,
        grant_types=data.get("grant_types", ["authorization_code", "refresh_token"]),
        response_types=data.get("response_types", ["code"]),
        scopes=data.get("scope", "openid profile email roles").split(),
        is_active=True,
        is_confidential=True,
        require_pkce=True,
        logo_uri=data.get("logo_uri"),
        client_uri=data.get("client_uri"),
        policy_uri=data.get("policy_uri"),
        tos_uri=data.get("tos_uri"),
    )
    client.save()
    
    # Return client credentials
    response = jsonify({
        "client_id": client_id,
        "client_secret": client_secret,
        "client_id_issued_at": int(__import__("time").time()),
        "client_secret_expires_at": 0,  # Never expires
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": data.get("token_endpoint_auth_method", "client_secret_basic"),
        "grant_types": client.grant_types,
        "response_types": client.response_types,
        "scope": " ".join(client.scopes),
    })
    return response, 201
