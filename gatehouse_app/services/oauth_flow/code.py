"""Authorization code generation, exchange, and redirect helpers."""
import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Optional

from gatehouse_app.models.oidc.oidc_authorization_code import OIDCAuthCode
from gatehouse_app.services.oauth_flow.login import OAuthFlowError

logger = logging.getLogger(__name__)


def generate_authorization_code(
    user_id: str,
    client_id: str,
    redirect_uri: str,
    scope: list = None,
    nonce: str = None,
    ip_address: str = None,
    user_agent: str = None,
    lifetime_seconds: int = 600,
) -> str:
    code = secrets.token_urlsafe(32)
    code_hash = hashlib.sha256(code.encode()).hexdigest()

    OIDCAuthCode.create_code(
        client_id=client_id,
        user_id=user_id,
        code_hash=code_hash,
        redirect_uri=redirect_uri,
        scope=scope,
        nonce=nonce,
        ip_address=ip_address,
        user_agent=user_agent,
        lifetime_seconds=lifetime_seconds,
    )

    logger.info(f"Generated authorization code for user={user_id}, client={client_id}")
    return code


def exchange_authorization_code(
    code: str,
    client_id: str,
    redirect_uri: str,
    ip_address: str = None,
) -> dict:
    code_hash = hashlib.sha256(code.encode()).hexdigest()

    auth_code = OIDCAuthCode.query.filter_by(
        client_id=client_id,
        code_hash=code_hash,
    ).first()

    if not auth_code:
        raise OAuthFlowError("Invalid authorization code", "INVALID_CODE", 400)

    if not auth_code.is_valid():
        if auth_code.is_used:
            raise OAuthFlowError(
                "Authorization code has already been used", "CODE_USED", 400
            )
        else:
            raise OAuthFlowError("Authorization code has expired", "CODE_EXPIRED", 400)

    if auth_code.redirect_uri != redirect_uri:
        raise OAuthFlowError("Redirect URI mismatch", "INVALID_REDIRECT_URI", 400)

    from gatehouse_app.models import User
    user = User.query.get(auth_code.user_id)
    if not user:
        raise OAuthFlowError("User not found", "USER_NOT_FOUND", 404)

    user_orgs = user.get_organizations()
    target_org = None
    if len(user_orgs) == 1:
        target_org = user_orgs[0]

    if not target_org:
        raise OAuthFlowError(
            "User does not have a default organization. Organization selection required.",
            "ORG_SELECTION_REQUIRED",
            400,
        )

    from gatehouse_app.services.auth_service import AuthService
    session = AuthService.create_session(user=user, is_compliance_only=False)
    auth_code.mark_as_used()

    session_dict = session.to_dict()
    session_dict["token"] = session.token
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    session_dict["expires_in"] = int((expires_at - now).total_seconds())

    logger.info(
        f"Authorization code exchanged for session: user={user.id}, "
        f"org_id={target_org.id}, client={client_id}"
    )

    return {
        "success": True,
        "token": session_dict["token"],
        "expires_in": session_dict["expires_in"],
        "token_type": "Bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "organization_id": target_org.id,
        },
    }


def create_redirect_response(
    redirect_uri: str,
    authorization_code: str,
    state: str = None,
):
    from urllib.parse import urlencode, urlparse, urlunparse
    from flask import redirect

    parsed = urlparse(redirect_uri)
    params = {"code": authorization_code}
    if state:
        params["state"] = state

    redirect_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        urlencode(params),
        parsed.fragment,
    ))

    logger.info(f"Redirecting to {parsed.scheme}://{parsed.netloc} with authorization code")
    return redirect(redirect_url)
