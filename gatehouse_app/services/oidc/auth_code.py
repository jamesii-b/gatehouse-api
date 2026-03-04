"""OIDC authorization code generation and validation."""
import logging
from datetime import datetime, timezone
from typing import Dict, Tuple

from flask import current_app

from gatehouse_app.models import User, OIDCAuthCode
from gatehouse_app.exceptions.validation_exceptions import ValidationError, NotFoundError
from gatehouse_app.services.oidc_audit_service import OIDCAuditService

logger = logging.getLogger(__name__)


def _hash_value(value: str) -> str:
    import hashlib
    return hashlib.sha256(value.encode()).hexdigest()


def _compute_code_challenge(verifier: str, method: str = "S256") -> str:
    import hashlib
    import base64
    if method == "S256":
        digest = hashlib.sha256(verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier


def generate_authorization_code(
    client_id: str,
    user_id: str,
    redirect_uri: str,
    scope: list,
    state: str,
    nonce: str,
    code_challenge: str = None,
    code_challenge_method: str = None,
    ip_address: str = None,
    user_agent: str = None,
) -> str:
    import secrets

    from gatehouse_app.models import OIDCClient

    logger.debug("[OIDC SERVICE] generate_authorization_code called")
    logger.debug("[OIDC SERVICE] client_id=%s, user_id=%s", client_id, user_id)

    client = OIDCClient.query.filter_by(client_id=client_id).first()

    if current_app.config.get('ENV') == 'development':
        logger.debug(f"[OIDC] Generate auth code - Client validation: client_id={client_id}, exists={client is not None}")

    if not client:
        raise NotFoundError("Client not found")

    if not client.is_active:
        raise ValidationError("Client is not active")

    if not client.is_redirect_uri_allowed(redirect_uri):
        raise ValidationError("Invalid redirect_uri")

    allowed_scopes = client.scopes or []
    valid_scopes = [s for s in scope if s in allowed_scopes]

    if not valid_scopes:
        raise ValidationError("Invalid scopes")

    code = secrets.token_urlsafe(32)
    code_hash = _hash_value(code)

    auth_code = OIDCAuthCode.create_code(
        client_id=client.id,
        user_id=user_id,
        code_hash=code_hash,
        redirect_uri=redirect_uri,
        scope=valid_scopes,
        nonce=nonce,
        code_verifier=code_challenge,
        ip_address=ip_address,
        user_agent=user_agent,
        lifetime_seconds=600,
    )
    logger.debug("[OIDC SERVICE] Auth code created, expires_at=%s", auth_code.expires_at.isoformat())

    OIDCAuditService.log_authorization_event(
        client_id=client.id,
        user_id=user_id,
        success=True,
        redirect_uri=redirect_uri,
        scope=valid_scopes,
    )

    return code


def validate_authorization_code(
    code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str = None,
    ip_address: str = None,
    user_agent: str = None,
) -> Tuple[Dict, User]:
    from gatehouse_app.models import OIDCClient
    from gatehouse_app.exceptions.auth_exceptions import InvalidTokenError

    logger.debug("[OIDC SERVICE] validate_authorization_code called, client_id=%s", client_id)

    client = OIDCClient.query.filter_by(client_id=client_id).first()
    if not client:
        logger.error(f"[OIDC] Validate auth code - Client not found: client_id={client_id}")
        from gatehouse_app.services.oidc import InvalidGrantError
        raise InvalidGrantError("Invalid client")

    code_hash = _hash_value(code)
    auth_code = OIDCAuthCode.query.filter_by(
        code_hash=code_hash,
        client_id=client.id,
        deleted_at=None,
    ).first()

    if not auth_code:
        OIDCAuditService.log_authorization_event(
            client_id=client.id,
            success=False,
            error_code="invalid_grant",
            error_description="Invalid or expired authorization code",
        )
        from gatehouse_app.services.oidc import InvalidGrantError
        raise InvalidGrantError("Invalid or expired authorization code")

    if auth_code.is_used:
        OIDCAuditService.log_authorization_event(
            client_id=client.id,
            user_id=auth_code.user_id,
            success=False,
            error_code="invalid_grant",
            error_description="Authorization code already used",
        )
        from gatehouse_app.services.oidc import InvalidGrantError
        raise InvalidGrantError("Authorization code already used")

    expires_at = auth_code.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    logger.debug(
        "[OIDC SERVICE] Time until expiration (seconds): %s",
        (expires_at - datetime.now(timezone.utc)).total_seconds(),
    )

    if auth_code.is_expired():
        OIDCAuditService.log_authorization_event(
            client_id=client.id,
            user_id=auth_code.user_id,
            success=False,
            error_code="invalid_grant",
            error_description="Authorization code expired",
        )
        from gatehouse_app.services.oidc import InvalidGrantError
        raise InvalidGrantError("Authorization code expired")

    if auth_code.redirect_uri != redirect_uri:
        from gatehouse_app.services.oidc import InvalidGrantError
        raise InvalidGrantError("Invalid redirect_uri")

    if client.require_pkce and auth_code.code_verifier:
        if not code_verifier:
            raise ValidationError("code_verifier is required")
        expected_challenge = _compute_code_challenge(code_verifier, "S256")
        if expected_challenge != auth_code.code_verifier:
            OIDCAuditService.log_authorization_event(
                client_id=client.id,
                user_id=auth_code.user_id,
                success=False,
                error_code="invalid_grant",
                error_description="Invalid code_verifier",
            )
            from gatehouse_app.services.oidc import InvalidGrantError
            raise InvalidGrantError("Invalid code_verifier")

    auth_code.mark_as_used()

    user = User.query.get(auth_code.user_id)
    if not user:
        from gatehouse_app.services.oidc import InvalidGrantError
        raise InvalidGrantError("User not found")

    claims = {
        "user_id": auth_code.user_id,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": auth_code.scope,
        "nonce": auth_code.nonce,
    }

    return claims, user
