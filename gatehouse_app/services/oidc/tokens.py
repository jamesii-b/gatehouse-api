"""OIDC token generation, refresh, validation, revocation, and introspection."""
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from flask import current_app

from gatehouse_app.models import OIDCClient, OIDCRefreshToken, OIDCTokenMetadata
from gatehouse_app.services.oidc_token_service import OIDCTokenService
from gatehouse_app.services.oidc_audit_service import OIDCAuditService
from gatehouse_app.exceptions.auth_exceptions import InvalidTokenError

logger = logging.getLogger(__name__)


def generate_tokens(
    client_id: str,
    user_id: str,
    scope: list,
    nonce: str = None,
    refresh_token: str = None,
    ip_address: str = None,
    user_agent: str = None,
    auth_time: int = None,
) -> Dict:
    logger.debug("[OIDC SERVICE] generate_tokens called: client_id=%s, user_id=%s", client_id, user_id)

    client = OIDCClient.query.filter_by(client_id=client_id).first()
    if not client:
        from gatehouse_app.services.oidc import InvalidClientError
        raise InvalidClientError()

    access_token_jti = OIDCTokenService._generate_jti()
    access_token = OIDCTokenService.create_access_token(
        client_id=client_id,
        user_id=user_id,
        scope=scope,
        jti=access_token_jti,
    )

    id_token = OIDCTokenService.create_id_token(
        client_id=client_id,
        user_id=user_id,
        nonce=nonce,
        scope=scope,
        access_token=access_token,
        auth_time=auth_time,
    )

    final_refresh_token = None
    if "refresh_token" in (client.grant_types or []):
        if refresh_token:
            refresh_token_obj = OIDCRefreshToken.query.filter_by(
                token_hash=hashlib.sha256(refresh_token.encode()).hexdigest(),
                deleted_at=None,
            ).first()
            if refresh_token_obj and refresh_token_obj.is_valid():
                new_refresh, new_hash = OIDCTokenService.create_refresh_token(
                    client_id=client_id,
                    user_id=user_id,
                    scope=scope,
                    access_token_id=access_token_jti,
                )
                refresh_token_obj.rotate(new_hash)
                final_refresh_token = new_refresh
        else:
            final_refresh_token, refresh_hash = OIDCTokenService.create_refresh_token(
                client_id=client_id,
                user_id=user_id,
                scope=scope,
                access_token_id=access_token_jti,
            )
            OIDCRefreshToken.create_token(
                client_id=client.id,
                user_id=user_id,
                token_hash=refresh_hash,
                scope=scope,
                access_token_id=access_token_jti,
                ip_address=ip_address,
                user_agent=user_agent,
                lifetime_seconds=client.refresh_token_lifetime or 2592000,
            )

    access_token_expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=client.access_token_lifetime or 3600
    )
    OIDCTokenMetadata.create_metadata(
        client_id=client.id,
        user_id=user_id,
        token_type="access_token",
        token_jti=access_token_jti,
        expires_at=access_token_expires_at,
    )

    id_token_jti = OIDCTokenService._generate_jti()
    id_token_expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=client.id_token_lifetime or 3600
    )
    OIDCTokenMetadata.create_metadata(
        client_id=client.id,
        user_id=user_id,
        token_type="id_token",
        token_jti=id_token_jti,
        expires_at=id_token_expires_at,
    )

    OIDCAuditService.log_token_event(
        client_id=client.id,
        user_id=user_id,
        token_type="access_token",
        success=True,
        grant_type="authorization_code",
        scopes=scope,
    )

    result = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": client.access_token_lifetime or 3600,
        "id_token": id_token,
    }
    if final_refresh_token:
        result["refresh_token"] = final_refresh_token

    return result


def refresh_access_token(
    refresh_token: str,
    client_id: str,
    scope: list = None,
    ip_address: str = None,
    user_agent: str = None,
) -> Dict:
    logger.debug("[OIDC SERVICE] refresh_access_token called, client_id=%s", client_id)

    client = OIDCClient.query.filter_by(client_id=client_id).first()
    if not client:
        from gatehouse_app.services.oidc import InvalidClientError
        raise InvalidClientError()

    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    refresh_token_obj = OIDCRefreshToken.query.filter_by(
        token_hash=token_hash,
        deleted_at=None,
    ).first()

    if not refresh_token_obj:
        OIDCAuditService.log_token_event(
            client_id=client.id,
            success=False,
            error_code="invalid_grant",
            error_description="Invalid refresh token",
        )
        from gatehouse_app.services.oidc import InvalidGrantError
        raise InvalidGrantError("Invalid refresh token")

    if not refresh_token_obj.is_valid():
        OIDCAuditService.log_token_event(
            client_id=client.id,
            user_id=refresh_token_obj.user_id,
            success=False,
            error_code="invalid_grant",
            error_description="Refresh token expired or revoked",
        )
        from gatehouse_app.services.oidc import InvalidGrantError
        raise InvalidGrantError("Refresh token expired or revoked")

    if refresh_token_obj.client_id != client.id:
        from gatehouse_app.services.oidc import InvalidGrantError
        raise InvalidGrantError("Client mismatch")

    granted_scope = scope or (refresh_token_obj.scope or [])

    access_token_jti = OIDCTokenService._generate_jti()
    access_token = OIDCTokenService.create_access_token(
        client_id=client_id,
        user_id=refresh_token_obj.user_id,
        scope=granted_scope,
        jti=access_token_jti,
    )

    id_token = OIDCTokenService.create_id_token(
        client_id=client_id,
        user_id=refresh_token_obj.user_id,
        scope=granted_scope,
        access_token=access_token,
    )

    new_refresh, new_hash = OIDCTokenService.create_refresh_token(
        client_id=client_id,
        user_id=refresh_token_obj.user_id,
        scope=granted_scope,
        access_token_id=access_token_jti,
    )
    refresh_token_obj.rotate(new_hash)

    access_token_expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=client.access_token_lifetime or 3600
    )
    OIDCTokenMetadata.create_metadata(
        client_id=client.id,
        user_id=refresh_token_obj.user_id,
        token_type="access_token",
        token_jti=access_token_jti,
        expires_at=access_token_expires_at,
    )

    OIDCAuditService.log_token_event(
        client_id=client.id,
        user_id=refresh_token_obj.user_id,
        token_type="access_token",
        success=True,
        grant_type="refresh_token",
        scopes=granted_scope,
    )

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": client.access_token_lifetime or 3600,
        "id_token": id_token,
        "refresh_token": new_refresh,
    }


def validate_access_token(token: str, client_id: str = None) -> Dict:
    logger.debug("[OIDC SERVICE] validate_access_token() called")

    try:
        claims = OIDCTokenService.validate_access_token(token, client_id)
        logger.debug("[OIDC SERVICE] Token validation successful")
        return claims
    except Exception as e:
        logger.error("[OIDC SERVICE] Token validation failed: %s: %s", type(e).__name__, str(e))
        _client_db_id = None
        if client_id:
            _c = OIDCClient.query.filter_by(client_id=client_id).first()
            _client_db_id = _c.id if _c else None
        OIDCAuditService.log_event(
            event_type="token_validation",
            client_id=_client_db_id,
            success=False,
            error_code="invalid_token",
            error_description=str(e),
        )
        raise InvalidTokenError(str(e))


def revoke_token(
    token: str,
    client_id: str,
    token_type_hint: str = None,
    ip_address: str = None,
    user_agent: str = None,
) -> bool:
    client = OIDCClient.query.filter_by(client_id=client_id).first()
    if not client:
        from gatehouse_app.services.oidc import InvalidClientError
        raise InvalidClientError()

    revoked = False
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    if token_type_hint in (None, "refresh_token"):
        refresh_token_obj = OIDCRefreshToken.query.filter_by(
            token_hash=token_hash,
            deleted_at=None,
        ).first()
        if refresh_token_obj:
            refresh_token_obj.revoke(reason="revoked_by_client")
            revoked = True
            OIDCAuditService.log_token_revocation_event(
                client_id=client.id,
                user_id=refresh_token_obj.user_id,
                token_type="refresh_token",
                reason="revoked_by_client",
            )

    if not revoked or token_type_hint in (None, "access_token"):
        try:
            claims = OIDCTokenService.decode_token(token)
            jti = claims.get("jti")
            if jti:
                revoked_at = OIDCTokenMetadata.revoke_by_jti(jti, reason="revoked_by_client")
                if revoked_at:
                    revoked = True
                    OIDCAuditService.log_token_revocation_event(
                        client_id=client.id,
                        user_id=claims.get("sub"),
                        token_type="access_token",
                        reason="revoked_by_client",
                    )
        except Exception:
            pass

    return revoked


def introspect_token(
    token: str,
    client_id: str = None,
    ip_address: str = None,
    user_agent: str = None,
) -> Dict:
    result = OIDCTokenService.introspect_token(token, client_id)

    _client_db_id = None
    if client_id:
        _ic = OIDCClient.query.filter_by(client_id=client_id).first()
        _client_db_id = _ic.id if _ic else None
    OIDCAuditService.log_event(
        event_type="token_introspection",
        client_id=_client_db_id,
        user_id=result.get("sub"),
        success=result.get("active", False),
        metadata={"active": result.get("active")},
    )

    return result
