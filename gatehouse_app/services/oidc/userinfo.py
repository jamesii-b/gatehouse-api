"""OIDC userinfo endpoint logic."""
import logging
from typing import Dict

from gatehouse_app.models import User
from gatehouse_app.exceptions.validation_exceptions import NotFoundError
from gatehouse_app.services.oidc_audit_service import OIDCAuditService

logger = logging.getLogger(__name__)


def get_userinfo(access_token: str, validate_access_token_fn) -> Dict:
    logger.debug("[OIDC SERVICE] get_userinfo() called")

    claims = validate_access_token_fn(access_token)
    user_id = claims.get("sub")

    user = User.query.get(user_id)
    if not user:
        logger.error("[OIDC SERVICE] User not found in database: user_id=%s", user_id)
        raise NotFoundError("User not found")

    scope_str = claims.get("scope", "")
    scopes = scope_str.split() if scope_str else []

    userinfo = {"sub": user_id}

    if "profile" in scopes and user.full_name:
        userinfo["name"] = user.full_name

    if "email" in scopes:
        userinfo["email"] = user.email
        userinfo["email_verified"] = user.email_verified

    if "roles" in scopes:
        userinfo["roles"] = _get_user_roles(user)

    _userinfo_client_id_str = claims.get("client_id")
    _userinfo_client_db_id = None
    if _userinfo_client_id_str:
        from gatehouse_app.models import OIDCClient
        _uc = OIDCClient.query.filter_by(client_id=_userinfo_client_id_str).first()
        _userinfo_client_db_id = _uc.id if _uc else None

    OIDCAuditService.log_userinfo_event(
        access_token=access_token,
        user_id=user_id,
        client_id=_userinfo_client_db_id,
        success=True,
        scopes_claimed=scopes,
    )

    return userinfo


def _get_user_roles(user: User) -> list:
    roles = []
    if not user or not user.organization_memberships:
        return roles
    for member in user.organization_memberships:
        roles.append({
            "organization_id": str(member.organization_id),
            "role": member.role.value,
        })
    return roles
