"""Shared helpers for external_auth subpackage."""
import logging
from gatehouse_app.utils.constants import AuthMethodType
from gatehouse_app.services.external_auth.models import ExternalAuthError

_OAUTH_BRIDGE_TTL = 600  # 10 minutes

logger = logging.getLogger(__name__)

PROVIDER_TYPE_MAP = {
    "google": AuthMethodType.GOOGLE,
    "github": AuthMethodType.GITHUB,
    "microsoft": AuthMethodType.MICROSOFT,
}


def get_provider_type(provider: str) -> AuthMethodType:
    provider_lower = provider.lower()
    if provider_lower not in PROVIDER_TYPE_MAP:
        raise ExternalAuthError(f"Unsupported provider: {provider}", "UNSUPPORTED_PROVIDER", 400)
    return PROVIDER_TYPE_MAP[provider_lower]


def _get_provider_endpoints(provider_type: AuthMethodType):
    if provider_type == AuthMethodType.GOOGLE:
        return (
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token",
            "https://www.googleapis.com/oauth2/v3/userinfo",
        )
    elif provider_type == AuthMethodType.GITHUB:
        return (
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            "https://api.github.com/user",
        )
    elif provider_type == AuthMethodType.MICROSOFT:
        return (
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            "https://graph.microsoft.com/oidc/userinfo",
        )
    else:
        raise ExternalAuthError(f"Unsupported provider: {provider_type}", "UNSUPPORTED_PROVIDER", 400)


def _store_oidc_bridge(oauth_state: str, oidc_session_id: str) -> None:
    try:
        import gatehouse_app.extensions as _ext
        rc = _ext.redis_client
        if rc is not None:
            rc.setex(f"oauth_oidc_bridge:{oauth_state}", _OAUTH_BRIDGE_TTL, oidc_session_id)
    except Exception:
        pass


def _pop_oidc_bridge(oauth_state: str) -> str | None:
    try:
        import gatehouse_app.extensions as _ext
        rc = _ext.redis_client
        if rc is not None:
            key = f"oauth_oidc_bridge:{oauth_state}"
            val = rc.get(key)
            if val:
                rc.delete(key)
                return val.decode() if isinstance(val, bytes) else val
    except Exception:
        pass
    return None


def _store_cli_redirect(oauth_state: str, redirect_url: str) -> None:
    try:
        import gatehouse_app.extensions as _ext
        rc = _ext.redis_client
        if rc is not None:
            rc.setex(f"oauth_cli_redirect:{oauth_state}", _OAUTH_BRIDGE_TTL, redirect_url)
    except Exception:
        pass


def _pop_cli_redirect(oauth_state: str) -> str | None:
    try:
        import gatehouse_app.extensions as _ext
        rc = _ext.redis_client
        if rc is not None:
            key = f"oauth_cli_redirect:{oauth_state}"
            val = rc.get(key)
            if val:
                rc.delete(key)
                return val.decode() if isinstance(val, bytes) else val
    except Exception:
        pass
    return None
