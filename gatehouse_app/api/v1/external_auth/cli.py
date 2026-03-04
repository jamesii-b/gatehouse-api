"""CLI token acquisition endpoints."""
import secrets
import logging
from urllib.parse import quote
from flask import request, current_app, redirect as flask_redirect
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.api.v1.external_auth._helpers import _OAUTH_BRIDGE_TTL

logger = logging.getLogger(__name__)


@api_v1_bp.route("/token_please", methods=["GET"])
def token_please():
    redirect_url = request.args.get("redirect_url", "").strip()

    if not redirect_url:
        return api_response(success=False, message="redirect_url query parameter is required", status=400, error_type="MISSING_REDIRECT_URL")

    from urllib.parse import urlparse as _urlparse
    parsed = _urlparse(redirect_url)
    if parsed.hostname not in ("localhost", "127.0.0.1"):
        return api_response(success=False, message="redirect_url must point to localhost", status=400, error_type="INVALID_REDIRECT_URL")

    cli_token = secrets.token_urlsafe(32)
    try:
        import gatehouse_app.extensions as _ext
        rc = _ext.redis_client
        if rc is not None:
            rc.setex(f"cli_redirect:{cli_token}", _OAUTH_BRIDGE_TTL, redirect_url)
        else:
            logger.warning("Redis not available; passing cli_redirect directly in URL")
            cli_token = None
    except Exception:
        cli_token = None

    frontend_url = current_app.config.get("FRONTEND_URL", "http://localhost:8080")

    if cli_token:
        login_url = f"{frontend_url}/login?cli_token={cli_token}"
    else:
        login_url = f"{frontend_url}/login?cli_redirect={quote(redirect_url, safe='')}"

    logger.info("CLI token_please: redirecting browser to Gatehouse login page")
    return flask_redirect(login_url, code=302)


@api_v1_bp.route("/cli/redirect-url", methods=["GET"])
def cli_redirect_url_lookup():
    cli_token = request.args.get("token", "").strip()
    if not cli_token:
        return api_response(success=False, message="token query parameter is required", status=400, error_type="MISSING_TOKEN")

    try:
        import gatehouse_app.extensions as _ext
        rc = _ext.redis_client
        if rc is not None:
            key = f"cli_redirect:{cli_token}"
            val = rc.get(key)
            if val is None:
                return api_response(success=False, message="CLI token not found or expired", status=404, error_type="TOKEN_NOT_FOUND")
            redirect_url = val.decode() if isinstance(val, bytes) else val
            return api_response(data={"redirect_url": redirect_url})
    except Exception as e:
        logger.error(f"cli_redirect_url_lookup error: {e}")
        return api_response(success=False, message="Internal error looking up CLI token", status=500, error_type="INTERNAL_ERROR")

    return api_response(success=False, message="Redis not available", status=503, error_type="SERVICE_UNAVAILABLE")
