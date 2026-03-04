"""Static helper methods for OAuth flows."""
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _compute_s256_challenge(verifier: str) -> str:
    import hashlib
    import base64
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def _build_authorization_url(config, state) -> str:
    from urllib.parse import urlencode
    provider = (config.provider_type or "").lower()

    params = {
        "client_id": config.client_id,
        "redirect_uri": state.redirect_uri,
        "response_type": "code",
        "scope": " ".join(config.scopes or ["openid", "profile", "email"]),
        "state": state.state,
    }

    if provider == "google":
        params["access_type"] = (
            config.settings.get("access_type", "offline") if config.settings else "offline"
        )
        params["prompt"] = (
            config.settings.get("prompt", "consent") if config.settings else "consent"
        )
    elif provider == "microsoft":
        params["prompt"] = (
            config.settings.get("prompt", "select_account") if config.settings else "select_account"
        )
    else:
        if config.settings:
            if "prompt" in config.settings:
                params["prompt"] = config.settings["prompt"]
            if "access_type" in config.settings:
                params["access_type"] = config.settings["access_type"]

    if state.nonce:
        params["nonce"] = state.nonce

    if state.code_challenge:
        params["code_challenge"] = state.code_challenge
        params["code_challenge_method"] = "S256"

    full_url = f"{config.auth_url}?{urlencode(params)}"

    logger.info(
        f"[PKCE DEBUG] Building authorization URL:\n"
        f"  provider_type: {config.provider_type}\n"
        f"  state.code_challenge: {state.code_challenge[:20] if state.code_challenge else 'None'}...\n"
        f"  params has code_challenge: {'code_challenge' in params}\n"
        f"  Full URL: {full_url}"
    )

    return full_url


def _exchange_code(config, code: str, redirect_uri: str, code_verifier: str = None) -> dict:
    import requests

    data = {
        "client_id": config.client_id,
        "client_secret": config.get_client_secret(),
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }

    if code_verifier:
        data["code_verifier"] = code_verifier

    logger.debug(
        f"Token exchange request: url={config.token_url}, "
        f"client_id={config.client_id}, redirect_uri={redirect_uri}, "
        f"has_code_verifier={bool(code_verifier)}"
    )

    response = requests.post(config.token_url, data=data)

    if response.status_code != 200:
        logger.error(
            f"Token exchange failed: status={response.status_code}, "
            f"response={response.text}"
        )

    response.raise_for_status()
    return response.json()


def _get_user_info(config, access_token: str) -> dict:
    import re
    import requests

    provider = (config.provider_type or "").lower()
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(config.userinfo_url, headers=headers)
    response.raise_for_status()

    data = response.json()

    if provider == "microsoft":
        email_verified = data.get("email_verified", True)
    else:
        email_verified = data.get("email_verified", False)

    sub = data.get("sub")

    raw_email = data.get("email")
    if not raw_email and sub:
        if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", sub):
            raw_email = sub
            email_verified = True
        else:
            raw_email = f"{sub}@{provider or 'oauth'}.local"
            email_verified = False

    raw_name = data.get("name") or data.get("display_name")
    if not raw_name and raw_email:
        raw_name = raw_email.split("@")[0]

    return {
        "provider_user_id": sub,
        "email": raw_email,
        "email_verified": email_verified,
        "name": raw_name,
        "first_name": data.get("given_name"),
        "last_name": data.get("family_name"),
        "picture": data.get("picture"),
        "raw_data": data,
    }


def _encrypt_provider_data(tokens: dict, user_info: dict) -> dict:
    from gatehouse_app.utils.encryption import encrypt

    return {
        "access_token": encrypt(tokens.get("access_token")) if tokens.get("access_token") else None,
        "token_type": tokens.get("token_type", "Bearer"),
        "expires_in": tokens.get("expires_in"),
        "refresh_token": encrypt(tokens.get("refresh_token")) if tokens.get("refresh_token") else None,
        "scope": tokens.get("scope", []),
        "id_token": encrypt(tokens.get("id_token")) if tokens.get("id_token") else None,
        "email": user_info.get("email"),
        "name": user_info.get("name"),
        "picture": user_info.get("picture"),
        "raw_data": user_info.get("raw_data", {}),
    }


def _decrypt_provider_data(provider_data: dict) -> dict:
    from gatehouse_app.utils.encryption import decrypt

    if not provider_data:
        return {}

    result = {
        "token_type": provider_data.get("token_type", "Bearer"),
        "expires_in": provider_data.get("expires_in"),
        "scope": provider_data.get("scope", []),
        "email": provider_data.get("email"),
        "name": provider_data.get("name"),
        "picture": provider_data.get("picture"),
        "raw_data": provider_data.get("raw_data", {}),
    }

    for field in ("access_token", "refresh_token", "id_token"):
        value = provider_data.get(field)
        if value:
            try:
                result[field] = decrypt(value)
            except Exception:
                result[field] = value
        else:
            result[field] = None

    return result
