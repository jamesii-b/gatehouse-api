"""OIDCService — public facade over the oidc sub-package."""
import logging
from typing import Dict, List, Optional, Tuple

from gatehouse_app.exceptions.auth_exceptions import InvalidTokenError

logger = logging.getLogger(__name__)


class OIDCError(Exception):
    def __init__(self, error: str, error_description: str = None, status_code: int = 400):
        self.error = error
        self.error_description = error_description
        self.status_code = status_code


class InvalidClientError(OIDCError):
    def __init__(self, error_description: str = "Invalid client"):
        super().__init__("invalid_client", error_description, 401)


class InvalidGrantError(OIDCError):
    def __init__(self, error_description: str = "Invalid grant"):
        super().__init__("invalid_grant", error_description, 400)


class InvalidRequestError(OIDCError):
    def __init__(self, error_description: str = "Invalid request"):
        super().__init__("invalid_request", error_description, 400)


from gatehouse_app.services.oidc import auth_code as _auth_code
from gatehouse_app.services.oidc import tokens as _tokens
from gatehouse_app.services.oidc import userinfo as _userinfo


class OIDCService:
    """Main OIDC service handling all OpenID Connect operations."""

    @staticmethod
    def _generate_code() -> str:
        import secrets
        return secrets.token_urlsafe(32)

    @staticmethod
    def _hash_value(value: str) -> str:
        import hashlib
        return hashlib.sha256(value.encode()).hexdigest()

    @classmethod
    def generate_authorization_code(
        cls,
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
        return _auth_code.generate_authorization_code(
            client_id, user_id, redirect_uri, scope, state, nonce,
            code_challenge, code_challenge_method, ip_address, user_agent,
        )

    @classmethod
    def validate_authorization_code(
        cls,
        code: str,
        client_id: str,
        redirect_uri: str,
        code_verifier: str = None,
        ip_address: str = None,
        user_agent: str = None,
    ) -> Tuple[Dict, object]:
        return _auth_code.validate_authorization_code(
            code, client_id, redirect_uri, code_verifier, ip_address, user_agent
        )

    @classmethod
    def _compute_code_challenge(cls, verifier: str, method: str = "S256") -> str:
        return _auth_code._compute_code_challenge(verifier, method)

    @classmethod
    def generate_tokens(
        cls,
        client_id: str,
        user_id: str,
        scope: list,
        nonce: str = None,
        refresh_token: str = None,
        ip_address: str = None,
        user_agent: str = None,
        auth_time: int = None,
    ) -> Dict:
        return _tokens.generate_tokens(
            client_id, user_id, scope, nonce, refresh_token, ip_address, user_agent, auth_time
        )

    @classmethod
    def refresh_access_token(
        cls,
        refresh_token: str,
        client_id: str,
        scope: list = None,
        ip_address: str = None,
        user_agent: str = None,
    ) -> Dict:
        return _tokens.refresh_access_token(refresh_token, client_id, scope, ip_address, user_agent)

    @classmethod
    def validate_access_token(cls, token: str, client_id: str = None) -> Dict:
        return _tokens.validate_access_token(token, client_id)

    @classmethod
    def revoke_token(
        cls,
        token: str,
        client_id: str,
        token_type_hint: str = None,
        ip_address: str = None,
        user_agent: str = None,
    ) -> bool:
        return _tokens.revoke_token(token, client_id, token_type_hint, ip_address, user_agent)

    @classmethod
    def introspect_token(
        cls,
        token: str,
        client_id: str = None,
        ip_address: str = None,
        user_agent: str = None,
    ) -> Dict:
        return _tokens.introspect_token(token, client_id, ip_address, user_agent)

    @classmethod
    def get_jwks(cls) -> Dict:
        from gatehouse_app.services.oidc_jwks_service import OIDCJWKSService
        return OIDCJWKSService().get_jwks()

    @classmethod
    def get_userinfo(cls, access_token: str) -> Dict:
        return _userinfo.get_userinfo(access_token, cls.validate_access_token)

    @staticmethod
    def _get_user_roles(user) -> list:
        return _userinfo._get_user_roles(user)
