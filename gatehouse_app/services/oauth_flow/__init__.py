"""OAuthFlowService — public facade and handle_callback dispatcher."""
import logging
from typing import Optional, Tuple

from gatehouse_app.models.auth.authentication_method import OAuthState
from gatehouse_app.utils.constants import AuthMethodType
from gatehouse_app.services.audit_service import AuditService
from gatehouse_app.services.external_auth import ExternalAuthService
from gatehouse_app.services.external_auth.models import ExternalAuthError

from gatehouse_app.services.oauth_flow.login import OAuthFlowError, initiate_login_flow, handle_login_callback
from gatehouse_app.services.oauth_flow.register import initiate_register_flow, handle_register_callback
from gatehouse_app.services.oauth_flow.code import (
    generate_authorization_code,
    exchange_authorization_code,
    create_redirect_response,
)

logger = logging.getLogger(__name__)


class OAuthFlowService:
    """Service for managing OAuth authentication flows."""

    @classmethod
    def initiate_login_flow(
        cls,
        provider_type: AuthMethodType,
        organization_id: str = None,
        redirect_uri: str = None,
        state_data: dict = None,
    ) -> Tuple[str, str]:
        return initiate_login_flow(provider_type, organization_id, redirect_uri, state_data)

    @classmethod
    def initiate_register_flow(
        cls,
        provider_type: AuthMethodType,
        organization_id: str = None,
        redirect_uri: str = None,
    ) -> Tuple[str, str]:
        return initiate_register_flow(provider_type, organization_id, redirect_uri)

    @classmethod
    def handle_callback(
        cls,
        provider_type: AuthMethodType,
        authorization_code: str,
        state: str,
        redirect_uri: str = None,
        error: str = None,
        error_description: str = None,
    ) -> dict:
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        try:
            from flask import request
            ip_address = request.remote_addr if request else None
            user_agent = request.headers.get("User-Agent") if request else None
        except RuntimeError:
            ip_address = None
            user_agent = None

        if error:
            AuditService.log_external_auth_login_failed(
                organization_id=None,
                provider_type=provider_type_str,
                failure_reason=error,
                error_message=error_description or error,
            )
            raise OAuthFlowError(
                error_description or f"OAuth error: {error}",
                error.upper() if error else "OAUTH_ERROR",
                400,
            )

        state_record = OAuthState.query.filter_by(state=state).first()

        if state_record:
            logger.debug(
                f"State validation: found=True, used={state_record.used}, "
                f"expires_at={state_record.expires_at}, is_valid={state_record.is_valid()}"
            )
        else:
            logger.warning(f"State validation: state token not found in database: {state}")

        if not state_record or not state_record.is_valid():
            AuditService.log_external_auth_login_failed(
                organization_id=state_record.organization_id if state_record else None,
                provider_type=provider_type_str,
                failure_reason="invalid_state",
                error_message="Invalid or expired OAuth state",
            )
            raise OAuthFlowError("Invalid or expired OAuth state", "INVALID_STATE", 400)

        effective_redirect = redirect_uri or state_record.redirect_uri

        if state_record.flow_type == "login":
            return handle_login_callback(
                provider_type=provider_type,
                state_record=state_record,
                authorization_code=authorization_code,
                redirect_uri=effective_redirect,
                ip_address=ip_address,
                user_agent=user_agent,
            )
        elif state_record.flow_type == "link":
            return cls._handle_link_callback(
                provider_type=provider_type,
                state_record=state_record,
                authorization_code=authorization_code,
                redirect_uri=effective_redirect,
            )
        elif state_record.flow_type == "register":
            return handle_register_callback(
                provider_type=provider_type,
                state_record=state_record,
                authorization_code=authorization_code,
                redirect_uri=effective_redirect,
            )
        else:
            raise OAuthFlowError(
                f"Unknown flow type: {state_record.flow_type}",
                "INVALID_FLOW_TYPE",
                400,
            )

    @classmethod
    def _handle_link_callback(
        cls,
        provider_type: AuthMethodType,
        state_record: OAuthState,
        authorization_code: str,
        redirect_uri: str,
    ) -> dict:
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        try:
            auth_method = ExternalAuthService.complete_link_flow(
                provider_type=provider_type,
                authorization_code=authorization_code,
                state=state_record.state,
                redirect_uri=redirect_uri,
            )

            logger.info(
                f"OAuth link successful for user={state_record.user_id}, "
                f"provider={provider_type_str}, auth_method_id={auth_method.id}"
            )

            return {
                "success": True,
                "flow_type": "link",
                "linked_account": {
                    "id": auth_method.id,
                    "provider_type": provider_type_str,
                    "provider_user_id": auth_method.provider_user_id,
                    "verified": auth_method.verified,
                },
            }

        except ExternalAuthError as e:
            logger.warning(
                f"OAuth link failed for state={state_record.id}, "
                f"provider={provider_type_str}, error={e.message}"
            )
            raise

    @classmethod
    def validate_state(cls, state: str) -> Optional[OAuthState]:
        state_record = OAuthState.query.filter_by(state=state).first()
        if state_record and state_record.is_valid():
            return state_record
        return None

    @classmethod
    def cleanup_expired_states(cls):
        OAuthState.cleanup_expired()
        logger.info("Expired OAuth states cleaned up")

    @classmethod
    def generate_authorization_code(
        cls,
        user_id: str,
        client_id: str,
        redirect_uri: str,
        scope: list = None,
        nonce: str = None,
        ip_address: str = None,
        user_agent: str = None,
        lifetime_seconds: int = 600,
    ) -> str:
        return generate_authorization_code(
            user_id, client_id, redirect_uri, scope, nonce, ip_address, user_agent, lifetime_seconds
        )

    @classmethod
    def exchange_authorization_code(
        cls,
        code: str,
        client_id: str,
        redirect_uri: str,
        ip_address: str = None,
    ) -> dict:
        return exchange_authorization_code(code, client_id, redirect_uri, ip_address)

    @classmethod
    def create_redirect_response(cls, redirect_uri: str, authorization_code: str, state: str = None):
        return create_redirect_response(redirect_uri, authorization_code, state)
